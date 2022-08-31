import json
import os
import time

import pytest

from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_PYTHON37,
    LAMBDA_RUNTIME_PYTHON38,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.awslambda.functions import lambda_integration
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
LAMBDA_SQS_INTEGRATION_FILE = os.path.join(THIS_FOLDER, "functions", "lambda_sqs_integration.py")
LAMBDA_SQS_BATCH_ITEM_FAILURE_FILE = os.path.join(
    THIS_FOLDER, "functions", "lambda_sqs_batch_item_failure.py"
)


def _await_event_source_mapping_enabled(lambda_client, uuid, retries=30):
    def assert_mapping_enabled():
        assert lambda_client.get_event_source_mapping(UUID=uuid)["State"] == "Enabled"

    retry(assert_mapping_enabled, sleep_before=2, retries=retries)


def _await_queue_size(sqs_client, queue_url: str, qsize: int, retries=10, sleep=1):
    # wait for all items to appear in the queue
    def _verify_event_queue_size():
        attr = "ApproximateNumberOfMessages"
        _approx = int(
            sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=[attr])[
                "Attributes"
            ][attr]
        )
        assert _approx >= qsize

    retry(_verify_event_queue_size, retries=retries, sleep=sleep)


@pytest.fixture(autouse=True)
def _snapshot_transformers(snapshot):
    # manual transformers since we are passing SQS attributes through lambdas and back again
    snapshot.add_transformer(snapshot.transform.key_value("QueueUrl"))
    snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
    snapshot.add_transformer(snapshot.transform.key_value("SenderId", reference_replacement=False))
    snapshot.add_transformer(snapshot.transform.key_value("SequenceNumber"))
    snapshot.add_transformer(snapshot.transform.resource_name())
    # body contains dynamic attributes so md5 hash changes
    snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
    # lower-case for when messages are rendered in lambdas
    snapshot.add_transformer(snapshot.transform.key_value("receiptHandle"))
    snapshot.add_transformer(snapshot.transform.key_value("md5OfBody"))


@pytest.mark.skip_snapshot_verify(
    paths=[
        # FIXME: this is most of the event source mapping unfortunately
        "$..ParallelizationFactor",
        "$..LastProcessingResult",
        "$..Topics",
        "$..MaximumRetryAttempts",
        "$..MaximumBatchingWindowInSeconds",
        "$..FunctionResponseTypes",
        "$..StartingPosition",
        "$..StateTransitionReason",
    ]
)
@pytest.mark.aws_validated
def test_failing_lambda_retries_after_visibility_timeout(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    """This test verifies a basic SQS retry scenario. The lambda uses an SQS queue as event source, and we are
    testing whether the lambda automatically retries after the visibility timeout expires, and, after the retry,
    properly deletes the message from the queue."""

    # create queue used in the lambda to send events to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    # timeout in seconds, used for both the lambda and the queue visibility timeout
    retry_timeout = 5

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_INTEGRATION_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
    )

    # create event source queue
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # wire everything with the event source mapping
    response = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=1,
    )
    mapping_uuid = response["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)
    response = lambda_client.get_event_source_mapping(UUID=mapping_uuid)
    snapshot.match("event_source_mapping", response)

    # trigger lambda with a message and pass the result destination url. the event format is expected by the
    # lambda_sqs_integration.py lambda.
    event = {"destination": destination_url, "fail_attempts": 1}
    sqs_client.send_message(
        QueueUrl=event_source_url,
        MessageBody=json.dumps(event),
    )

    # now wait for the first invocation result which is expected to fail
    then = time.time()
    first_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in first_response
    snapshot.match("first_attempt", first_response)

    # and then after a few seconds (at least the visibility timeout), we expect the
    second_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in second_response
    snapshot.match("second_attempt", second_response)

    # check that it took at least the retry timeout between the first and second attempt
    assert time.time() >= then + retry_timeout

    # assert message is removed from the queue
    assert "Messages" not in sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=retry_timeout + 1, MaxNumberOfMessages=1
    )


@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..ParallelizationFactor",
        "$..LastProcessingResult",
        "$..Topics",
        "$..MaximumRetryAttempts",
        "$..MaximumBatchingWindowInSeconds",
        "$..FunctionResponseTypes",
        "$..StartingPosition",
        "$..StateTransitionReason",
    ]
)
@pytest.mark.aws_validated
def test_redrive_policy_with_failing_lambda(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    """This test verifies that SQS moves a message that is passed to a failing lambda to a DLQ according to the
    redrive policy, and the lambda is invoked the correct number of times. The test retries twice and the event
    source mapping should then automatically move the message to the DLQ, but not earlier (see
    https://github.com/localstack/localstack/issues/5283)"""

    # create queue used in the lambda to send events to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    # timeout in seconds, used for both the lambda and the queue visibility timeout
    retry_timeout = 5
    retries = 2

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_INTEGRATION_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
    )

    # create dlq for event source queue
    event_dlq_url = sqs_create_queue(QueueName=f"event-dlq-{short_uid()}")
    event_dlq_arn = sqs_queue_arn(event_dlq_url)

    # create event source queue
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": event_dlq_arn, "maxReceiveCount": retries}
            ),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # wire everything with the event source mapping
    mapping_uuid = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=1,
    )["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

    # trigger lambda with a message and pass the result destination url. the event format is expected by the
    # lambda_sqs_integration.py lambda.
    event = {"destination": destination_url, "fail_attempts": retries}
    sqs_client.send_message(
        QueueUrl=event_source_url,
        MessageBody=json.dumps(event),
    )

    # now wait for the first invocation result which is expected to fail
    first_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in first_response
    snapshot.match("first_attempt", first_response)

    # check that the DLQ is empty
    assert "Messages" not in sqs_client.receive_message(QueueUrl=event_dlq_url, WaitTimeSeconds=1)

    # the second is also expected to fail, and then the message moves into the DLQ
    second_response = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in second_response
    snapshot.match("second_attempt", second_response)

    # now check that the event messages was placed in the DLQ
    dlq_response = sqs_client.receive_message(QueueUrl=event_dlq_url, WaitTimeSeconds=15)
    assert "Messages" in dlq_response
    snapshot.match("dlq_response", dlq_response)


@pytest.mark.aws_validated
def test_sqs_queue_as_lambda_dead_letter_queue(
    sqs_client,
    lambda_client,
    lambda_su_role,
    create_lambda_function,
    sqs_create_queue,
    sqs_queue_arn,
    snapshot,
):
    snapshot.add_transformer(
        [
            # MessageAttributes contain the request id, messes the hash
            snapshot.transform.key_value(
                "MD5OfMessageAttributes",
                value_replacement="<md5-hash>",
                reference_replacement=False,
            ),
            snapshot.transform.jsonpath(
                "$..Messages..MessageAttributes.RequestID.StringValue", "request-id"
            ),
        ]
    )

    dlq_queue_url = sqs_create_queue()
    dlq_queue_arn = sqs_queue_arn(dlq_queue_url)

    function_name = f"lambda-fn-{short_uid()}"
    lambda_creation_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_PYTHON,
        runtime=LAMBDA_RUNTIME_PYTHON37,
        role=lambda_su_role,
        DeadLetterConfig={"TargetArn": dlq_queue_arn},
    )
    snapshot.match(
        "lambda-response-dlq-config",
        lambda_creation_response["CreateFunctionResponse"]["DeadLetterConfig"],
    )

    # invoke Lambda, triggering an error
    payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
    lambda_client.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload),
        InvocationType="Event",
    )

    def receive_dlq():
        result = sqs_client.receive_message(
            QueueUrl=dlq_queue_url, MessageAttributeNames=["All"], VisibilityTimeout=0
        )
        assert len(result["Messages"]) > 0
        return result

    # check that the SQS queue used as DLQ received the error from the lambda
    # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here
    # reduced retries when using localstack to avoid tests flaking
    retries = 120 if is_aws_cloud() else 3
    messages = retry(receive_dlq, retries=retries, sleep=3)

    snapshot.match("messages", messages)


@pytest.mark.skip_snapshot_verify(
    paths=[
        # FIXME: we don't seem to be returning SQS FIFO sequence numbers correctly
        "$..SequenceNumber",
        # no idea why this one fails
        "$..receiptHandle",
        # matching these attributes doesn't work well because of the dynamic nature of messages
        "$..md5OfBody",
        "$..MD5OfMessageBody",
        # FIXME: this is most of the event source mapping unfortunately
        "$..create_event_source_mapping.ParallelizationFactor",
        "$..create_event_source_mapping.LastProcessingResult",
        "$..create_event_source_mapping.Topics",
        "$..create_event_source_mapping.MaximumRetryAttempts",
        "$..create_event_source_mapping.MaximumBatchingWindowInSeconds",
        "$..create_event_source_mapping.FunctionResponseTypes",
        "$..create_event_source_mapping.StartingPosition",
        "$..create_event_source_mapping.StateTransitionReason",
        "$..create_event_source_mapping.State",
        "$..create_event_source_mapping.ResponseMetadata",
    ]
)
@pytest.mark.aws_validated
def test_report_batch_item_failures(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    """This test verifies the SQS Lambda integration feature Reporting batch item failures
    redrive policy, and the lambda is invoked the correct number of times. The test retries twice and the event
    source mapping should then automatically move the message to the DQL, but not earlier (see
    https://github.com/localstack/localstack/issues/5283)"""

    # create queue used in the lambda to send invocation results to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    # timeout in seconds, used for both the lambda and the queue visibility timeout.
    # increase to 10 if testing against AWS fails.
    retry_timeout = 8
    retries = 2

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_BATCH_ITEM_FAILURE_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
        envvars={"DESTINATION_QUEUE_URL": destination_url},
    )

    # create dlq for event source queue
    event_dlq_url = sqs_create_queue(
        QueueName=f"event-dlq-{short_uid()}.fifo", Attributes={"FifoQueue": "true"}
    )
    event_dlq_arn = sqs_queue_arn(event_dlq_url)

    # create event source queue
    # we use a FIFO queue to be sure the lambda is invoked in a deterministic way
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}.fifo",
        Attributes={
            "FifoQueue": "true",
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": event_dlq_arn, "maxReceiveCount": retries}
            ),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # put a batch in the queue. the event format is expected by the lambda_sqs_batch_item_failure.py lambda.
    # we add the batch before the event_source_mapping to be sure that the entire batch is sent to the first invocation.
    # message 1 succeeds immediately
    # message 2 and 3 succeeds after one retry
    # message 4 fails after 2 retries and lands in the DLQ
    response = sqs_client.send_message_batch(
        QueueUrl=event_source_url,
        Entries=[
            {
                "Id": "message-1",
                "MessageBody": json.dumps({"message": 1, "fail_attempts": 0}),
                "MessageGroupId": "1",
                "MessageDeduplicationId": "dedup-1",
            },
            {
                "Id": "message-2",
                "MessageBody": json.dumps({"message": 2, "fail_attempts": 1}),
                "MessageGroupId": "1",
                "MessageDeduplicationId": "dedup-2",
            },
            {
                "Id": "message-3",
                "MessageBody": json.dumps({"message": 3, "fail_attempts": 1}),
                "MessageGroupId": "1",
                "MessageDeduplicationId": "dedup-3",
            },
            {
                "Id": "message-4",
                "MessageBody": json.dumps({"message": 4, "fail_attempts": retries}),
                "MessageGroupId": "1",
                "MessageDeduplicationId": "dedup-4",
            },
        ],
    )
    # sort so snapshotting works
    response["Successful"].sort(key=lambda r: r["Id"])
    snapshot.match("send_message_batch", response)

    # wait for all items to appear in the queue
    _await_queue_size(sqs_client, event_source_url, qsize=4, retries=30)

    # wire everything with the event source mapping
    response = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=10,
        MaximumBatchingWindowInSeconds=0,
        FunctionResponseTypes=["ReportBatchItemFailures"],
    )
    snapshot.match("create_event_source_mapping", response)
    mapping_uuid = response["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

    # now wait for the first invocation result which is expected to have processed message 1 we wait half the retry
    # interval to wait long enough for the message to appear, but short enough to check that the DLQ is empty after
    # the first attempt.
    first_invocation = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=int(retry_timeout / 2), MaxNumberOfMessages=1
    )
    assert "Messages" in first_invocation
    # hack to make snapshot work
    first_invocation["Messages"][0]["Body"] = json.loads(first_invocation["Messages"][0]["Body"])
    first_invocation["Messages"][0]["Body"]["event"]["Records"].sort(
        key=lambda record: json.loads(record["body"])["message"]
    )
    snapshot.match("first_invocation", first_invocation)

    # check that the DQL is empty
    assert "Messages" not in sqs_client.receive_message(QueueUrl=event_dlq_url)

    # now wait for the second invocation result which is expected to have processed message 2 and 3
    second_invocation = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=retry_timeout + 2, MaxNumberOfMessages=1
    )
    assert "Messages" in second_invocation
    # hack to make snapshot work
    second_invocation["Messages"][0]["Body"] = json.loads(second_invocation["Messages"][0]["Body"])
    second_invocation["Messages"][0]["Body"]["event"]["Records"].sort(
        key=lambda record: json.loads(record["body"])["message"]
    )
    snapshot.match("second_invocation", second_invocation)

    # here we make sure there's actually not a third attempt, since our retries = 2
    third_attempt = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=1, MaxNumberOfMessages=1
    )
    assert "Messages" not in third_attempt

    # now check that message 4 was placed in the DLQ
    dlq_response = sqs_client.receive_message(QueueUrl=event_dlq_url, WaitTimeSeconds=15)
    assert "Messages" in dlq_response
    snapshot.match("dlq_response", dlq_response)


@pytest.mark.aws_validated
def test_report_batch_item_failures_on_lambda_error(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    # timeout in seconds, used for both the lambda and the queue visibility timeout
    retry_timeout = 2
    retries = 2

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_INTEGRATION_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
    )

    # create dlq for event source queue
    event_dlq_url = sqs_create_queue(QueueName=f"event-dlq-{short_uid()}")
    event_dlq_arn = sqs_queue_arn(event_dlq_url)

    # create event source queue
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": event_dlq_arn, "maxReceiveCount": retries}
            ),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # send a batch with a message to the queue that provokes a lambda failure (the lambda tries to parse the body as
    # JSON, but if it's not a json document, it fails). consequently, the entire batch should be discarded
    sqs_client.send_message_batch(
        QueueUrl=event_source_url,
        Entries=[
            {
                "Id": "message-1",
                "MessageBody": "{not a json body",
            },
            {
                # this one's ok, but will be sent to the DLQ nonetheless because it's part of this bad batch.
                "Id": "message-2",
                "MessageBody": json.dumps({"message": 2, "fail_attempts": 0}),
            },
        ],
    )
    _await_queue_size(sqs_client, event_source_url, qsize=2)

    # wire everything with the event source mapping
    mapping_uuid = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        FunctionResponseTypes=["ReportBatchItemFailures"],
    )["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

    # the message should arrive in the DLQ after 2 retries + some time for processing

    messages = []

    def _collect_message():
        dlq_response = sqs_client.receive_message(QueueUrl=event_dlq_url)
        messages.extend(dlq_response.get("Messages", []))
        assert len(messages) >= 2

    # the message should arrive in the DLQ after 2 retries + some time for processing
    wait_time = retry_timeout * retries
    retry(_collect_message, retries=10, sleep=1, sleep_before=wait_time)

    snapshot.match("dlq_messages", messages)


@pytest.mark.aws_validated
def test_report_batch_item_failures_invalid_result_json_batch_fails(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    # create queue used in the lambda to send invocation results to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    # timeout in seconds, used for both the lambda and the queue visibility timeout.
    # increase to 10 if testing against AWS fails.
    retry_timeout = 4
    retries = 2

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_BATCH_ITEM_FAILURE_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
        envvars={
            "DESTINATION_QUEUE_URL": destination_url,
            "OVERWRITE_RESULT": '{"batchItemFailures": [{"foo":"notvalid"}]}',
        },
    )

    # create dlq for event source queue
    event_dlq_url = sqs_create_queue(QueueName=f"event-dlq-{short_uid()}")
    event_dlq_arn = sqs_queue_arn(event_dlq_url)

    # create event source queue
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": event_dlq_arn, "maxReceiveCount": retries}
            ),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # wire everything with the event source mapping
    mapping_uuid = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=10,
        MaximumBatchingWindowInSeconds=0,
        FunctionResponseTypes=["ReportBatchItemFailures"],
    )["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

    # trigger the lambda, the message content doesn't matter because the whole batch should be treated as failure
    sqs_client.send_message(
        QueueUrl=event_source_url,
        MessageBody=json.dumps({"message": 1, "fail_attempts": 0}),
    )

    # now wait for the first invocation result which is expected to have processed message 1 we wait half the retry
    # interval to wait long enough for the message to appear, but short enough to check that the DLQ is empty after
    # the first attempt.
    first_invocation = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in first_invocation
    snapshot.match("first_invocation", first_invocation)

    # now wait for the second invocation result, which should be a retry of the first
    second_invocation = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in second_invocation
    # hack to make snapshot work
    snapshot.match("second_invocation", second_invocation)

    # now check that the messages was placed in the DLQ
    dlq_response = sqs_client.receive_message(QueueUrl=event_dlq_url, WaitTimeSeconds=15)
    assert "Messages" in dlq_response
    snapshot.match("dlq_response", dlq_response)


@pytest.mark.aws_validated
def test_report_batch_item_failures_empty_json_batch_succeeds(
    create_lambda_function,
    lambda_client,
    sqs_client,
    sqs_create_queue,
    sqs_queue_arn,
    lambda_su_role,
    snapshot,
    cleanups,
):
    # create queue used in the lambda to send invocation results to (to verify lambda was invoked)
    destination_queue_name = f"destination-queue-{short_uid()}"
    destination_url = sqs_create_queue(QueueName=destination_queue_name)
    snapshot.match(
        "get_destination_queue_url", sqs_client.get_queue_url(QueueName=destination_queue_name)
    )

    # timeout in seconds, used for both the lambda and the queue visibility timeout.
    # increase to 10 if testing against AWS fails.
    retry_timeout = 4
    retries = 1

    # set up lambda function
    function_name = f"failing-lambda-{short_uid()}"
    create_lambda_function(
        func_name=function_name,
        handler_file=LAMBDA_SQS_BATCH_ITEM_FAILURE_FILE,
        runtime=LAMBDA_RUNTIME_PYTHON38,
        role=lambda_su_role,
        timeout=retry_timeout,  # timeout needs to be <= than visibility timeout
        envvars={"DESTINATION_QUEUE_URL": destination_url, "OVERWRITE_RESULT": "{}"},
    )

    # create dlq for event source queue
    event_dlq_url = sqs_create_queue(QueueName=f"event-dlq-{short_uid()}")
    event_dlq_arn = sqs_queue_arn(event_dlq_url)

    # create event source queue
    # we use a FIFO queue to be sure the lambda is invoked in a deterministic way
    event_source_url = sqs_create_queue(
        QueueName=f"source-queue-{short_uid()}",
        Attributes={
            # the visibility timeout is implicitly also the time between retries
            "VisibilityTimeout": str(retry_timeout),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": event_dlq_arn, "maxReceiveCount": retries}
            ),
        },
    )
    event_source_arn = sqs_queue_arn(event_source_url)

    # wire everything with the event source mapping
    mapping_uuid = lambda_client.create_event_source_mapping(
        EventSourceArn=event_source_arn,
        FunctionName=function_name,
        BatchSize=10,
        MaximumBatchingWindowInSeconds=0,
        FunctionResponseTypes=["ReportBatchItemFailures"],
    )["UUID"]
    cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=mapping_uuid))
    _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

    # trigger the lambda, the message content doesn't matter because the whole batch should be treated as failure
    sqs_client.send_message(
        QueueUrl=event_source_url,
        MessageBody=json.dumps({"message": 1, "fail_attempts": 0}),
    )

    # now wait for the first invocation result which is expected to have processed message 1 we wait half the retry
    # interval to wait long enough for the message to appear, but short enough to check that the DLQ is empty after
    # the first attempt.
    first_invocation = sqs_client.receive_message(
        QueueUrl=destination_url, WaitTimeSeconds=15, MaxNumberOfMessages=1
    )
    assert "Messages" in first_invocation
    snapshot.match("first_invocation", first_invocation)

    # now check that the messages was placed in the DLQ
    dlq_response = sqs_client.receive_message(
        QueueUrl=event_dlq_url, WaitTimeSeconds=retry_timeout + 1
    )
    assert "Messages" not in dlq_response
