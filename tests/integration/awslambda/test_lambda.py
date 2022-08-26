import base64
import json
import logging
import os
from typing import Dict, TypeVar

import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.lambda_ import Runtime
from localstack.services.awslambda import lambda_api
from localstack.services.awslambda.lambda_api import (
    LAMBDA_DEFAULT_HANDLER,
    LAMBDA_TEST_ROLE,
    get_lambda_policy_name,
)
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    update_done,
)
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    load_file,
    retry,
    safe_requests,
    short_uid,
    to_bytes,
    to_str,
)
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.testutil import (
    create_lambda_archive,
)

from .functions import lambda_integration

LOG = logging.getLogger(__name__)


# TODO: find a better way to manage these handler files
THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_integration.py")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.py")
TEST_LAMBDA_PYTHON_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_python_version.py")
TEST_LAMBDA_PYTHON_UNHANDLED_ERROR = os.path.join(
    THIS_FOLDER, "functions/lambda_unhandled_error.py"
)
TEST_LAMBDA_AWS_PROXY = os.path.join(THIS_FOLDER, "functions/lambda_aws_proxy.py")
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, "functions/lambda_python3.py")
TEST_LAMBDA_INTEGRATION_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_integration.js")
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_handler.js")
TEST_LAMBDA_NODEJS_ES6 = os.path.join(THIS_FOLDER, "functions/lambda_handler_es6.mjs")
TEST_LAMBDA_HELLO_WORLD = os.path.join(THIS_FOLDER, "functions/lambda_hello_world.py")
TEST_LAMBDA_NODEJS_APIGW_INTEGRATION = os.path.join(THIS_FOLDER, "functions/apigw_integration.js")
TEST_LAMBDA_NODEJS_APIGW_502 = os.path.join(THIS_FOLDER, "functions/apigw_502.js")
TEST_LAMBDA_GOLANG_ZIP = os.path.join(THIS_FOLDER, "functions/golang/handler.zip")
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, "functions/lambda_integration.rb")
TEST_LAMBDA_DOTNETCORE2 = os.path.join(THIS_FOLDER, "functions/dotnetcore2/dotnetcore2.zip")
TEST_LAMBDA_DOTNETCORE31 = os.path.join(THIS_FOLDER, "functions/dotnetcore31/dotnetcore31.zip")
TEST_LAMBDA_DOTNET6 = os.path.join(THIS_FOLDER, "functions/dotnet6/dotnet6.zip")
TEST_LAMBDA_CUSTOM_RUNTIME = os.path.join(THIS_FOLDER, "functions/custom-runtime")
TEST_LAMBDA_HTTP_RUST = os.path.join(THIS_FOLDER, "functions/rust-lambda/function.zip")
TEST_LAMBDA_JAVA_WITH_LIB = os.path.join(
    THIS_FOLDER, "functions/java/lambda_echo/lambda-function-with-lib-0.0.1.jar"
)
TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS = os.path.join(
    THIS_FOLDER,
    "functions",
    "java",
    "lambda_multiple_handlers",
    "build",
    "distributions",
    "lambda-function-with-multiple-handlers.zip",
)
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, "functions/lambda_environment.py")

TEST_LAMBDA_SEND_MESSAGE_FILE = os.path.join(THIS_FOLDER, "functions/lambda_send_message.py")
TEST_LAMBDA_PUT_ITEM_FILE = os.path.join(THIS_FOLDER, "functions/lambda_put_item.py")
TEST_LAMBDA_START_EXECUTION_FILE = os.path.join(THIS_FOLDER, "functions/lambda_start_execution.py")

TEST_LAMBDA_URL = os.path.join(THIS_FOLDER, "functions/lambda_url.js")

TEST_LAMBDA_FUNCTION_PREFIX = "lambda-function"

TEST_GOLANG_LAMBDA_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/example-handler-{os}-{arch}.tar.gz"


TEST_LAMBDA_LIBS = [
    "requests",
    "psutil",
    "urllib3",
    "chardet",
    "certifi",
    "idna",
    "pip",
    "dns",
]

def is_old_provider():
    return (
        os.environ.get("TEST_TARGET") != "AWS_CLOUD"
        and os.environ.get("PROVIDER_OVERRIDE_LAMBDA") != "asf"
    )


PROVIDED_TEST_RUNTIMES = [
    Runtime.provided,
    # TODO remove skip once we use correct images
    pytest.param(
        Runtime.provided_al2,
        marks=pytest.mark.skipif(
            is_old_provider(), reason="curl missing in provided.al2 lambci image"
        ),
    ),
]

T = TypeVar("T")


def read_streams(payload: T) -> T:
    new_payload = {}
    for k, v in payload.items():
        if isinstance(v, Dict):
            new_payload[k] = read_streams(v)
        elif isinstance(v, StreamingBody):
            new_payload[k] = to_str(v.read())
        else:
            new_payload[k] = v
    return new_payload


# API only functions (no lambda execution itself, i.e. no invoke)
class TestLambdaAPI:
    @pytest.mark.only_localstack
    def test_create_lambda_function(self, lambda_client):
        """Basic test that creates and deletes a Lambda function"""
        func_name = f"lambda_func-{short_uid()}"
        kms_key_arn = f"arn:{aws_stack.get_partition()}:kms:{aws_stack.get_region()}:{get_aws_account_id()}:key11"
        vpc_config = {
            "SubnetIds": ["subnet-123456789"],
            "SecurityGroupIds": ["sg-123456789"],
        }
        tags = {"env": "testing"}

        kwargs = {
            "FunctionName": func_name,
            "Runtime": Runtime.python3_7,
            "Handler": LAMBDA_DEFAULT_HANDLER,
            "Role": LAMBDA_TEST_ROLE.format(account_id=get_aws_account_id()),
            "KMSKeyArn": kms_key_arn,
            "Code": {
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            "Timeout": 3,
            "VpcConfig": vpc_config,
            "Tags": tags,
            "Environment": {"Variables": {"foo": "bar"}},
        }

        result = lambda_client.create_function(**kwargs)
        function_arn = result["FunctionArn"]
        assert testutil.response_arn_matches_partition(lambda_client, function_arn)

        partial_function_arn = ":".join(function_arn.split(":")[3:])

        # Get function by Name, ARN and partial ARN
        for func_ref in [func_name, function_arn, partial_function_arn]:
            rs = lambda_client.get_function(FunctionName=func_ref)
            assert rs["Configuration"].get("KMSKeyArn", "") == kms_key_arn
            assert rs["Configuration"].get("VpcConfig", {}) == vpc_config
            assert rs["Tags"] == tags

        # clean up
        lambda_client.delete_function(FunctionName=func_name)
        with pytest.raises(Exception) as exc:
            lambda_client.delete_function(FunctionName=func_name)
        assert "ResourceNotFoundException" in str(exc)

    @pytest.mark.skip_snapshot_verify
    def test_add_lambda_permission_aws(
        self, lambda_client, iam_client, create_lambda_function, account_id, snapshot
    ):
        """Testing the add_permission call on lambda, by adding a new resource-based policy to a lambda function"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )
        lambda_arn = lambda_create_response["CreateFunctionResponse"]["FunctionArn"]
        snapshot.match("create_lambda", lambda_create_response)
        # create lambda permission
        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission", resp)

        # fetch lambda policy
        get_policy_result = lambda_client.get_policy(FunctionName=function_name)
        snapshot.match("get_policy", get_policy_result)
        assert lambda_arn == json.loads(get_policy_result["Policy"])["Statement"][0]["Resource"]

    # TODO permissions cannot be added to $LATEST
    @pytest.mark.skipif(
        not is_old_provider(), reason="test does not make valid assertions against AWS"
    )
    def test_add_lambda_permission(self, lambda_client, iam_client, create_lambda_function):
        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )
        lambda_arn = lambda_create_response["CreateFunctionResponse"]["FunctionArn"]
        # create lambda permission
        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )

        # fetch lambda policy
        policy = lambda_client.get_policy(FunctionName=function_name)["Policy"]
        assert isinstance(policy, str)
        policy = json.loads(to_str(policy))
        assert action == policy["Statement"][0]["Action"]
        assert sid == policy["Statement"][0]["Sid"]
        assert lambda_arn == policy["Statement"][0]["Resource"]
        assert principal == policy["Statement"][0]["Principal"]["Service"]
        assert (
            aws_stack.s3_bucket_arn("test-bucket")
            == policy["Statement"][0]["Condition"]["ArnLike"]["AWS:SourceArn"]
        )

        # fetch IAM policy
        # this is not a valid assertion in general (especially against AWS)
        policies = iam_client.list_policies(Scope="Local", MaxItems=500)["Policies"]
        policy_name = get_lambda_policy_name(function_name)
        matching = [p for p in policies if p["PolicyName"] == policy_name]
        assert len(matching) == 1
        assert ":policy/" in matching[0]["Arn"]

        # remove permission that we just added
        resp = lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            Qualifier="qual1",
            RevisionId="r1",
        )
        assert 200 == resp["ResponseMetadata"]["HTTPStatusCode"]

    @pytest.mark.skip_snapshot_verify
    def test_remove_multi_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Tests creation and subsequent removal of multiple permissions, including the changes in the policy"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )

        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        permission_1_add = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
        )
        snapshot.match("add_permission_1", permission_1_add)

        sid_2 = "sqs"
        principal_2 = "sqs.amazonaws.com"
        permission_2_add = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid_2,
            Principal=principal_2,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission_2", permission_2_add)
        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)

        with pytest.raises(ClientError) as e:
            lambda_client.remove_permission(
                FunctionName=function_name,
                StatementId="non-existent",
            )

        snapshot.match("expect_error_remove_permission", e.value.response)
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid_2,
        )
        policy = json.loads(
            lambda_client.get_policy(
                FunctionName=function_name,
            )["Policy"]
        )
        snapshot.match("policy_after_removal", policy)
        assert policy["Statement"][0]["Sid"] == sid

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
        )
        with pytest.raises(ClientError) as ctx:
            lambda_client.get_policy(FunctionName=function_name)
        snapshot.match("expect_exception_get_policy", ctx.value.response)
        assert ctx.value.response["Error"]["Code"] == "ResourceNotFoundException"

    @pytest.mark.skipif(
        not is_old_provider(), reason="test does not make valid assertions against AWS"
    )
    def test_add_lambda_multiple_permission(
        self, iam_client, lambda_client, create_lambda_function
    ):
        """Test adding multiple permissions"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )

        # create lambda permissions
        action = "lambda:InvokeFunction"
        principal = "s3.amazonaws.com"
        statement_ids = ["s4", "s5"]
        for sid in statement_ids:
            resp = lambda_client.add_permission(
                FunctionName=function_name,
                Action=action,
                StatementId=sid,
                Principal=principal,
                SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
            )
            assert "Statement" in resp

        # fetch IAM policy
        # this is not a valid assertion in general (especially against AWS)
        policies = iam_client.list_policies(Scope="Local", MaxItems=500)["Policies"]
        policy_name = get_lambda_policy_name(function_name)
        matching = [p for p in policies if p["PolicyName"] == policy_name]
        assert 1 == len(matching)
        assert ":policy/" in matching[0]["Arn"]

        # validate both statements
        policy = matching[0]
        versions = iam_client.list_policy_versions(PolicyArn=policy["Arn"])["Versions"]
        assert 1 == len(versions)
        statements = versions[0]["Document"]["Statement"]
        for i in range(len(statement_ids)):
            assert action == statements[i]["Action"]
            assert lambda_api.func_arn(function_name) == statements[i]["Resource"]
            assert principal == statements[i]["Principal"]["Service"]
            assert (
                aws_stack.s3_bucket_arn("test-bucket")
                == statements[i]["Condition"]["ArnLike"]["AWS:SourceArn"]
            )
            # check statement_ids in reverse order
            assert statement_ids[abs(i - 1)] == statements[i]["Sid"]

        # remove permission that we just added
        resp = lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            Qualifier="qual1",
            RevisionId="r1",
        )
        assert 200 == resp["ResponseMetadata"]["HTTPStatusCode"]

    @pytest.mark.skip_snapshot_verify
    @pytest.mark.snapshot
    def test_lambda_asynchronous_invocations(
        self,
        lambda_client,
        create_lambda_function,
        sqs_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        """Testing API actions of function event config"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
            role=lambda_su_role,
        )
        queue_arn = sqs_queue_arn(sqs_queue)
        destination_config = {
            "OnSuccess": {"Destination": queue_arn},
            "OnFailure": {"Destination": queue_arn},
        }

        # adding event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            MaximumEventAgeInSeconds=123,
            DestinationConfig=destination_config,
        )
        snapshot.match("put_function_event_invoke_config", response)

        # over writing event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            DestinationConfig=destination_config,
        )
        snapshot.match("put_function_event_invoke_config_overwritemaxeventage", response)

        # updating event invoke config
        response = lambda_client.update_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=1,
        )
        snapshot.match("put_function_event_invoke_config_maxattempt1", response)

        # clean up
        lambda_client.delete_function_event_invoke_config(FunctionName=function_name)

    def test_function_concurrency(self, lambda_client, create_lambda_function, snapshot):
        """Testing the api of the put function concurrency action"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )
        # TODO botocore.errorfactory.InvalidParameterValueException:
        #  An error occurred (InvalidParameterValueException) when calling the PutFunctionConcurrency operation: Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [50].
        response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=123
        )
        snapshot.match("put_function_concurrency", response)
        assert "ReservedConcurrentExecutions" in response
        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency", response)
        assert "ReservedConcurrentExecutions" in response
        lambda_client.delete_function_concurrency(FunctionName=function_name)

    @pytest.mark.skip_snapshot_verify
    def test_function_code_signing_config(self, lambda_client, create_lambda_function, snapshot):
        """Testing the API of code signing config"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )

        response = lambda_client.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{aws_stack.get_region()}:000000000000:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
        snapshot.match("create_code_signing_config", response)

        assert "Description" in response["CodeSigningConfig"]
        assert "SigningProfileVersionArns" in response["CodeSigningConfig"]["AllowedPublishers"]
        assert (
            "UntrustedArtifactOnDeployment" in response["CodeSigningConfig"]["CodeSigningPolicies"]
        )

        code_signing_arn = response["CodeSigningConfig"]["CodeSigningConfigArn"]
        response = lambda_client.update_code_signing_config(
            CodeSigningConfigArn=code_signing_arn,
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        )
        snapshot.match("update_code_signing_config", response)

        assert (
            "Warn"
            == response["CodeSigningConfig"]["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"]
        )
        response = lambda_client.get_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        snapshot.match("get_code_signing_config", response)

        response = lambda_client.put_function_code_signing_config(
            CodeSigningConfigArn=code_signing_arn, FunctionName=function_name
        )
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        snapshot.match("put_function_code_signing_config", response)

        response = lambda_client.get_function_code_signing_config(FunctionName=function_name)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        snapshot.match("get_function_code_signing_config", response)
        assert code_signing_arn == response["CodeSigningConfigArn"]
        assert function_name == response["FunctionName"]

        response = lambda_client.delete_function_code_signing_config(FunctionName=function_name)
        assert 204 == response["ResponseMetadata"]["HTTPStatusCode"]

        response = lambda_client.delete_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        assert 204 == response["ResponseMetadata"]["HTTPStatusCode"]

    # TODO not executed
    def create_multiple_lambda_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Test creating multiple lambda permissions and checking the policy"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"test-function-{short_uid()}"

        # FIXME no zip file/function?
        create_lambda_function(
            func_name=function_name,
            runtime=Runtime.python3_7,
            libs=TEST_LAMBDA_LIBS,
        )

        action = "lambda:InvokeFunction"
        sid = "logs"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="logs.amazonaws.com",
        )
        snapshot.match("add_permission_response_1", resp)
        assert "Statement" in resp

        sid = "kinesis"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="kinesis.amazonaws.com",
        )
        snapshot.match("add_permission_response_2", resp)

        assert "Statement" in resp

        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)

    @pytest.mark.aws_validated
    def test_url_config_lifecycle(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value(
                    "FunctionUrl", "lambda-url", reference_replacement=False
                ),
            ]
        )

        function_name = f"test-function-{short_uid()}"

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ex:
            lambda_client.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_creation", ex.value.response)

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=Runtime.nodejs14X,
            handler="lambda_handler.handler",
        )

        url_config_created = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("url_creation", url_config_created)

        with pytest.raises(lambda_client.exceptions.ResourceConflictException) as ex:
            lambda_client.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_duplication", ex.value.response)

        url_config_obtained = lambda_client.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config", url_config_obtained)

        url_config_updated = lambda_client.update_function_url_config(
            FunctionName=function_name,
            AuthType="AWS_IAM",
        )
        snapshot.match("updated_url_config", url_config_updated)

        lambda_client.delete_function_url_config(FunctionName=function_name)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ex:
            lambda_client.get_function_url_config(FunctionName=function_name)
        snapshot.match("failed_getter", ex.value.response)


class TestLambdaBaseFeatures:
    @pytest.mark.skip_snapshot_verify
    def test_dead_letter_queue(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        """Creates a lambda with a defined dead letter queue, and check failed lambda invocation leads to a message"""
        # create DLQ and Lambda function
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())

        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            runtime=Runtime.python3_6,
            DeadLetterConfig={"TargetArn": queue_arn},
            role=lambda_su_role,
        )
        snapshot.match("create_lambda_with_dlq", create_lambda_response)

        # invoke Lambda, triggering an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        # assert that message has been received on the DLQ
        def receive_dlq():
            result = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(result["Messages"]) > 0
            msg_attrs = result["Messages"][0]["MessageAttributes"]
            assert "RequestID" in msg_attrs
            assert "ErrorCode" in msg_attrs
            assert "ErrorMessage" in msg_attrs
            snapshot.match("sqs_dlq_message", result)

        # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here, potential flakes
        retry(receive_dlq, retries=120, sleep=3)

        # update DLQ config
        update_function_config_response = lambda_client.update_function_configuration(
            FunctionName=lambda_name, DeadLetterConfig={}
        )
        snapshot.match("delete_dlq", update_function_config_response)
        # invoke Lambda again, assert that status code is 200 and error details contained in the payload
        result = lambda_client.invoke(
            FunctionName=lambda_name, Payload=json.dumps(payload), LogType="Tail"
        )
        result = read_streams(result)
        payload = json.loads(to_str(result["Payload"]))
        snapshot.match("result_payload", payload)
        assert 200 == result["StatusCode"]
        assert "Unhandled" == result["FunctionError"]
        assert "$LATEST" == result["ExecutedVersion"]
        assert "Test exception" in payload["errorMessage"]
        assert "Exception" in payload["errorType"]
        assert isinstance(payload["stackTrace"], list)
        log_result = result.get("LogResult")
        assert log_result
        logs = to_str(base64.b64decode(to_str(log_result)))
        assert "START" in logs
        assert "Test exception" in logs
        assert "END" in logs
        assert "REPORT" in logs

    @pytest.mark.parametrize(
        "condition,payload",
        [
            ("Success", {}),
            ("RetriesExhausted", {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}),
        ],
    )
    @pytest.mark.skip_snapshot_verify
    def test_assess_lambda_destination_invocation(
        self,
        condition,
        payload,
        lambda_client,
        sqs_client,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        # message body contains ARN
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))

        """Testing the destination config API and operation (for the OnSuccess case)"""
        # create DLQ and Lambda function
        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            role=lambda_su_role,
        )

        put_event_invoke_config_response = lambda_client.put_function_event_invoke_config(
            FunctionName=lambda_name,
            DestinationConfig={
                "OnSuccess": {"Destination": queue_arn},
                "OnFailure": {"Destination": queue_arn},
            },
        )
        snapshot.match("put_function_event_invoke_config", put_event_invoke_config_response)

        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(rs["Messages"]) > 0
            msg = rs["Messages"][0]["Body"]
            msg = json.loads(msg)
            assert condition == msg["requestContext"]["condition"]
            snapshot.match("destination_message", rs)

        retry(receive_message, retries=120, sleep=3)

    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult"])
    def test_large_payloads(self, caplog, lambda_client, create_lambda_function, snapshot):
        """Testing large payloads sent to lambda functions (~5MB)"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_6,
        )
        payload = {"test": "test123456" * 100 * 1000 * 5}  # 5MB payload
        payload_bytes = to_bytes(json.dumps(payload))
        result = lambda_client.invoke(FunctionName=function_name, Payload=payload_bytes)
        result = read_streams(result)
        snapshot.match("invocation_response", result)
        assert 200 == result["ResponseMetadata"]["HTTPStatusCode"]
        result_data = result["Payload"]
        result_data = json.loads(to_str(result_data))
        assert payload == result_data

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify  # skipped - the diff is too big
    @pytest.mark.skipif(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="Lambda function state pending for small lambdas not supported on localstack",
    )
    def test_function_state(self, lambda_client, lambda_su_role, snapshot):
        """Tests if a lambda starts in state "Pending" but moves to "Active" at some point"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        # necessary due to changing zip timestamps. We might need a reproducible archive method for this
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        function_name = f"test-function-{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

        try:

            def create_function():
                return lambda_client.create_function(
                    FunctionName=function_name,
                    Runtime="python3.9",
                    Handler="handler.handler",
                    Role=lambda_su_role,
                    Code={"ZipFile": zip_file},
                )

            response = retry(create_function, sleep=3, retries=5)

            snapshot.match("create-fn-response", response)
            assert response["State"] == "Pending"

            # lambda has to get active at some point
            def _check_lambda_state():
                response = lambda_client.get_function(FunctionName=function_name)
                assert response["Configuration"]["State"] == "Active"
                return response

            response = retry(_check_lambda_state)
            snapshot.match("get-fn-response", response)
        finally:
            try:
                lambda_client.delete_function(FunctionName=function_name)
            except Exception:
                LOG.debug("Unable to delete function %s", function_name)




TEST_LAMBDA_CACHE_NODEJS = os.path.join(THIS_FOLDER, "functions", "lambda_cache.js")
TEST_LAMBDA_CACHE_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_cache.py")
TEST_LAMBDA_TIMEOUT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_timeout.py")
TEST_LAMBDA_INTROSPECT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_introspect.py")


class TestLambdaBehavior:
    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (
                TEST_LAMBDA_CACHE_NODEJS,
                Runtime.nodejs12X,
            ),  # TODO: can we do some kind of nested parametrize here?
            (TEST_LAMBDA_CACHE_PYTHON, Runtime.python3_8),
        ],
        ids=["nodejs", "python"],
    )
    @pytest.mark.xfail(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="lambda caching not supported currently",
    )  # TODO: should be removed after the lambda rework
    def test_lambda_cache_local(
        self, lambda_client, create_lambda_function, lambda_fn, lambda_runtime
    ):
        """tests the local context reuse of packages in AWS lambda"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
        )

        result = lambda_client.invoke(FunctionName=func_name)
        result_data = result["Payload"].read()
        assert result["StatusCode"] == 200
        assert json.loads(result_data)["counter"] == 0

        result = lambda_client.invoke(FunctionName=func_name)
        result_data = result["Payload"].read()
        assert result["StatusCode"] == 200
        assert json.loads(result_data)["counter"] == 1

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_TIMEOUT_PYTHON, Runtime.python3_8),
        ],
        ids=["python"],
    )
    @pytest.mark.xfail(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="lambda timeouts not supported currently",
    )  # TODO: should be removed after the lambda rework
    def test_lambda_timeout_logs(
        self,
        lambda_client,
        create_lambda_function,
        lambda_fn,
        lambda_runtime,
        logs_client,
        snapshot,
    ):
        """tests the local context reuse of packages in AWS lambda"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
            timeout=1,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 2}))
        snapshot.match("invoke-result", result)
        assert result["StatusCode"] == 200

        log_group_name = f"/aws/lambda/{func_name}"
        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def assert_events():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert any(["starting wait" in e["message"] for e in log_events])
            assert not any(["done waiting" in e["message"] for e in log_events])

        retry(assert_events, retries=15)

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_TIMEOUT_PYTHON, Runtime.python3_8),
        ],
        ids=["python"],
    )
    @pytest.mark.skip_snapshot_verify
    def test_lambda_no_timeout_logs(
        self,
        lambda_client,
        create_lambda_function,
        lambda_fn,
        lambda_runtime,
        logs_client,
        snapshot,
    ):
        """tests the local context reuse of packages in AWS lambda"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 1}))
        snapshot.match("invoke-result", result)
        assert result["StatusCode"] == 200
        log_group_name = f"/aws/lambda/{func_name}"

        def _log_stream_available():
            result = logs_client.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            return len(result) > 0

        wait_until(_log_stream_available, strategy="linear")

        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def _assert_log_output():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]
            return any(["starting wait" in e["message"] for e in log_events]) and any(
                ["done waiting" in e["message"] for e in log_events]
            )

        wait_until(_assert_log_output, strategy="linear")

    @pytest.mark.skip(reason="very slow (only execute when needed)")
    def test_lambda_provisioned_concurrency_moves_with_alias(
        self, lambda_client, logs_client, create_lambda_function, snapshot
    ):
        """
        create fn ⇒ publish version ⇒ create alias for version ⇒ put concurrency on alias
        ⇒ new version with change ⇒ change alias to new version ⇒ concurrency moves with alias? same behavior for calls to alias/version?
        """
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        alias_name = f"test_alias_{short_uid()}"

        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        snapshot.match("get-function-configuration", fn)
        assert fn["State"] == "Active"

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        snapshot.match("publish_version_1", first_ver)
        assert first_ver["State"] == "Active"
        assert fn["RevisionId"] != first_ver["RevisionId"]

        get_function_configuration = lambda_client.get_function_configuration(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_configuration_version_1", first_ver)
        assert get_function_configuration["RevisionId"] == first_ver["RevisionId"]

        # There's no ProvisionedConcurrencyConfiguration yet
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create Alias and add ProvisionedConcurrencyConfiguration to it
        alias = lambda_client.create_alias(
            FunctionName=func_name, FunctionVersion=first_ver["Version"], Name=alias_name
        )
        snapshot.match("create_alias", alias)
        assert alias["FunctionVersion"] == first_ver["Version"]
        assert alias["RevisionId"] != first_ver["RevisionId"]
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        versioned_revision_id_before = get_function_result["Configuration"]["RevisionId"]
        snapshot.match("get_function_before_provisioned", get_function_result)
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, alias_name))
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_function_after_provisioned", get_function_result)
        versioned_revision_id_after = get_function_result["Configuration"]["RevisionId"]
        assert versioned_revision_id_before != versioned_revision_id_after

        # Alias AND Version now both use provisioned-concurrency (!)
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # Update lambda configuration and publish new version
        lambda_client.update_function_configuration(FunctionName=func_name, Timeout=10)
        assert wait_until(update_done(lambda_client, func_name))
        lambda_conf = lambda_client.get_function_configuration(FunctionName=func_name)
        snapshot.match("get_function_after_update", lambda_conf)

        # Move existing alias to the new version
        new_version = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=lambda_conf["RevisionId"]
        )
        snapshot.match("publish_version_2", new_version)
        new_alias = lambda_client.update_alias(
            FunctionName=func_name, FunctionVersion=new_version["Version"], Name=alias_name
        )
        snapshot.match("update_alias", new_alias)
        assert new_alias["RevisionId"] != new_version["RevisionId"]

        # lambda should now be provisioning new "hot" execution environments for this new alias->version pointer
        # the old one should be de-provisioned
        get_provisioned_config_result = lambda_client.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_provisioned_config_after_alias_move", get_provisioned_config_result)
        assert wait_until(
            concurrency_update_done(lambda_client, func_name, alias_name),
            strategy="linear",
            wait=30,
            max_retries=20,
            _max_wait=600,
        )  # this is SLOW (~6-8 min)

        # concurrency should still only work for the alias now
        # NOTE: the old version has been de-provisioned and will run 'on-demand' now!
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"
        assert (
            get_invoke_init_type(lambda_client, func_name, new_version["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # ProvisionedConcurrencyConfig should only be "registered" to the alias, not the referenced version
        with pytest.raises(Exception) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=new_version["Version"]
            )
        e.match("ProvisionedConcurrencyConfigNotFoundException")

    @pytest.mark.skip(reason="very slow (only execute when needed)")
    def test_lambda_provisioned_concurrency_doesnt_apply_to_latest(
        self, lambda_client, logs_client, create_lambda_function
    ):
        """create fn ⇒ publish version ⇒ provisioned concurrency @version ⇒ test if it applies to call to $LATEST"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        assert fn["State"] == "Active"

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        assert first_ver["State"] == "Active"
        assert fn["RevisionId"] != first_ver["RevisionId"]
        assert (
            lambda_client.get_function_configuration(
                FunctionName=func_name, Qualifier=first_ver["Version"]
            )["RevisionId"]
            == first_ver["RevisionId"]
        )

        # Normal published version without ProvisionedConcurrencyConfiguration
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create ProvisionedConcurrencyConfiguration for this Version
        versioned_revision_id_before = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )["Configuration"]["RevisionId"]
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name,
            Qualifier=first_ver["Version"],
            ProvisionedConcurrentExecutions=1,
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, first_ver["Version"]))
        versioned_revision_id_after = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )["Configuration"]["RevisionId"]
        assert versioned_revision_id_before != versioned_revision_id_after
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )

        # $LATEST does *NOT* use provisioned concurrency
        assert get_invoke_init_type(lambda_client, func_name, "$LATEST") == "on-demand"
        # TODO: why is this flaky?
        # assert lambda_client.get_function(FunctionName=func_name, Qualifier='$LATEST')['Configuration']['RevisionId'] == lambda_client.get_function(FunctionName=func_name, Qualifier=first_ver['Version'])['Configuration']['RevisionId']


# features
class TestLambdaURL:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..context",
            "$..event.headers.x-forwarded-proto",
            "$..event.headers.x-forwarded-for",
            "$..event.headers.x-forwarded-port",
            "$..event.headers.x-amzn-lambda-forwarded-client-ip",
            "$..event.headers.x-amzn-lambda-forwarded-host",
            "$..event.headers.x-amzn-lambda-proxy-auth",
            "$..event.headers.x-amzn-lambda-proxying-cell",
            "$..event.headers.x-amzn-trace-id",
        ]
    )
    def test_lambda_url_invocation(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("requestId", "uuid", reference_replacement=False),
                snapshot.transform.key_value(
                    "FunctionUrl", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.http.sourceIp",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-forwarded-for", "ip-address", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-amzn-lambda-forwarded-client-ip",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-amzn-lambda-forwarded-host",
                    "lambda-url",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.host", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.apiId", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.domainName", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.domainPrefix", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.time", "readable-date", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.timeEpoch",
                    "epoch-milliseconds",
                    reference_replacement=False,
                ),
            ]
        )

        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs14X,
            handler="lambda_url.handler",
        )

        url_config = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )

        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )

        snapshot.match("add_permission", permissions_response)

        url = url_config["FunctionUrl"]
        url += "custom_path/extend?test_param=test_value"

        result = safe_requests.post(
            url, data=b"{'key':'value'}", headers={"User-Agent": "python-requests/testing"}
        )

        assert result.status_code == 200
        snapshot.match("lambda_url_invocation", json.loads(result.content))

        result = safe_requests.post(url, data="text", headers={"Content-Type": "text/plain"})
        event = json.loads(result.content)["event"]
        assert event["body"] == "text"
        assert event["isBase64Encoded"] is False

        result = safe_requests.post(url)
        event = json.loads(result.content)["event"]
        assert "Body" not in event
        assert event["isBase64Encoded"] is False

