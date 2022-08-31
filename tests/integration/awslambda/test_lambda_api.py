import json

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    is_old_provider,
    update_done,
)
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until
from tests.integration.awslambda.test_lambda import (
    TEST_LAMBDA_INTROSPECT_PYTHON,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NODEJS,
    TEST_LAMBDA_PYTHON_ECHO,
)


@pytest.fixture(autouse=True)
def fixture_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(
        snapshot.transform.key_value("CodeSha256", reference_replacement=False)
    )


# class TestLambdaFunction: ... # TODO
# class TestLambdaAlias: ... # TODO
# class TestLambdaVersions: ... # TODO
# class TestLambdaTag: ... # TODO
# class TestLambdaSigningConfig: ... # TODO

# pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=[
#     "$..Architectures",
#     "$..Environment",
# ])


class TestLambdaEventInvokeConfig:
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..FunctionArn"])
    @pytest.mark.aws_validated
    def test_lambda_asynchronous_invocations(
        self,
        lambda_client,
        create_lambda_function,
        sqs_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
        cleanups,
    ):
        """Testing API actions of function event config"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
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
        cleanups.append(
            lambda: lambda_client.delete_function_event_invoke_config(FunctionName=function_name)
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


class TestLambdaReservedConcurrency:
    @pytest.mark.skip(reason="very slow (only execute when needed)")
    # @pytest.mark.aws_validated
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

    @pytest.mark.skip(
        reason="Doesn't work when the account/region has a current global concurrency limit of < 101"
    )
    # @pytest.mark.aws_validated
    def test_function_concurrency(self, lambda_client, create_lambda_function, snapshot):
        """Testing the api of the put function concurrency action"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
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


class TestLambdaProvisionedConcurrency:
    @pytest.mark.skip(reason="very slow (only execute when needed)")
    # @pytest.mark.aws_validated
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


# API only functions (no lambda execution itself, i.e. no invoke)
class TestLambdaPermissions:
    @pytest.mark.aws_validated
    def test_add_lambda_permission_aws(
        self, lambda_client, iam_client, create_lambda_function, account_id, snapshot
    ):
        """Testing the add_permission call on lambda, by adding a new resource-based policy to a lambda function"""

        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
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

    # @pytest.mark.aws_validated
    def test_remove_multi_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Tests creation and subsequent removal of multiple permissions, including the changes in the policy"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
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

    # @pytest.mark.aws_validated
    def test_function_code_signing_config(self, lambda_client, create_lambda_function, snapshot):
        """Testing the API of code signing config"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
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

    # @pytest.mark.aws_validated
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


class TestLambdaUrl:
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
            runtime=Runtime.nodejs14_x,
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
