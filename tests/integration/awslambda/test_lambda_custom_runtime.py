import pytest

from localstack.services.awslambda.lambda_api import use_docker
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.awslambda.test_lambda import PROVIDED_TEST_RUNTIMES, TEST_LAMBDA_CUSTOM_RUNTIME, read_streams


class TestCustomRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker provided runtimes not applicable if run locally"
    )
    @pytest.mark.parametrize(
        "runtime",
        PROVIDED_TEST_RUNTIMES,
    )
    @pytest.mark.skip_snapshot_verify
    def test_provided_runtimes(
        self, lambda_client, create_lambda_function, runtime, check_lambda_logs, snapshot
    ):
        """Test simple provided lambda (with curl as RIC) invocation"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_CUSTOM_RUNTIME,
            handler="function.handler",
            runtime=runtime,
        )
        snapshot.match("create-result", result)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"text": "bar with \'quotes\\""}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        result_data = result_data.strip()
        # jsonify in pro (re-)formats the event json so we allow both versions here
        assert result_data in (
            """Echoing request: '{"text": "bar with \'quotes\\""}'""",
            """Echoing request: '{"text":"bar with \'quotes\\""}'""",
        )

        # assert that logs are present
        expected = [".*Custom Runtime Lambda handler executing."]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=20)
