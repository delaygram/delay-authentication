import json
import os
import unittest
import boto3
from unittest import mock
from moto import mock_ssm, mock_cognitoidp, mock_events
from functions.confirm import app as confirm_function
from functions.register import app as register_function


@mock.patch.dict(os.environ, {"StageName": "test", 'DISABLE_XRAY': 'true', "EVENT_BUS": "test_event_bus"})
@mock_ssm
@mock_cognitoidp
@mock_events
class TestRegisterUser(unittest.TestCase):
    def setUp(self):
        self.cognito_mock = boto3.client('cognito-idp')
        self.cognito_user_pool = self.cognito_mock.create_user_pool(PoolName='DelaygramAuthorizerUserPoolName',
                                                                    AutoVerifiedAttributes=['email'],
                                                                    Schema=[{'AttributeDataType': 'String',
                                                                             'Name': 'email',
                                                                             'Required': True}])
        self.user_pool_id = self.cognito_user_pool['UserPool']['Id']

        self.cognito_client = self.cognito_mock.create_user_pool_client(ClientName='DelaygramAuthorizerClient',
                                                                        UserPoolId=self.user_pool_id,
                                                                        GenerateSecret=True)
        client_id = self.cognito_client['UserPoolClient']['ClientId']

        self.ssm_mock = boto3.client('ssm')
        self.ssm_mock.put_parameter(Name="DelaygramAuthorizerPoolId-test",
                                    Value=self.user_pool_id)
        self.ssm_mock.put_parameter(Name="DelaygramAuthorizerClientId-test",
                                    Value=client_id)

    def tearDown(self):
        self.ssm_mock.delete_parameters(
            Names=["DelaygramAuthorizerClientId-test", "DelaygramAuthorizerPoolId-test"])
        self.cognito_mock.delete_user_pool(UserPoolId=self.user_pool_id)

    def test_confirm_registration_happy_flow(self):
        self.register_test_user()

        confirmation_request = {'username': 'test_user',
                                'code': '1234'}
        confirmation_event = {'body': json.dumps(confirmation_request)}
        print(confirmation_event)
        context = 'not used'
        ret = confirm_function.lambda_handler(confirmation_event, context)

        assert ret['statusCode'] == 200
        assert ret['body'] == json.dumps({'username': 'test_user'})

    @staticmethod
    def register_test_user():
        registration_request = {
            'username': 'test_user',
            'password': 'test_password',
            'email': 'test@email.com'
        }

        register_event = {
            'body': json.dumps(registration_request)
        }

        context = 'not used'
        return register_function.lambda_handler(register_event, context)

    def admin_confirm_test_user(self):
        self.cognito_mock.admin_confirm_sign_up(
            UserPoolId=self.user_pool_id,
            Username='test_user'
        )
