import json
import os
import unittest
import boto3
from unittest import mock
from moto import mock_ssm, mock_cognitoidp, mock_events
from functions.register import app as register_function
from functions.login import app as login_function


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

    def test_login_happy_flow(self):
        self.register_test_user()
        self.admin_confirm_test_user()

        login_request = {'username': 'test_user', 'password': 'test_password'}
        login_event = {'body': json.dumps(login_request)}
        context = 'not used'
        ret = login_function.lambda_handler(login_event, context)

        assert ret['statusCode'] == 200

    def test_login_alternative_flow_registered_but_not_confirmed(self):
        self.register_test_user()

        login_request = {'username': 'test_user', 'password': 'test_password'}
        login_event = {'body': json.dumps(login_request)}
        context = 'not used'
        ret = login_function.lambda_handler(login_event, context)

        assert ret['statusCode'] == 403
        assert ret['body'] == json.dumps({'type': 'UserNotConfirmedException',
                                          'message': 'User is not confirmed.'})

    def test_login_alternative_flow_wrong_username(self):
        self.register_test_user()
        self.admin_confirm_test_user()

        login_request = {'username': 'wrong_user', 'password': 'test_password'}
        login_event = {'body': json.dumps(login_request)}
        context = 'not used'
        ret = login_function.lambda_handler(login_event, context)

        assert ret['statusCode'] == 404
        assert ret['body'] == json.dumps({'type': 'UserNotFoundException',
                                          'message': 'User does not exist.'})

    def test_login_alternative_flow_wrong_password(self):
        self.register_test_user()
        self.admin_confirm_test_user()

        login_request = {'username': 'test_user', 'password': 'wrong_password'}
        login_event = {'body': json.dumps(login_request)}
        context = 'not used'
        ret = login_function.lambda_handler(login_event, context)

        assert ret["statusCode"] == 404
        assert ret["body"] == json.dumps({'type': 'NotAuthorizedException',
                                          'message': 'Incorrect username or password.'})

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
