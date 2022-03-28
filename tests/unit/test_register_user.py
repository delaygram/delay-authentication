import json
import os
import unittest
import boto3
from unittest import mock
from moto import mock_ssm, mock_cognitoidp, mock_events
from functions.register import app

@mock.patch.dict(os.environ, {"StageName": "test", 'DISABLE_XRAY': 'true', "EVENT_BUS": "test_event_bus"})
@mock_ssm
@mock_cognitoidp
@mock_events
class TestRegisterUser(unittest.TestCase):
    def setUp(self):
        # Mock Cognito
        self.cognito_mock = boto3.client('cognito-idp')
        self.cognito_user_pool = self.cognito_mock.create_user_pool(PoolName='test_pool',
                                                                    AutoVerifiedAttributes=['email'],
                                                                    Schema=[{'AttributeDataType': 'String',
                                                                             'Name': 'email',
                                                                             'Required': True}])
        self.user_pool_id = self.cognito_user_pool['UserPool']['Id']
        self.cognito_client = self.cognito_mock.create_user_pool_client(ClientName='test_client',
                                                                        UserPoolId=self.user_pool_id,
                                                                        GenerateSecret=True)
        client_id = self.cognito_client['UserPoolClient']['ClientId']

        # Mock SSM
        self.ssm_mock = boto3.client('ssm')
        self.ssm_mock.put_parameter(Name='DelaygramAuthorizerUserPoolId-test',
                                    Value=self.user_pool_id)
        self.ssm_mock.put_parameter(Name='DelaygramAuthorizerClientId-test',
                                    Value=client_id)

    def tearDown(self):
        self.cognito_mock.delete_user_pool(UserPoolId=self.user_pool_id)
        self.ssm_mock.delete_parameter(Name=['DelaygramAuthorizerUserPoolId-test','DelaygramAuthorizerClientId-test'])

    def test_register_user_happy_flow(self):
        ret = self.register_test_user()
        assert ret['statusCode'] == 201
        assert ret['body'] == json.dumps({'username': 'test_user'})
        registered_users = self.cognito_mock.list_users(UserPoolId=self.user_pool_id)['Users']
        assert len(registered_users) == 1
        assert registered_users[0]['Username'] == 'test_user'

    def test_register_user_alternate_flow_username_already_taken(self):