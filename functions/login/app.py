import base64
import hashlib
import hmac
import logging
import os

import boto3
import botocore
import simplejson as json


def lambda_handler(event, context):
    cognito = boto3.client('cognito-idp')
    event_bus = boto3.client('events')

    logging.info(f'Received event: {event}')

    body = json.loads(event['body'])
    username = body['username']
    password = body['password']

    try:
        logging.info(f'Attempting to authenticate user {username}')
        response = cognito.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': get_secret_hash(username, get_client_id(), get_user_pool_id())
            },
            ClientId=get_client_id()
        )

        logging.info(f'Authentication successful for user {username}')

        user_id = retrieve_user_id(username)

        logging.info(f'Publishing event for user {user_id} : {username}')
        result = event_bus.put_events(
            Entries=[{
                'Source': 'auth-login-lambda',
                'DetailType': 'UserLoggedIn',
                'Detail': json.dumps({
                    'user_id': user_id,
                    'username': username
                }),
                'EventBusName': os.environ.get('EVENT_BUS')
            }]
        )

        logging.info(f'Event published: {result}')
        logging.info(f'Returning response: {response}')
        return {
            'statusCode': 200,
            'body': json.dumps({
                'username': username,
                'access_token': response['AuthenticationResult']['IdToken']
            })
        }
    except botocore.exceptions.ClientError as error:
        logging.error(f'Client error: {error}')

        if error.response['Error']['Code'] == 'UserNotConfirmedException':
            logging.error(f'User {username} not confirmed')
            return {
                'statusCode': 403,
                'body': json.dumps({
                    'type': error.response['Error']['Code'],
                    'message': error.response['Error']['Message']
                })
            }
        elif error.response['Error']['Code'] == 'NotAuthorizedException':
            logging.error(f'User {username} not authorized')
            return {
                'statusCode': 404,
                'body': json.dumps({
                    'type': error.response['Error']['Code'],
                    'message': error.response['Error']['Message']
                })
            }
        elif error.response['Error']['Code'] == 'UserNotFoundException':
            logging.error(f'User {username} not found')
            return {
                'statusCode': 404,
                'body': json.dumps({
                    'type': error.response['Error']['Code'],
                    'message': error.response['Error']['Message']
                })
            }


def retrieve_user_id(username):
    logging.info(f'Retrieving user id for username {username}')
    response = boto3.client('cognito-idp').admin_get_user(
        UserPoolId=get_user_pool_id(),
        Username=username
    )
    return response['UserAttributes'][0]['Value']


def get_user_pool_id():
    stage_name = os.environ.get('StageName')
    user_pool_id_parameter_name = "DelaygramAuthorizer-" + stage_name
    return boto3.client('ssm').get_parameter(Name=user_pool_id_parameter_name)['Parameter']['Value']


def get_client_id():
    client_id_parameter_name = "DelaygramAuthorizerClient"
    return boto3.client('ssm').get_parameter(Name=client_id_parameter_name)['Parameter']['Value']


def get_client_secret(user_pool_id, client_id):
    response = boto3.client('cognito-idp').describe_user_pool(
        UserPoolId=user_pool_id,
        ClientId=client_id
    )
    return response['UserPoolClient']['ClientSecret']


def get_secret_hash(username, client_id, user_pool_id):
    client_secret = get_client_secret(user_pool_id, client_id)
    message = bytes(username + client_id + 'utf-8')
    key = bytes(client_secret, 'utf-8')
    return base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()
