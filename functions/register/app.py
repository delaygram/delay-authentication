import base64
import hashlib
import hmac
import json
import boto3
import os
import botocore


def lambda_handler(event, context):
    cognito = boto3.client('cognito-idp')
    event_bus = boto3.client('events')

    print(f'Received event: {event}')

    body = json.loads(event['body'])
    username = body['username']
    password = body['password']
    email = body['email']

    try:
        print(f'Creating user {username}')
        response = cognito.sign_up(
            ClientId=get_client_id(),
            SecretHash=get_secret_hash(username, get_client_id(), get_user_pool_id()),
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email',
                 'Value': email}])

        print(f'User created: {response}')

        user_id = retrieve_user_id(username)

        print(f'Creating user pool trigger for user {user_id}')
        result = event_bus.put_events(Entries=[{'Source': 'auth-register-lambda',
                                                'DetailType': 'UserRegistered',
                                                'Detail': json.dumps({"username": username,
                                                                      "user_id": user_id}),
                                                'EventBusName': os.environ.get('EVENT_BUS')}])

        print(f'Returning response: {response}')
        return {"statusCode": 201,
                "body": json.dumps({"username": username})}

    except botocore.exceptions.ClientError as error:

        print(f'Error: {error}')

        return {"statusCode": 409,
                "body": json.dumps({
                    "type": error.response['Error']['Code'],
                    "message": error.response['Error']['Message']})}


def retrieve_user_id(username):
    print(f'Retrieving user id for username {username}')
    response = boto3.client('cognito-idp').admin_get_user(
        UserPoolId=get_user_pool_id(),
        Username=username
    )
    return response['UserAttributes'][0]['Value']


def get_user_pool_id():
    stage_name = os.environ.get('StageName')
    user_pool_id_parameter_name = "DelaygramAuthorizerPoolId-" + stage_name
    return boto3.client('ssm').get_parameter(Name=user_pool_id_parameter_name)['Parameter']['Value']


def get_client_id():
    stage_name = os.environ.get('StageName')
    client_id_parameter_name = "DelaygramAuthorizerClientId-" + stage_name
    return boto3.client('ssm').get_parameter(Name=client_id_parameter_name)['Parameter']['Value']


def get_client_secret(user_pool_id, client_id):
    response = boto3.client('cognito-idp').describe_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id
    )
    return response['UserPoolClient']['ClientSecret']


def get_secret_hash(username, client_id, user_pool_id):
    client_secret = get_client_secret(user_pool_id, client_id)
    message = bytes(username + client_id, 'utf-8')
    key = bytes(client_secret, 'utf-8')
    return base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()
