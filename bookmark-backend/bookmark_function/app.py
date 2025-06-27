import json # <-- ENSURE NO SPACES/TABS BEFORE THIS LINE
import os
import uuid
import boto3
import datetime
from decimal import Decimal
from botocore.exceptions import ClientError
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Custom JSON Encoder to handle Decimal objects from DynamoDB
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        return json.JSONEncoder.default(self, obj)

dynamodb = boto3.resource('dynamodb')
cognito_client = boto3.client('cognito-idp')

TABLE_NAME = os.environ.get('BOOKMARKS_TABLE_NAME')
USER_POOL_ID = os.environ.get('USER_POOL_ID')

def get_table():
    return dynamodb.Table(TABLE_NAME)

def get_user_id_from_event(event):
    """
    Extracts the user ID (sub) from the API Gateway event's requestContext.
    For authenticated requests, this comes from Cognito JWT claims.
    """
    try:
        if 'authorizer' in event['requestContext'] and \
           'claims' in event['requestContext']['authorizer'] and \
           'sub' in event['requestContext']['authorizer']['claims']:
            return event['requestContext']['authorizer']['claims']['sub']
        logger.warning("User ID (sub) not found in event context for an authorized request.")
        return None
    except KeyError as e:
        logger.error(f"Error extracting user ID from claims: {e}")
        return None

# Helper function to get current UTC timestamp in milliseconds
def current_time_millis():
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)

def register_user(event):
    """Handles user registration (Cognito SignUp)."""
    try:
        body = json.loads(event['body'])
        email = body.get('email')
        password = body.get('password')
        user_pool_client_id = body.get('userPoolClientId')

        if not all([email, password, user_pool_client_id]):
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'error': 'Email, password, and UserPoolClientId are required.'}, cls=DecimalEncoder)
            }

        response = cognito_client.sign_up(
            ClientId=user_pool_client_id,
            Username=email,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({
                'message': 'User registered successfully. Please confirm your email.',
                'userSub': response['UserConfirmed'],
                'userConfirmed': response['UserConfirmed']
            }, cls=DecimalEncoder)
        }
    except ClientError as e:
        logger.error(f"Cognito registration error: {e}")
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        status_code = 400 if error_code in ['UsernameExistsException', 'InvalidPasswordException', 'UserLambdaValidationException'] else 500
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': error_message, 'code': error_code}, cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"General registration error: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'An unexpected error occurred during registration.'}, cls=DecimalEncoder)
        }

def confirm_user_registration(event):
    """Handles user confirmation (Cognito ConfirmSignUp)."""
    try:
        body = json.loads(event['body'])
        email = body.get('email')
        confirmation_code = body.get('confirmationCode')
        user_pool_client_id = body.get('userPoolClientId')

        if not all([email, confirmation_code, user_pool_client_id]):
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'error': 'Email, confirmation code, and UserPoolClientId are required.'}, cls=DecimalEncoder)
            }

        response = cognito_client.confirm_sign_up(
            ClientId=user_pool_client_id,
            Username=email,
            ConfirmationCode=confirmation_code,
            ForceAliasCreation=False
        )
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'message': 'User confirmed successfully.'}, cls=DecimalEncoder)
        }
    except ClientError as e:
        logger.error(f"Cognito confirmation error: {e}")
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        status_code = 400 if error_code in ['CodeMismatchException', 'ExpiredCodeException', 'UserNotFoundException', 'NotAuthorizedException'] else 500
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': error_message, 'code': error_code}, cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"General confirmation error: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'An unexpected error occurred during confirmation.'}, cls=DecimalEncoder)
        }

def sign_in_user(event):
    """Handles user sign-in (Cognito InitiateAuth)."""
    try:
        body = json.loads(event['body'])
        email = body.get('email')
        password = body.get('password')
        user_pool_client_id = body.get('userPoolClientId')

        if not all([email, password, user_pool_client_id]):
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'error': 'Email, password, and UserPoolClientId are required.'}, cls=DecimalEncoder)
            }

        response = cognito_client.initiate_auth(
            ClientId=user_pool_client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({
                'message': 'Sign-in successful',
                'idToken': response['AuthenticationResult']['IdToken'],
                'accessToken': response['AuthenticationResult']['AccessToken'],
                'refreshToken': response['AuthenticationResult'].get('RefreshToken')
            }, cls=DecimalEncoder)
        }
    except ClientError as e:
        logger.error(f"Cognito sign-in error: {e}")
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        status_code = 400 if error_code in ['NotAuthorizedException', 'UserNotFoundException', 'UserNotConfirmedException'] else 500
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': error_message, 'code': error_code}, cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"General sign-in error: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'An unexpected error occurred during sign-in.'}, cls=DecimalEncoder)
        }

def create_bookmark(event, user_id):
    """Creates a new bookmark."""
    table = get_table()
    try:
        body = json.loads(event['body'])
        title = body.get('title')
        url = body.get('url')
        description = body.get('description', '')
        tags = body.get('tags', [])

        if not title or not url:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'message': 'Title and URL are required.'}, cls=DecimalEncoder)
            }

        bookmark_id = str(uuid.uuid4())
        item = {
            'userId': user_id,
            'bookmarkId': bookmark_id,
            'title': title,
            'url': url,
            'description': description,
            'tags': tags,
            'createdAt': current_time_millis(),
            'updatedAt': current_time_millis()
        }
        table.put_item(Item=item)
        return {
            'statusCode': 201,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps(item, cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"Error creating bookmark: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'Could not create bookmark.'}, cls=DecimalEncoder)
        }

def get_bookmarks(event, user_id):
    """Retrieves all bookmarks for a user."""
    table = get_table()
    try:
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('userId').eq(user_id)
        )
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps(response['Items'], cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"Error retrieving bookmarks: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'Could not retrieve bookmarks.'}, cls=DecimalEncoder)
        }

def get_bookmark_by_id(event, user_id):
    """Retrieves a single bookmark by ID for a user."""
    table = get_table()
    bookmark_id = event['pathParameters']['bookmarkId']
    try:
        response = table.get_item(
            Key={'userId': user_id, 'bookmarkId': bookmark_id}
        )
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'message': 'Bookmark not found.'}, cls=DecimalEncoder)
            }
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps(response['Item'], cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"Error retrieving bookmark by ID: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'Could not retrieve bookmark.'}, cls=DecimalEncoder)
        }

def update_bookmark(event, user_id):
    """Updates an existing bookmark for a user."""
    table = get_table()
    bookmark_id = event['pathParameters']['bookmarkId']
    try:
        body = json.loads(event['body'])
        title = body.get('title')
        url = body.get('url')
        description = body.get('description', '')
        tags = body.get('tags', [])

        update_expression_parts = []
        expression_attribute_values = {}
        expression_attribute_names = {}

        if title is not None:
            update_expression_parts.append('#T = :t')
            expression_attribute_names['#T'] = 'title'
            expression_attribute_values[':t'] = title
        if url is not None:
            update_expression_parts.append('#U = :u')
            expression_attribute_names['#U'] = 'url'
            expression_attribute_values[':u'] = url
        if description is not None:
            update_expression_parts.append('#D = :d')
            expression_attribute_names['#D'] = 'description'
            expression_attribute_values[':d'] = description
        if tags is not None:
            update_expression_parts.append('#TA = :ta')
            expression_attribute_names['#TA'] = 'tags'
            expression_attribute_values[':ta'] = tags

        if not update_expression_parts:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'message': 'No update parameters provided.'}, cls=DecimalEncoder)
            }

        update_expression_parts.append('updatedAt = :ua')
        expression_attribute_values[':ua'] = current_time_millis()

        update_expression = "SET " + ", ".join(update_expression_parts)

        response = table.update_item(
            Key={'userId': user_id, 'bookmarkId': bookmark_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues='ALL_NEW'
        )
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps(response['Attributes'], cls=DecimalEncoder)
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationException' and 'The provided key element does not match the schema' in e.response['Error']['Message']:
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'message': 'Bookmark not found or invalid key.'}, cls=DecimalEncoder)
            }
        logger.error(f"Error updating bookmark: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'Could not update bookmark.'}, cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"General error updating bookmark: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'An unexpected error occurred during update.'}, cls=DecimalEncoder)
        }


def delete_bookmark(event, user_id):
    """Deletes a bookmark for a user."""
    table = get_table()
    bookmark_id = event['pathParameters']['bookmarkId']
    try:
        response = table.delete_item(
            Key={'userId': user_id, 'bookmarkId': bookmark_id},
            ReturnValues='ALL_OLD'
        )
        if not response.get('Attributes'):
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
                },
                'body': json.dumps({'message': 'Bookmark not found.'}, cls=DecimalEncoder)
            }
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'message': 'Bookmark deleted successfully.'}, cls=DecimalEncoder)
        }
    except Exception as e:
        logger.error(f"Error deleting bookmark: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'error': 'Could not delete bookmark.'}, cls=DecimalEncoder)
        }

def lambda_handler(event, context):
    """Main Lambda handler to route requests."""
    logger.info(f"Received event: {json.dumps(event)}")
    http_method = event['httpMethod']
    path = event['path']

    # Handle CORS preflight OPTIONS requests
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            }
        }

    # Handle authentication paths (no authorizer)
    if path == '/register' and http_method == 'POST':
        return register_user(event)
    elif path == '/signin' and http_method == 'POST':
        return sign_in_user(event)
    elif path == '/confirm' and http_method == 'POST':
        return confirm_user_registration(event)

    # For all other paths, require authentication
    user_id = get_user_id_from_event(event)
    if not user_id:
        return {
            'statusCode': 401,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
            },
            'body': json.dumps({'message': 'Unauthorized: Missing or invalid authentication token.'}, cls=DecimalEncoder)
        }

    # Handle bookmark CRUD operations (requires authentication)
    if path == '/bookmarks':
        if http_method == 'POST':
            return create_bookmark(event, user_id)
        elif http_method == 'GET':
            return get_bookmarks(event, user_id)
    elif path.startswith('/bookmarks/'):
        # Extract bookmarkId from path
        path_parts = path.split('/')
        if len(path_parts) > 2:
            bookmark_id = path_parts[2]
            if http_method == 'GET':
                return get_bookmark_by_id(event, user_id)
            elif http_method == 'PUT':
                return update_bookmark(event, user_id)
            elif http_method == 'DELETE':
                return delete_bookmark(event, user_id)

    return {
        'statusCode': 404,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
        },
        'body': json.dumps({'message': 'Not Found'}, cls=DecimalEncoder)
    }
