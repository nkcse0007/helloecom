from functools import wraps

import jwt
from datetime import datetime, timedelta
from uuid import uuid4
from myapps.models import UserLoginInfo
from utils.common import generate_response
from utils.http_code import *
import os
from django.http.response import JsonResponse
from utils.common import get_input_data

private_key = open('utils/jwt/private.pem').read()
public_key = open('utils/jwt/public.pub').read()
refresh_private_key = open('utils/jwt/refresh_private.pem').read()
refresh_public_key = open('utils/jwt/refresh_public.pub').read()


class JwtAuth:

    def __init__(self, row_or_token=None):
        self.data = row_or_token

    def encode(self, payload, request, user):
        """
        params: payload, request
        usage: generate access and refresh token.
        """
        jwt_id = uuid4().hex
        try:
            origin = request.META['HTTP_ORIGIN'].split('//')[1]
            print(request.META['HTTP_ORIGIN'].split('//')[1])
        except:
            print('EXCEPTION IN ORIGIN>>')
            # print(e)
            origin = ''

        encoded_jwt = jwt.encode(payload,
                                 private_key, algorithm='RS512', headers={
                                    'exp': (datetime.now() + timedelta(days=10)).timestamp(),
                                    'aud': origin,
                                    'sub': user.email,
                                    'iss': 'CommonDashboard',
                                    'kid': jwt_id,
                                    'iat': int(datetime.now().timestamp())
            })

        refresh_token = jwt.encode(payload,
                                   refresh_private_key, algorithm='RS512', headers={
                                    'exp': (datetime.now() + timedelta(days=10)).timestamp(),
                                    'aud': origin,
                                    'sub': user.email,
                                    'iss': 'MyCvFactory',
                                    'kid': jwt_id,
                                    'iat': int(datetime.now().timestamp())
            })

        return encoded_jwt.decode(), refresh_token.decode()

    def decode(self):
        """
        usage: decode token and find payload and header from the token.
        """
        payload = jwt.decode(self.data, public_key, algorithms='RS512')
        headers = jwt.get_unverified_header(self.data)
        return payload, headers

    def decode_refresh(self):
        """
        usage: decode refresh token and find payload and header from the token.
        """
        payload = jwt.decode(self.data, refresh_public_key, algorithms='RS512')
        headers = jwt.get_unverified_header(self.data)
        return payload, headers


def authenticate_login(fun):
    """
    param: function
    usage: decorator to check if user is authenticated, token is valid, token not expired.
    """

    @wraps(fun)
    def function_wrapper(request, *args, **kwargs):
        try:
            try:
                token = request.headers.get('Authorization').split()
                if not token:
                    token = get_input_data(request)['access_token']
                if not token:
                    return JsonResponse(generate_response(message='Unauthorised User', status=HTTP_401_UNAUTHORIZED))

                if len(token) == 1:
                    return generate_response(message='Invalid token header, no token provided.',
                                             status=HTTP_401_UNAUTHORIZED)

                try:
                    token = token[-1]
                    if token == "null" or not token:
                        return generate_response(message='Null token not allowed.', status=HTTP_401_UNAUTHORIZED)
                except UnicodeError:
                    return generate_response(
                        message='Error! Invalid token header. Token string should not contain invalid characters.',
                        status=HTTP_401_UNAUTHORIZED)

                try:
                    dec = JwtAuth(str(token))
                    payload, headers = dec.decode()
                except UnicodeError:
                    return generate_response(
                        message='Error! Invalid token header.',
                        status=HTTP_401_UNAUTHORIZED)
            except Exception as e:
                print(e)
                return generate_response(message='Unauthorised user', status=HTTP_401_UNAUTHORIZED)

            if datetime.fromtimestamp(headers['exp']) < datetime.now():
                return generate_response(message='Token Expired.', status=HTTP_401_UNAUTHORIZED)

            if UserLoginInfo.objects(id=payload['id']):

                if not UserLoginInfo.objects(id=payload['id']):
                    return generate_response(message='Unauthorised user', status=HTTP_401_UNAUTHORIZED)

                if not UserLoginInfo.objects.get(id=payload['id'])['is_active']:
                    return generate_response(message='User is inactive. Please contact admin.',
                                             status=HTTP_401_UNAUTHORIZED)

                if UserLoginInfo.objects.get(id=payload['id'])['is_deleted']:
                    return generate_response(message='User is deleted previously. Please contact admin.',
                                             status=HTTP_401_UNAUTHORIZED)

                return fun(*args, **kwargs)

            else:
                return generate_response(message='User is inactive. Please contact admin.',
                                         status=HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return generate_response(message='Authentication failed, Invalid token. Please login again.',
                                     status=HTTP_401_UNAUTHORIZED)

    return function_wrapper


def get_token(request):
    """
    param: request
    usage: find token from the request. if token in body, param or header.
    """
    token = request.headers.get('Authorization').split()
    if not token:
        token = get_input_data(request)['access_token']
    if not token:
        return JsonResponse(generate_response(message='Unauthorised User', status=HTTP_401_UNAUTHORIZED))

    if len(token) == 1:
        return JsonResponse(generate_response(message='Invalid token header, no token provided.',
                                              status=HTTP_401_UNAUTHORIZED))

    token = token[-1]
    if token == "null" or not token:
        return JsonResponse(generate_response(message='Null token not allowed.', status=HTTP_401_UNAUTHORIZED))
    return token


def get_new_refresh_token(refresh_token):
    """
    Validate and get applicant from applicant_id

    Args:
        refresh_token: Either the applicant table ID or job applicant table ID

    Returns:
        access_token: New Access Token

    Raise:
        GraphQLError: if applicant_id is not valid

    """
    decoded_jwt = jwt.decode(refresh_token, refresh_public_key, algorithms='RS512')
    user = UserLoginInfo.objects.get(id=decoded_jwt['id'])
    jwt_id = uuid4().hex
    origin = ''
    encoded_jwt = jwt.encode(
        {'id': str(user['id']), 'email': user['email']},
        private_key, algorithm='RS512', headers={
            'exp': (datetime.now() + timedelta(days=10)).timestamp(),
            'aud': origin,
            'sub': user['email'],
            'iss': 'MyCvFactory',
            'kid': jwt_id,
            'iat': int(datetime.now().timestamp())
        })

    return encoded_jwt


def get_user_from_token(request):
    token = get_token(request)
    Jwt = JwtAuth(token)
    user_id, headers = Jwt.decode()[0]['id'] if 'id' in Jwt.decode()[0] else '', Jwt.decode()[1]
    user = UserLoginInfo.objects.get(id=user_id)
    return user, headers


def get_refresh_access_token(request, user):
    Jwt = JwtAuth(os.environ.get('VERIFY_TOKEN'))
    response = {
        'id': str(user.id),
        'phone': user.phone,
        'email': user.email,
        'role': user.role,
        'auth_type': user.auth_type,
    }
    return Jwt.encode(response, request, user)
