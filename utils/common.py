import uuid
import requests
import string
import random
from utils.http_code import *
import os
import jwt
from datetime import datetime, timedelta, timezone


# import pandas as pd

def get_input_data(request):
    if request.method == 'GET':
        input_data = request.GET
    else:
        input_data = request.data
    return input_data


def generate_response(data=None, message=None, status=400):
    if status == HTTP_200_OK or status == HTTP_201_CREATED:
        status_bool = True
    else:
        status_bool = False

    return {
        'data': data,
        'message': modify_slz_error(message, status_bool),
        'status': status_bool,
        'status_code': status
    }


def modify_slz_error(message, status):
    final_error = list()
    if message:
        if type(message) == str:
            if not status:
                final_error.append(
                    {
                        'error': message
                    }
                )
            else:
                final_error = message
        elif type(message) == list:
            final_error = message
        else:
            for key, value in message.items():
                final_error.append(
                    {'error': str(key) + ': ' + str(value[0])}
                )
    else:
        final_error = None
    return final_error


def send_error(error, status=False, data=None):
    if data is None:
        data = {}
    return {'message': [{'error': error}], 'data': data, 'status': status}, 400


def change_file_name(filename):
    extension = filename.split('.')[-1]
    return uuid.uuid4().hex + '.' + extension


#
# def save_files_to_filesystem(file_name, file):
#     fs = FileSystemStorage()
#     filename = fs.save('sheets/' + file_name, file)
#     uploaded_file_url = fs.url(filename)
#     return uploaded_file_url


def get_client_ip(request):
    x_forwarded_for = request.remote_addr
    ip = x_forwarded_for.split(',')[0]
    return ip


# TODO get location from ip
def get_location(ip):
    try:
        loc = requests.request("GET", "http://ip-api.com/json/{0}".format(ip)).json()
        print(loc)
        location = loc['city'] + ', ' + loc['country'] + ', ' + loc['countryCode']
    except Exception as e:
        print(e)
        location = "unidentified"

    return location


def get_user_from_token(request=None, token=None):
    from utils.jwt.jwt_security import get_token, JwtAuth
    if not token:
        token = get_token(request)
    Jwt = JwtAuth(token)
    user, headers = Jwt.decode()[0], Jwt.decode()[1]
    return user


def id_generator(size=4, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


def alpha_id_generator(size=4, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class TokenGenerator:

    @staticmethod
    def encode_token(user):

        payload = {"exp": datetime.now(timezone.utc) + timedelta(days=1), "id": str(user.id)}
        token = jwt.encode(payload, os.environ.get('JWT_SECRET_KEY'), algorithm="HS256")
        return token

    @staticmethod
    def decode_token(token):
        return jwt.decode(token, os.environ.get('JWT_SECRET_KEY'), algorithms="HS256", options={"require_exp": True})

    @staticmethod
    def check_token(token):
        try:
            jwt.decode(token, os.environ.get('JWT_SECRET_KEY'), algorithms="HS256", options={"require_exp": True})
            return True
        except:
            return False

    @staticmethod
    def get_user_id(token):
        data = jwt.decode(token, os.environ.get('JWT_SECRET_KEY'), algorithms="HS256", options={"require_exp": True})
        return data['id']


account_activation_token = TokenGenerator()
