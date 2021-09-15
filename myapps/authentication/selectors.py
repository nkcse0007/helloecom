# from flask_jwt_extended import create_access_token, create_refresh_token

# project resources
from myapps.models import UserLoginInfo, OrganizationModel, StoreModel, UserLocationModel, UserProfileModel
from utils.common import generate_response
from utils.http_code import *
import datetime
from utils.constants import *

expiry = datetime.timedelta(days=5)


def get_user_profile(payload):
    user = UserLoginInfo.objects(id=payload['id']).exclude('password').values().last()
    if user['role'] == ORGANIZATION_ROLE_TYPE:
        user['meta'] = OrganizationModel.objects.filter(user=user['id']).values().last()
    if user['role'] == STORE_ROLE_TYPE:
        user['meta'] = StoreModel.objects.filter(user=user['id']).values().last()
    if user['role'] == USER_ROLE_TYPE:
        user['meta'] = UserProfileModel.objects.filter(user=user['id']).values().last()

    return generate_response(data=user, status=HTTP_200_OK)


def get_organization_profile(payload):
    organization = OrganizationModel.objects.filter(id=payload['id']).values().last()
    organization['store'] = list(StoreModel.objects.filter(organization=organization['id']).values())
    return generate_response(data=organization, status=HTTP_200_OK)


def get_store_profile(payload):
    organization = StoreModel.objects.filter(id=payload['id']).values().last()
    return generate_response(data=organization, status=HTTP_200_OK)


def get_user_location(jwt_payload, input_data):
    if 'id' in input_data:
        location = UserLocationModel.objects.filter(id=input_data['id']).values().get()
    else:
        location = list(UserLocationModel.objects.filter(user=jwt_payload['id']).values())
    return generate_response(data=location, status=HTTP_200_OK)
