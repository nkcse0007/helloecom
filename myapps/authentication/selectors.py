# from flask_jwt_extended import create_access_token, create_refresh_token

# project resources
from myapps.models import UserLoginInfo, OrganizationModel, StoreModel, UserLocationModel, UserProfileModel
from utils.common import generate_response
from utils.http_code import *
import datetime
from utils.constants import *

expiry = datetime.timedelta(days=5)


def get_user_profile(payload):
    user = UserLoginInfo.objects(id=payload['id']).exclude('password').get().to_json()
    if user['role'] == ORGANIZATION_ROLE_TYPE:
        user['meta'] = OrganizationModel.objects.filter(user=user['id']).get().to_json()
    if user['role'] == STORE_ROLE_TYPE:
        user['meta'] = StoreModel.objects.filter(user=user['id']).get().to_json()
    if user['role'] == USER_ROLE_TYPE:
        user['meta'] = UserProfileModel.objects.filter(user=user['id']).get().to_json()

    return generate_response(data=user, status=HTTP_200_OK)


def get_organization_profile(payload):
    organization = OrganizationModel.objects.filter(id=payload['id']).last().to_json()
    organization['store'] = [store.to_json() for store in StoreModel.objects.filter(organization=organization['id'])]
    return generate_response(data=organization, status=HTTP_200_OK)


def get_store_profile(payload):
    organization = StoreModel.objects.filter(id=payload['id']).last().to_json()
    return generate_response(data=organization, status=HTTP_200_OK)


def get_user_location(jwt_payload, input_data):
    if 'id' in input_data:
        location = UserLocationModel.objects(id=input_data['id']).get().to_json()
    else:
        location = [loc.to_json() for loc in UserLocationModel.objects.filter(user=jwt_payload['id'])]
    return generate_response(data=location, status=HTTP_200_OK)
