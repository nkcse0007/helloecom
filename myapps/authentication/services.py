# project resources
from myapps.models import UserLoginInfo, OrganizationModel, StoreModel, UserLocationModel, UserProfileModel
from utils.common import generate_response
from utils.http_code import *
from utils.services.email_service import send_verification_email
from utils.constants import *
from utils.services.twilio_otp import create_otp
from utils.jwt.jwt_security import get_refresh_access_token
from django.db.models import Q
import random


def create_user(request, input_data):
    if 'auth_type' not in input_data or not input_data['auth_type']:
        return generate_response(message='auth_type is required.')
    if 'role' not in input_data or not input_data['role']:
        return generate_response(message='role is required.')
    if input_data['role'] == ORGANIZATION_ROLE_TYPE:
        if 'organization_info' not in input_data or not input_data['organization_info']:
            return generate_response(message='organization_info is required.')
    if input_data['role'] == STORE_ROLE_TYPE:
        if 'store_info' not in input_data or not input_data['store_info']:
            return generate_response(message='store_info is required.')

    query = Q()
    if input_data['auth_type'] == PHONE_LOGIN_TYPE:
        query &= Q(phone=input_data['phone'])
    if input_data['auth_type'] == EMAIL_LOGIN_TYPE:
        query &= Q(email=input_data['email'].lower())
    user = UserLoginInfo.objects(query)
    if user:
        return generate_response(
            message='This user is already exist in our record with this phone or email, please login.'
        )
    organization_info = input_data.pop('organization_info') if 'organization_info' in input_data else {}
    store_info = input_data.pop('store_info') if 'store_info' in input_data else {}
    organization_id = input_data.pop('organization_id') if 'organization_id' in input_data else None
    name = input_data.pop('name') if 'name' in input_data else ''
    user = UserLoginInfo(**input_data)
    errors = user.clean(**input_data)
    if errors:
        return errors
    if user.email:
        user.email = user.email.lower()
    user.create_user(**input_data)
    if input_data['role'] == USER_ROLE_TYPE:
        create_user_profile(user, input_data, name)
    if input_data['role'] == ORGANIZATION_ROLE_TYPE:
        create_organization(user, organization_info)
    if input_data['role'] == STORE_ROLE_TYPE:
        create_store(user, store_info, organization_id)
    if input_data['role'] == AGENCY_USER_ROLE_TYPE:
        create_agency_user(user, input_data['parent'])
    if input_data['auth_type'] == PHONE_LOGIN_TYPE:
        create_otp(user.phone_code, user.phone)
    if input_data['auth_type'] == EMAIL_LOGIN_TYPE:
        send_verification_email(request, input_data, user)
    return generate_response(data=user.to_json(), message='User Created', status=HTTP_201_CREATED)


def login_user(request, input_data):
    if 'email_or_phone' not in input_data or not input_data['email_or_phone']:
        return generate_response(message='email_or_phone is missing or invalid.')
    if 'password' not in input_data or not input_data['password']:
        return generate_response(message='password is required.')
    try:
        # if input_data['auth_type'] == PHONE_LOGIN_TYPE:
        #     if 'phone' not in input_data or not input_data['phone']:
        #         return generate_response(message='phone is required')
        #     user = UserLoginInfo.objects.get(phone=input_data.get('phone').lower())
        # else:
        #     if 'email' not in input_data or not input_data['email']:
        #         return generate_response(message='email is required')
        #     user = UserLoginInfo.objects.get(email=input_data.get('email').lower())
        user = UserLoginInfo.objects.get(
            Q(email=input_data['email_or_phone'].lower()) | Q(phone=input_data['email_or_phone']))
    except:
        return generate_response(message='No record found with this email or phone, please signup first.')
    auth_success = user.check_pw_hash(input_data.get('password'))
    if not auth_success:
        return generate_response(message='Email or password you provided is invalid. please check it once',
                                 status=HTTP_401_UNAUTHORIZED)
    if not user.is_active:
        return generate_response(message='User is blocked by admin, Please contact admin.',
                                 status=HTTP_401_UNAUTHORIZED)
    if user.is_deleted:
        return generate_response(message='User has deleted their account previously, please contact admin.',
                                 status=HTTP_401_UNAUTHORIZED)
    if not user.is_verified:
        return generate_response(message='User is not verified his account, please check your email.',
                                 status=HTTP_401_UNAUTHORIZED)
    else:
        # access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
        # refresh_token = create_refresh_token(identity=str(user.id))

        access_token, refresh_token = get_refresh_access_token(request, user)
        return generate_response(data={'access_token': access_token,
                                       'refresh_token': refresh_token,
                                       'logged_in_as': f"{user.email}",
                                       'meta': user.to_json()
                                       }, status=HTTP_200_OK)


def social_login(request, input_data):
    new_user = False
    try:
        user = UserLoginInfo.objects.get(email=input_data['email'].lower())
    except:
        user = UserLoginInfo(**input_data)
        new_user = True
        # provider random default password
        user.password = str(random.randint(10000000, 99999999))
    errors = user.clean()
    if errors:
        return errors
    if 'social_id' not in input_data or not input_data['social_id']:
        return generate_response(message='Social id is missing or invalid.')

    user.email = input_data['email'].lower()
    user.role = input_data['role']
    user.auth_type = input_data['auth_type']
    user.social_id = input_data['social_id']
    user.is_active = True
    user.is_verified = True
    # if input_data['role'] == B2B_USER:
    #     user.parent = self.input_data['parent']
    user.save()

    access_token, refresh_token = get_refresh_access_token(request, user)
    return generate_response(data={'access_token': access_token,
                                   'refresh_token': refresh_token,
                                   'logged_in_as': f"{user.email}",
                                   'meta': user.to_json()
                                   }, status=HTTP_200_OK)


def update_user(input_data, user):
    if 'email' in input_data and input_data['email']:
        if UserLoginInfo.objects(email=input_data['email']):
            return generate_response(message='This email is already registered with us. please try another.')
        user.email = input_data['email']
    if 'phone' in input_data and input_data['phone']:
        if UserLoginInfo.objects(phone=input_data['phone']):
            return generate_response(message='This phone is already registered with us. please try another.')
        if 'phone_code' not in input_data or not input_data['phone_code']:
            return generate_response(message='Phone code is required')
        user.phone_code = input_data['phone_code']
        user.phone = input_data['phone']
    user_profile = UserProfileModel.objects(user=user.id).get()
    if 'profile_image' in input_data and input_data['profile_image']:
        user_profile.profile_image = input_data['profile_image']
    if 'name' in input_data and input_data['name']:
        user_profile.name = input_data['name']
    if 'intro' in input_data and input_data['intro']:
        user_profile.intro = input_data['intro']
    user.save()
    return generate_response(data=user.to_json(), message='User updated', status=HTTP_200_OK)


def update_organization(jwt_payload, input_data):
    user = UserLoginInfo.objects.get(id=jwt_payload['id'])
    organization = OrganizationModel.objects.get(user=jwt_payload['id'])
    if 'language' in input_data and input_data['language']:
        user.language = input_data['language']
    if 'is_deleted' in input_data and input_data['is_deleted']:
        user.is_deleted = input_data['is_deleted']
    if 'email' in input_data and input_data['email']:
        if UserLoginInfo.objects(email=input_data['email']):
            return generate_response(message='This email is already registered with us. please try another.')
        user.email = input_data['email']
    if 'phone' in input_data and input_data['phone']:
        if UserLoginInfo.objects(phone=input_data['phone']):
            return generate_response(message='This phone is already registered with us. please try another.')
        if 'phone_code' not in input_data or not input_data['phone_code']:
            return generate_response(message='Phone code is required')
        user.phone_code = input_data['phone_code']
        user.phone = input_data['phone']
    if 'title' in input_data and input_data['title']:
        organization.title = input_data['title']
    if 'intro' in input_data and input_data['intro']:
        organization.intro = input_data['intro']
    if 'domain' in input_data and input_data['domain']:
        organization.domain = input_data['domain']
    if 'latlong' in input_data and input_data['latlong']:
        organization.latlong = input_data['latlong']
    if 'theme' in input_data and input_data['theme']:
        organization.theme = input_data['theme']
    if 'logo' in input_data and input_data['logo']:
        organization.logo = input_data['logo']
    if 'images' in input_data and input_data['images']:
        embedded_images = list()
        for image in input_data['images']:
            if 'title' in image and 'url' in image:
                image_instance = Images()
                image_instance.title = image['title']
                image_instance.url = image['url']
                embedded_images.append(image_instance)
        organization.images = embedded_images
    if 'address' in input_data and input_data['address']:
        organization.address = input_data['address']
    if 'city' in input_data and input_data['city']:
        organization.city = input_data['city']
    if 'country' in input_data and input_data['country']:
        organization.country = input_data['country']
    if 'pin' in input_data and input_data['pin']:
        organization.pin = input_data['pin']
    if 'establish_date' in input_data and input_data['establish_date']:
        organization.establish_date = input_data['establish_date']
    user.save()
    organization.save()

    return generate_response(data=organization.to_json(), message='Organization updated', status=HTTP_200_OK)


def update_store(jwt_payload, input_data):
    user = UserLoginInfo.objects.get(id=jwt_payload['id'])
    store = StoreModel.objects.get(user=jwt_payload['id'])
    if 'language' in input_data and input_data['language']:
        user.language = input_data['language']
    if 'is_deleted' in input_data and input_data['is_deleted']:
        user.is_deleted = input_data['is_deleted']
    if 'email' in input_data and input_data['email']:
        if UserLoginInfo.objects(email=input_data['email']):
            return generate_response(message='This email is already registered with us. please try another.')
        user.email = input_data['email']
    if 'phone' in input_data and input_data['phone']:
        if UserLoginInfo.objects(phone=input_data['phone']):
            return generate_response(message='This phone is already registered with us. please try another.')
        if 'phone_code' not in input_data or not input_data['phone_code']:
            return generate_response(message='Phone code is required')
        user.phone_code = input_data['phone_code']
        user.phone = input_data['phone']
    if 'title' in input_data and input_data['title']:
        store.title = input_data['title']
    if 'intro' in input_data and input_data['intro']:
        store.intro = input_data['intro']
    if 'domain' in input_data and input_data['domain']:
        store.domain = input_data['domain']
    if 'latlong' in input_data and input_data['latlong']:
        store.latlong = input_data['latlong']
    if 'theme' in input_data and input_data['theme']:
        store.theme = input_data['theme']
    if 'logo' in input_data and input_data['logo']:
        store.logo = input_data['logo']
    if 'images' in input_data and input_data['images']:
        embedded_images = list()
        for image in input_data['images']:
            if 'title' in image and 'url' in image:
                image_instance = Images()
                image_instance.title = image['title']
                image_instance.url = image['url']
                embedded_images.append(image_instance)
        store.images = embedded_images
    if 'address' in input_data and input_data['address']:
        store.address = input_data['address']
    if 'city' in input_data and input_data['city']:
        store.city = input_data['city']
    if 'country' in input_data and input_data['country']:
        store.country = input_data['country']
    if 'pin' in input_data and input_data['pin']:
        store.pin = input_data['pin']
    if 'establish_date' in input_data and input_data['establish_date']:
        store.establish_date = input_data['establish_date']
    user.save()
    store.save()

    return generate_response(data=store.to_json(), message='Store updated', status=HTTP_200_OK)


def create_user_location(jwt_payload, input_data):
    location = UserLocationModel(user=jwt_payload['id'], **input_data)
    location.save()
    return generate_response(data=location.to_json(), message='Location created', status=HTTP_201_CREATED)


def update_user_location(input_data, location):
    if 'is_default_location' in input_data and input_data['is_default_location']:
        location.is_default_location = input_data['is_default_location']
    if 'offer_radius' in input_data and input_data['offer_radius']:
        location.offer_radius = input_data['offer_radius']
    if 'location_type' in input_data and input_data['location_type']:
        location.location_type = input_data['location_type']
    if 'other_location_title' in input_data and input_data['other_location_title']:
        location.other_location_title = input_data['other_location_title']
    if 'latlong' in input_data and input_data['latlong']:
        location.latlong = input_data['latlong']
    if 'address' in input_data and input_data['address']:
        location.address = input_data['address']
    if 'city' in input_data and input_data['city']:
        location.city = input_data['city']
    if 'country' in input_data and input_data['country']:
        location.country = input_data['country']
    if 'pin' in input_data and input_data['pin']:
        location.pin = input_data['pin']
    location.save()
    return generate_response(data=location.to_json(), message='Location updated', status=HTTP_200_OK)


def create_user_profile(user, input_data, name):
    user_profile = UserProfileModel(user=user,
                                    name=name,
                                    profile_summary=input_data[
                                        'profile_summary'] if 'profile_summary' in input_data else '',
                                    profile_image=input_data[
                                        'profile_image'] if 'profile_image' in input_data else 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png',
                                    )
    user_profile.save()


def create_organization(user, organization_data):
    organization = OrganizationModel(user=user, **organization_data)
    organization.save()


def create_store(user, store_data, organization_id):
    store = StoreModel(user=user, organization=organization_id, **store_data)
    store.save()


def create_agency_user(user, parent):
    user = UserLoginInfo.objects(id=user.id).get()
    user.parent = parent
    user.save()
