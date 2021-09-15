# flask packages
from myapps.authentication.services import create_user, update_user, update_organization, update_user_location, \
    create_user_location, update_store, login_user, social_login
from myapps.authentication.selectors import get_user_profile, get_organization_profile, \
    get_user_location, get_store_profile
from rest_framework.response import Response
from django.http.response import HttpResponse
from utils.common import generate_response
from myapps.models import UserLoginInfo, OrganizationModel, StoreModel, UserLocationModel
from utils.http_code import *
from utils.common import account_activation_token
from utils.common import get_user_from_token, get_input_data
from utils.jwt.jwt_security import authenticate_login
from utils.services.twilio_otp import create_otp, verify_otp
from rest_framework.views import APIView


class SignUpApi(APIView):

    @staticmethod
    def post(request) -> Response:
        """
        POST response method for creating user.

        :return: JSON object
        """
        input_data = get_input_data(request)
        response = create_user(request, input_data)
        return Response(response)


class EmailLoginApi(APIView):

    @staticmethod
    def post(request) -> Response:
        """
        POST response method for retrieving user web token.

        :return: JSON object
        """
        input_data = get_input_data(request)
        response = login_user(request, input_data)
        return Response(response)


class SocialLoginApi(APIView):

    @staticmethod
    def post(request) -> Response:
        """
        POST response method for retrieving user web token.

        :return: JSON object
        """
        input_data = get_input_data(request)
        response = social_login(request, input_data)
        return Response(response)


class VerifyEmailApi(APIView):

    @staticmethod
    def get(request, uid, token):
        try:
            user = UserLoginInfo.objects.get(id=uid)
        except:
            user = None
        if user is not None and account_activation_token.check_token(token):
            if user.is_verified:
                return HttpResponse('Account already verified.')
            user.is_verified = True
            user.save()

            return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
        else:
            return HttpResponse('Activation link is invalid!')


class GetOtpApi(APIView):
    @staticmethod
    def post(request) -> Response:
        input_data = get_input_data(request)
        if 'phone' not in input_data or not input_data['phone']:
            return Response(generate_response(message='phone is required.'))
        try:
            user = UserLoginInfo.objects(phone=input_data['phone']).get(request)
        except:
            return Response(generate_response(message='No record found with this phone. please signup first.'))
        otp = create_otp(user.phone_code, user.phone)
        return Response(generate_response(message='Otp sent to the registered mobile number.', status=HTTP_200_OK))


class VerifyOtpApi(APIView):
    @staticmethod
    def post(request) -> Response:
        input_data = get_input_data(request)
        if 'phone' not in input_data or not input_data['phone']:
            return Response(generate_response(message='phone is required.'))
        if 'otp' not in input_data or not input_data['otp']:
            return Response(generate_response(message='otp is required.'))
        try:
            user = UserLoginInfo.objects(phone=input_data['phone']).get(request)
        except:
            return Response(generate_response(message='User not found with this phone. please signup first.'))
        if user.is_verified:
            return Response(generate_response(message='Otp is already verified.', status=HTTP_200_OK))
        if verify_otp(user.phone_code, user.phone, input_data['otp']):
            user.is_verified = True
            user.save()
            return Response(generate_response(message='Otp successfully verified.', status=HTTP_200_OK))
        else:
            return Response(generate_response(message='Invalid Otp'))


class UserProfileApi(APIView):
    @staticmethod
    @authenticate_login
    def get(request) -> Response:
        jwt_payload = get_user_from_token(request)
        response = get_user_profile(jwt_payload)
        return Response(response)

    @staticmethod
    @authenticate_login
    def delete(request) -> Response:
        jwt_payload = get_user_from_token(request)
        user = UserLoginInfo.objects.get(id=jwt_payload['id'])
        user.is_deleted = True
        user.save()
        return Response(
            generate_response(data=user.id, message='User deleted.', status=HTTP_404_NOT_FOUND))

    @staticmethod
    @authenticate_login
    def put(request) -> Response:
        input_data = get_input_data(request)
        jwt_payload = get_user_from_token(request)
        user = UserLoginInfo.objects.get(id=jwt_payload['id'])
        response = update_user(input_data, user)
        return Response(response)


class OrganizationApi(APIView):

    @staticmethod
    @authenticate_login
    def get(request) -> Response:
        jwt_payload = get_user_from_token(request)
        response = get_organization_profile(jwt_payload)
        return Response(response)

    @staticmethod
    @authenticate_login
    def delete(request) -> Response:
        jwt_payload = get_user_from_token(request)
        instance = OrganizationModel.objects.get(id=jwt_payload['id'])
        instance.delete(request)
        instance.save()
        return Response(
            generate_response(message='Organization deleted.', status=HTTP_200_OK))

    @staticmethod
    @authenticate_login
    def put(request) -> Response:
        input_data = get_input_data(request)
        jwt_payload = get_user_from_token(request)
        response = update_organization(jwt_payload, input_data)
        return Response(response)


class StoreApi(APIView):

    @staticmethod
    @authenticate_login
    def get(request) -> Response:
        jwt_payload = get_user_from_token(request)
        response = get_store_profile(jwt_payload)
        return Response(response)

    @staticmethod
    @authenticate_login
    def delete(request) -> Response:
        jwt_payload = get_user_from_token(request)
        instance = StoreModel.objects.get(id=jwt_payload['id'])
        instance.delete(request)
        instance.save()
        return Response(
            generate_response(message='Store deleted.', status=HTTP_200_OK))

    @staticmethod
    @authenticate_login
    def put(request) -> Response:
        input_data = get_input_data(request)
        jwt_payload = get_user_from_token(request)
        response = update_store(jwt_payload, input_data)
        return Response(response)


class UserLocationApi(APIView):

    @staticmethod
    @authenticate_login
    def get(request) -> Response:
        jwt_payload = get_user_from_token(request)
        input_data = get_input_data(request)
        response = get_user_location(jwt_payload, input_data)
        return Response(response)

    @staticmethod
    def post(request) -> Response:
        input_data = get_input_data(request)
        jwt_payload = get_user_from_token(request)
        response = create_user_location(jwt_payload, input_data)
        return Response(response)

    @staticmethod
    @authenticate_login
    def put(request) -> Response:
        input_data = get_input_data(request)
        location = UserLocationModel.objects.get(id=input_data['id'])
        response = update_user_location(input_data, location)
        return Response(response)

    @staticmethod
    @authenticate_login
    def delete(request) -> Response:
        input_data = get_input_data(request)
        location = UserLocationModel.objects.get(id=input_data['id'])
        location.is_deleted = True
        location.save()
        return Response(
            generate_response(data=location.id, message='Location deleted.', status=HTTP_404_NOT_FOUND)
        )
