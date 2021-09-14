import re
import phonenumbers
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from django.utils.regex_helper import _lazy_re_compile
from rest_framework.status import *
from django.utils.translation import gettext_lazy as _


def minimum_length_char(value):
    if len(value) < 3:
        raise ValidationError(
            _('Value should be minimum 3 characters'),
            params={'value': value},
        )


def minimum_length_phone(value):
    if len(value) < 7:
        raise ValidationError(
            _('Value should be minimum 3 characters'),
            params={'value': value},
        )


def minimum(value):
    if len(value) < 1:
        raise ValidationError(
            _('Value should be minimum 1 characters'),
            params={'value': value},
        )


def check_email(value):

    if '+' in value:
        raise ValidationError(
            _('Special characters are not allowed in email'),
            params={'value': value},
        )

def is_valid_email(email):
    user_regex = _lazy_re_compile(
        r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*\Z"  # dot-atom
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"\Z)',  # quoted-string
        re.IGNORECASE)
    domain_regex = _lazy_re_compile(
        # max length for domain name labels is 63 characters per RFC 1034
        r'((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+)(?:[A-Z0-9-]{2,63}(?<!-))\Z',
        re.IGNORECASE)
    literal_regex = _lazy_re_compile(
        # literal form, ipv4 or ipv6 address (SMTP 4.1.3)
        r'\[([A-f0-9:.]+)\]\Z',
        re.IGNORECASE)

    if not email or '@' not in email:
        return False
    user_part, domain_part = email.rsplit('@', 1)
    if not user_regex.match(user_part):
        return False

    if not validate_domain_part(domain_regex, literal_regex, domain_part):
        return False

    return True


def validate_domain_part(domain_regex, literal_regex, domain_part):
    if domain_regex.match(domain_part):
        return True

    literal_match = literal_regex.match(domain_part)
    if literal_match:
        ip_address = literal_match[1]
        try:
            validate_ipv46_address(ip_address)
            return True
        except ValidationError:
            pass
    return False


def is_valid_phone(phone, country_code):
    try:
        z = phonenumbers.parse(str(country_code) + str(phone), None)
    except Exception as e:
        return {'message': 'country code is required'}, False

    if phonenumbers.is_valid_number(z):
        return {'message': ''}, True
    else:
        return {'message': ''}, False


def is_fb_valid_phone(phone):
    if 15 > len(phone) > 9:
        try:
            hello = int(phone)
            return True
        except:
            return False
    else:
        return False


def validate_user(input_data):
    from authentication.serializers import UserLoginInfoSerializer, UserLoginInfoModel
    from utils.common import modify_slz_error
    _error_list = list()
    if not input_data:
        _error_list.append({"error": "Error! data is missing"})

    if input_data:
        slz = UserLoginInfoSerializer(data=input_data)
        if not slz.is_valid():
            return {'message': modify_slz_error(slz.errors), 'data': {}, 'status': False}, HTTP_400_BAD_REQUEST
        input_data['email'] = input_data['email'].lower()
        if UserLoginInfoModel.objects.filter(email=input_data['email']).exists():
            _error_list.append({"error": f"{input_data['email']} email already exist."})
        else:
            pass

        if len(_error_list) <= 0:
            return {'message': _error_list, 'data': {}, 'status': False}, HTTP_200_OK


def validate_user_login(input_data):
    _error_list = list()
    if not input_data:
        _error_list.append({"error": "data is missing"})
    if input_data:
        if "email" not in input_data or input_data['email'] == '':
            _error_list.append({"error": "Email, field is required"})
        if "password" not in input_data or input_data['password'] == '':
            _error_list.append({"error": "Password, field is required"})
        if 'email' in input_data and not is_valid_email(input_data["email"]):
            _error_list.append({"error": "Email, invalid email."})
        if len(_error_list) <= 0:
            return {'message': _error_list, 'data': {}, 'status': False}, HTTP_200_OK

    return {'message': _error_list, 'data': {}, 'status': False}, HTTP_400_BAD_REQUEST


def validate_new_password(data):
    _error_list = list()
    if not data:
        _error_list.append({"error": "data is missing"})

    if data:
        if "uid" not in data:
            _error_list.append({"error": "uid, field is required"})
        if "token" not in data:
            _error_list.append({"error": "token, field is required"})

        if 'uid' in data and data['uid'] == '':
            _error_list.append({"error": "uid, Not to be empty"})

        if "new_password" not in data:
            _error_list.append({"error": "password, field is required"})

        if 'new_password' in data and data['uid'] == '':
            _error_list.append({"error": "password, Not to be empty"})

        if 'token' in data and data['uid'] == '':
            _error_list.append({"error": "token, Not to be empty"})

        if len(_error_list) <= 0:
            return {'message': _error_list, 'data': {}, 'status': True}, HTTP_200_OK

    return {'message': _error_list, 'data': {}, 'status': False}, HTTP_400_BAD_REQUEST
