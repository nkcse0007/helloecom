import logging
from django.contrib.auth.models import BaseUserManager
from utils.constants import *
from utils.validations import *
# from utils.validations import isValidPhone
from utils.common import generate_response

logger = logging.getLogger(__name__)


def validate_phone(value):
    print(value)
    try:
        phonenumbers.parse(value)
        return True
    except ValidationError:
        return False


def validate_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.match(regex, email):
        return True

    else:
        return False


# -------------------------------------------------------------------------------
# ManagerAccountUser
# -------------------------------------------------------------------------------
class ManagerAccountUser(BaseUserManager):
    """
    Provides manager methods for the user model.
    """

    # ---------------------------------------------------------------------------
    # create_user
    # ---------------------------------------------------------------------------
    def create_user(self, email=None, password=None, role=None, parent_user=None, permissions=None, is_verified=False,
                    input_data=None,
                    **kwargs):
        """
        This method creates a new user and its associated profile(empty)
        that can be updated whenever required.
        """
        if email is None:
            raise ValueError('Users must have a email')

        user = self.model(email=self.normalize_email(email), password=password)

        user.phone_code = input_data['phone_code'] if 'phone_code' in input_data and input_data['phone_code'] else ''
        user.phone = input_data['phone'] if 'phone' in input_data and input_data['phone'] else ''
        # user.email = input_data['email'] if 'email' in input_data and input_data['email'] else ''
        user.auth_type = input_data['auth_type']
        user.role = role
        try:
            from myapps.authentication.models import LanguageModel
            language = LanguageModel.objects.get(code='en')
            user.language = language
        except:
            pass

        # update user password

        user.set_password(password)

        # save the new user
        user.save(using=self._db)

        return user

    # ---------------------------------------------------------------------------
    # create_superuser
    # ---------------------------------------------------------------------------
    def create_superuser(self, email, password):
        """
        This method creates a superuser for the system.
        
        It takes following arguments:
        1) email - email of superuser (required)
        2) password - strong password of superuser (required)
        3) is_active - set to true
        """

        logger.info('Creating superuser with email %s', email)

        user = self.create_user(email=email,
                                password=password,
                                role=SUPER_ADMIN_ROLE_TYPE,
                                parent_user=None,
                                permissions=None,
                                is_verified=True,
                                is_staff=True,
                                is_superuser=True,
                                is_active=True
                                )

        logger.info('Superuser %s successfully created!', user)

        return user

    def clean(self, *args, **kwargs):
        if kwargs['auth_type'] == EMAIL_LOGIN_TYPE:
            if not kwargs['email'] or not type(kwargs['email']) == str or not validate_email(kwargs['email']):
                return generate_response(message='Email is missing or invalid.')
        if kwargs['auth_type'] == PHONE_LOGIN_TYPE:
            if not kwargs['phone'] or not type(kwargs['phone']) == str or not validate_phone(
                    kwargs['phone_code'] + kwargs['phone']):
                return generate_response(message='Phone is missing or invalid.')
        if not kwargs['password'] or not type(kwargs['password']) == str or not len(kwargs['password']) > 6:
            return generate_response(message='Password is missing or invalid. password should be minimum 6 characters.')
        if not kwargs['role'] or not type(kwargs['role']) == str or kwargs['role'] not in ROLE_TYPE_LIST:
            return generate_response(message='role is missing or invalid.')
        if not kwargs['auth_type'] or not type(kwargs['auth_type']) == str or kwargs[
            'auth_type'] not in LOGIN_TYPE_LIST:
            return generate_response(message='Auth type is missing or invalid.')
        if kwargs['role'] == AGENCY_USER_ROLE_TYPE:
            if not kwargs['parent']:
                return generate_response(message='Parent id is required.')
        return None
