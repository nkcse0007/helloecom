from django.db import models
from django.contrib.auth import login
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from utils.constants import *
from utils.validations import *
from django.contrib.postgres.fields import ArrayField
from myapps.authentication.managers.user import ManagerAccountUser
import uuid
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField

from utils.db.base_model import AbstractBaseModel

from utils.common import generate_response
from utils.constants import *
from utils.db.base_model import AbstractBaseModel
import phonenumbers
from location_field.models.plain import PlainLocationField
import re


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


class PermissionsModel(AbstractBaseModel):
    """
    Model: PermissionsModel
    Description: Create PermissionsModel
    Fields:
        title: title of the permission
    """
    title = models.CharField(max_length=20, null=False, blank=False)
    role = models.CharField(max_length=15, choices=ROLE_TYPE, blank=False, null=False,
                            help_text='Type of role.')

    def __str__(self):
        return self.title


class LanguageModel(AbstractBaseModel):
    title = models.CharField(max_length=20, default='English')
    code = models.CharField(max_length=5, default='en')

    def __str__(self):
        return self.title


class UserLoginInfo(AbstractBaseUser, PermissionsMixin, AbstractBaseModel):
    auth_type = models.CharField(max_length=15, choices=LOGIN_TYPE, blank=False, null=False,
                                 help_text='Type of authentication.')
    parent = models.TextField(blank=True, default='')  # For Aggregators
    role = models.CharField(max_length=15, choices=ROLE_TYPE, blank=False, null=False,
                            help_text='Type of role.')
    email = models.EmailField(unique=True, null=True)
    password = models.TextField(blank=False, null=False)
    phone = models.CharField(max_length=10, default='', blank=True)
    phone_code = models.CharField(max_length=14, default='', blank=True)
    social_id = models.CharField(max_length=50, blank=True, null=True, default='')
    permissions = models.ManyToManyField(to=PermissionsModel, blank=True, help_text='Permission of user')
    language = models.ManyToManyField(to=LanguageModel, blank=True, help_text='Language of user')
    is_verified = models.BooleanField(default=False, help_text="Toggles verification status for a user.")
    is_deleted = models.BooleanField(default=False, help_text="Toggles soft delete status for a user.")
    is_active = models.BooleanField(default=True, help_text="Toggles active status for a user.")

    is_staff = models.BooleanField(default=False,
                                   help_text="Designates the user as "
                                             "a staff member.")

    is_superuser = models.BooleanField(default=False,
                                       help_text="Designates the user as"
                                                 " a super user.")

    objects = ManagerAccountUser()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # def generate_pw_hash(self):
    #     self.password = generate_password_hash(password=self.password).decode('utf-8')
    #     return self.password
    #
    # def check_pw_hash(self, password: str) -> bool:
    #     return check_password_hash(pw_hash=self.password, password=password)

    # Use documentation from BCrypt for password hashing
    # check_pw_hash.__doc__ = check_password_hash.__doc__

    def clean(self, *args, **kwargs):
        if self.auth_type == EMAIL_LOGIN_TYPE:
            if not self.email or not type(self.email) == str or not validate_email(self.email):
                return generate_response(message='Email is missing or invalid.')
        if self.auth_type == PHONE_LOGIN_TYPE:
            if not self.phone or not type(self.phone) == str or not validate_phone(self.phone_code + self.phone):
                return generate_response(message='Phone is missing or invalid.')
        if not self.password or not type(self.password) == str or not len(self.password) > 6:
            return generate_response(message='Password is missing or invalid. password should be minimum 6 characters.')
        if not self.role or not type(self.role) == str or self.role not in ROLE_TYPE:
            return generate_response(message='Password is missing or invalid.')
        if not self.auth_type or not type(self.auth_type) == str or self.auth_type not in LOGIN_TYPE:
            return generate_response(message='Auth type is missing or invalid.')
        if self.role == AGENCY_USER_ROLE_TYPE:
            if not self.parent:
                return generate_response(message='Parent id is required.')
        return None

    # -------------------------------------------------------------------------
    # Meta
    # -------------------------------------------------------------------------
    class Meta:
        db_table = "user_login_info_model"
        verbose_name = "User"
        verbose_name_plural = "User Login Information"

    def __str__(self):
        """
        Returns the string representation of the      object.
        """
        return str(self.email)

    def auto_login(self, request):
        """
        A shortcut to auto login in a user, without using the user's password.
        """

        self.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, self)

    @property
    def get_name(self):
        return self.email


class OrganizationModel(AbstractBaseModel):
    user = models.OneToOneField(UserLoginInfo, on_delete=models.CASCADE)
    title = models.CharField(max_length=30, blank=False)
    intro = models.TextField(default='', blank=True)
    domain = models.URLField(blank=True)
    latlong = PlainLocationField(blank=True)
    theme = models.CharField(max_length=30, default='', blank=True)
    logo = models.URLField(blank=True)
    images = ArrayField(models.JSONField(blank=True, null=True), blank=True, null=True, default=list)
    address = models.CharField(max_length=30, default='', blank=True)
    city = models.CharField(max_length=30, default='', blank=True)
    country = models.CharField(max_length=30, default='', blank=True)
    pin = models.CharField(max_length=30, default='', blank=True)
    establish_date = models.DateTimeField(blank=True)

    def __str__(self):
        return str(self.title)

    class Meta:
        """
        Meta fields
        """
        db_table = "organization_model"
        verbose_name = "Organization Info"
        verbose_name_plural = "Organization Information"


class StoreModel(AbstractBaseModel):
    user = models.OneToOneField(UserLoginInfo, blank=False, on_delete=models.CASCADE)
    organization = models.ForeignKey(OrganizationModel, on_delete=models.SET_NULL, blank=True, null=True)
    title = models.CharField(max_length=30, blank=False)
    intro = models.CharField(max_length=30, default='', blank=True)
    domain = models.URLField(blank=True)
    latlong = PlainLocationField(blank=True)
    theme = models.CharField(max_length=30, default='', blank=True)
    logo = models.URLField(blank=True)
    images = ArrayField(models.JSONField(blank=True, null=True), blank=True, null=True, default=list)
    address = models.CharField(max_length=30, default='', blank=True)
    city = models.CharField(max_length=30, default='', blank=True)
    country = models.CharField(max_length=30, default='', blank=True)
    pin = models.CharField(max_length=30, default='', blank=True)
    establish_date = models.DateTimeField(blank=True)

    def __str__(self):
        return str(self.title)

    class Meta:
        """
        Meta fields
        """
        db_table = "store_model"
        verbose_name = "Store_Info"
        verbose_name_plural = "Store Information"


class UserProfileModel(AbstractBaseModel):
    user = models.OneToOneField(UserLoginInfo, blank=False, on_delete=models.CASCADE)
    name = models.CharField(max_length=30, blank=False)
    profile_summary = models.CharField(max_length=30, default='', blank=True)
    profile_image = models.URLField(default='', blank=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        """
        Meta fields
        """
        db_table = "user_model"
        verbose_name = "User Info"
        verbose_name_plural = "User Information"


class UserLocationModel(AbstractBaseModel):
    user = models.ForeignKey(UserLoginInfo, blank=False, on_delete=models.CASCADE)
    is_default_location = models.BooleanField(default=False)
    offer_radius = models.IntegerField(default=3)
    location_type = models.CharField(max_length=30, choices=LOCATION_TYPES, default=DEFAULT_LOCATION_TYPE, blank=False)
    other_location_title = models.CharField(max_length=30, default='', blank=True)
    latlong = PlainLocationField(blank=True)
    address = models.CharField(max_length=30, default='', blank=True)
    city = models.CharField(max_length=30, default='', blank=True)
    country = models.CharField(max_length=30, default='', blank=True)
    pin = models.CharField(max_length=30, default='', blank=True)

    def __str__(self):
        return str(self.user)

    class Meta:
        """
        Meta fields
        """
        db_table = "location_model"
        verbose_name = "User Location"
        verbose_name_plural = "User Locations"
