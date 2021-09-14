import logging

from django.contrib.auth.models import BaseUserManager
from utils.constants import SUPER_ADMIN_ROLE_TYPE

# from utils.validations import isValidPhone

logger = logging.getLogger(__name__)


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

        user = self.model(email=self.normalize_email(email), password=password, **kwargs)
        user.auth_type = "FORM"
        user.parent = parent_user if parent_user else ''
        user.is_verified = is_verified

        # update user password

        user.set_password(password)

        # add role
        user.role.append(role)

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