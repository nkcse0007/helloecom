import logging
import uuid

from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.http.response import Http404

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------------
# ManagerAccountVerification
# -------------------------------------------------------------------------------
class ManagerAccountVerification(models.Manager):
    """
    Provides manager methods for the verification model.
    """

    # ---------------------------------------------------------------------------
    # generate_verification
    # ---------------------------------------------------------------------------
    def generate_verification(self, user, verification_type=None):
        """
        This method is used to create a one time code for user verification
        after a new user's registration. and for a forgot password verification
        """

        if not verification_type:
            verification_type = self.model.VERIFICATION_TYPES[0][0]

        try:
            return \
                self.model.objects.get(user=user,
                                       type=verification_type)
        except ObjectDoesNotExist:
            expiration_date = ""
            return \
                self.model.objects.create(user=user,
                                          token=uuid.uuid4(),
                                          type=verification_type,
                                          expiration=expiration_date)

    # ---------------------------------------------------------------------------
    # send_verification_email
    # ---------------------------------------------------------------------------
    def send_verification_email(self, user, verification_type=None):
        """
        Method sends verification email to specified user.
        """

        verification = self.generate_verification(user, verification_type)

        if verification_type == 1:
            verification.send_user_forgot_password_email()
            return
        verification.send_verification_email()

    # ---------------------------------------------------------------------------
    # verify_user
    # ---------------------------------------------------------------------------
    def verify_email(self, token):
        """
        Gets the token and the user, sets their account's is_verified to true
        and their on boarding step count to 2.
        """

        try:
            verification = \
                self.model.objects.get(token=token,
                                       type=self.model.VERIFICATION_TYPES[0][0])
            verification.user.is_verified = True
            verification.user.save()
            verification.delete()

            return verification.user

        except ObjectDoesNotExist:
            raise Http404("This is not a valid verification")

    # ---------------------------------------------------------------------------
    # verify_password
    # ---------------------------------------------------------------------------
    def verify_password(self, token):
        """
        Gets the token and type of verification and then deletes the
        verification after it has been used once.
        """

        try:
            verification = \
                self.model.objects.get(token=token,
                                       type=self.model.VERIFICATION_TYPES[1][0])
            verification.delete()
            return verification.user

        except ObjectDoesNotExist:
            raise Http404("This is not a valid object")
