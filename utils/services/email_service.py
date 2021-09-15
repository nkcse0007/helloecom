import base64
import os

from utils.common import account_activation_token
from multiprocessing import Process
from utils.constants import *

from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.core.mail import EmailMessage


def send_verification_email(request, input_data, user):
    # current_site = request.url_root
    mail_subject = 'HelloEcom: Verify your account'
    domain = os.environ.get('API_URL')
    uid = user.id
    token = account_activation_token.encode_token(user)
    html = f"Please click on the link to confirm your registration, {domain}/api/auth/verify-account/{uid}/{token.decode()}"
    mail = EmailMessage(
        mail_subject,
        html,
        to=[user.email]
    )
    mail.send()

