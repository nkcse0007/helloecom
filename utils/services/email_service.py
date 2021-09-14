import base64
from utils.common import account_activation_token
from multiprocessing import Process
from utils.constants import *

from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.core.mail import EmailMessage


def send_verification_email(request, input_data, user):
    current_site = request.url_root
    mail_subject = 'Common Dashboard: Verify your account'
    domain = current_site
    uid = user.id
    token = account_activation_token.encode_token(user)
    html = f"Please click on the link to confirm your registration, {domain}api/auth/verify-account/{uid}/{token.decode()}"
    mail = EmailMessage(
        mail_subject,
        html,
        to=[user.email]
    )
    mail.send()


def send_chat_notification(recipient_emails, message_body, sender_email):
    mail_subject = 'New message from ' + sender_email
    html = f'<h3>{message_body}</h3>'
    mail = EmailMessage(
        mail_subject,
        html,
        to=[recipient_emails]
    )
    mail.send()
