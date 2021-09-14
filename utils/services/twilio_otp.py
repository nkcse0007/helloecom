from twilio.rest import Client
import os
from utils.constants import *

client = Client(os.environ.get('TWILIO_SID'),
                os.environ.get('TWILIO_TOKEN'))
verify = client.verify.services(os.environ.get('VERIFY_SERVICE_ID'))


def create_otp(phone_code, phone):
    try:
        otp = verify.verifications.create(to=f'{phone_code}{phone}', channel='sms')
        return True
    except Exception as e:
        print(e)
        return False


def verify_otp(phone_code, phone, otp):
    try:
        result = verify.verification_checks.create(to=f'{phone_code}{phone}', code=otp)
        if result.status == 'approved':
            return True
    except:
        pass
    return False


def welcome_sms(user):
    try:
        message = client.messages.create(
            body=f'Hello, Thanks for registering with ticketbox. Your username is {user.username}. ',
            from_=os.environ.get('TWILIO_PHONE_NUMBER'),
            to=f'{user.phone_code}{user.phone}'
        )

        print(message.sid)
    except:
        pass
