from __future__ import absolute_import, unicode_literals
from celery import shared_task
from accounts import models as accounts_models
from accounts import notifications as accounts_notifications
from accounts import utils
from app import settings
from twilio.rest import Client


@shared_task
def send_welcome_email(user: accounts_models.User):
    """
        function send welcome email to the user when the user registers

        :param user: Model User
        :return: True
    """
    notify = accounts_notifications.Notifications(send_email=True, template="email/welcome.html")
    data = {'username': user.username, 'msg': 'Welcome to App'}
    notify.send_email(email_destinity=user.email, data=data)
    return True


@shared_task
def send_recover_password_email(user: accounts_models.User):
    """
        function send email to user with code to recover your password

        :param user: Model User
        :return: True
    """
    notify = accounts_notifications.Notifications(send_email=True, template="email/password_recover.html")
    new_code = utils.code_generator(8)
    data = {'username': user.username, 'msg': 'Your new password', 'code': new_code}
    notify.send_email(email_destinity=user.email, data=data)
    user.recovery = new_code
    user.save()
    return True


@shared_task
def send_recover_password_phone(user: accounts_models.User):
    """
        function send message to user phone with code to recover your password

        :param user: Model User
        :return: True
    """
    new_code = utils.code_generator(8)
    account_sid = settings.TWILLIO_ACCOUNT_SID
    auth_token = settings.TWILLIO_AUTH_TOKEN
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        body="Hello {} use this code to recover your password {}".format(user.username, new_code),
        from_=settings.NUMBER_FROM_SEND,
        to=user.user_phone.all()[0].number
    )
    user.recovery = new_code
    user.save()
    print(message.sid)
    return True
