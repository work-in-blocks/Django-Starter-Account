from django.conf import settings
from django.core.mail.message import EmailMultiAlternatives
from django.template.loader import render_to_string
from app import settings


class Notifications:
    """
        this class contain all method to send email for all notification on system.
    """

    def __init__(self, send_email=True, template=None):
        """
            initialize this class with template direction.

            :param send_email: True
            :type send_email: bool.
            :param template: direction of template.
            :type template: string.
        """
        self.template = template
        self.url_web = settings.URL

    def send_email(self, email_destinity, data):
        """
            this method get the data information and send a email with the template indicate.

            :param email_destinity: email to send information.
            :type email_destinity: string.
            :param data: user information.
            :type data: dict.
        """
        if self.template is None:
            raise ValueError("A template is needed to send an email")
        data["url"] = self.url_web
        subject = data.get('msg')
        to = email_destinity
        from_email = settings.EMAIL_HOST_USER
        template = self.template
        text_content = render_to_string(template, data)
        html_content = render_to_string(template, data)
        send = EmailMultiAlternatives(subject, text_content, from_email, [to],
                                      headers={'From': 'App <' + from_email + '>',
                                               'Reply-to': 'App <' + from_email + '>'})
        send.attach_alternative(html_content, "text/html")
        send.send()
