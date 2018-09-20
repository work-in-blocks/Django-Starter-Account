from accounts import models as accounts_models
from cerberus import Validator
from django.utils.translation import ugettext_lazy as _
from datetime import datetime
import re
import datetime as datetime_module


class RegisterValidator(Validator):
    """
        Validate class to register account.
    """

    schema = {
        'username': {'type': 'string', 'required': True, 'empty': False, 'minlength': 6, 'maxlength': 30},
        'first_name': {'type': 'string', 'required': True, 'empty': False, 'minlength': 3, 'maxlength': 30},
        'last_name': {'type': 'string', 'required': True, 'empty': False, 'minlength': 3, 'maxlength': 30},
        'email': {'type': 'string', 'required': True, 'empty': False, "mail": True},
        'phone': {'type': 'string', 'required': True, 'empty': False, 'maxlength': 16},
        'password': {'type': 'string', 'required': True, 'empty': False, 'minlength': 6, 'maxlength': 20},
        'age': {'type': 'string', 'required': True, 'empty': False, 'birthday': True},
        'sex': {'type': 'string', 'required': True, 'empty': False,
                'allowed': [i[0] for i in accounts_models.User.TYPE_SEX]},
    }

    def __init__(self, data, *args, **kwargs):
        """
            initialize cerberus with the user information to register in weedmatch.

            :param data: user information.
            :type data: dict.
        """
        super(RegisterValidator, self).__init__(*args, **kwargs)
        self.data = data
        self.schema = self.__class__.schema

    def validation(self):
        """
            :return: none if data is correct
        """
        return self.validate(self.data, self.schema)

    def _validate_mail(self, mail, field, value):
        """ Validate the user's email

        The rule's arguments are validated against this schema:
        {'type': 'boolean'}
        """
        if mail:
            if not re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', value):
                self._error(field, str(_("Please enter a valid email address")))
            elif len(value.split("@")[0]) >= 64:
                self._error(field, str(_("Invalid email")))
            elif len(value.split("@")[1].split(".")[0]) >= 255:
                self._error(field, str(_("Invalid email")))

    def _validate_birthday(self, birthday, field, date):
        """ Validate the user's birthday

        The rule's arguments are validated against this schema:
        {'type': 'boolean'}
        """
        if birthday:
            if not re.match(r'([12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))', date):
                self._error(field, str(_("The date you entered is not valid")))
            else:
                delta = datetime_module.date.today() - datetime.strptime(date, '%Y-%m-%d').date()
                if datetime_module.date.fromordinal(delta.days).year <= 18:
                    self._error(field, str(_("to register you must be 18 years old")))

    def change_value(self, data: list) -> list:
        """
            this method covers all cerberus error messages from English to Spanish,
            depends on the Accept-Language header.

            :param data: error messages of cerberus.
            :return: list with error messages.
        """
        for i in range(0, len(data)):
            if data[i][0:15] == "unallowed value":
                convert = str(data[i])
                data[i] = str(_(convert[0:15])) + convert[16:]
            else:
                convert = str(data[i])
                data[i] = str(_(convert))
        return data

    def mistakes(self):
        """
            This method returns the error when, the information sent by the user does not comply
            with the rules in the validation with cerberus

            :return: error of cerberus
        """
        return self.errors
