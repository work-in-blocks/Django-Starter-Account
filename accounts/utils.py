import random
import string
from accounts import models as accounts_models


def random_generator(email):
    """
        This method create with the email of user a username automatic in App

        :param email: email of user.
        :type email: string.
        :return: username.
    """
    random_number = str(random.randint(0, 999))
    if len(random_number) == 2:
        random_number = '0' + random_number
    if len(random_number) == 1:
        random_number = '00' + random_number
    username = email + '_' + random_number
    if not accounts_models.User.objects.filter(username=username).exists():
        return username
    return random_generator(email)


def code_generator(size=8, chars=string.ascii_uppercase + string.digits):
    """
       this method generates a string randomly

       :param size: size of string.
       :type size: integer.
       :param chars: sting with number and character
       :type chars: str.
       :return: random string.
    """
    return ''.join(random.choice(chars) for _ in range(size))
