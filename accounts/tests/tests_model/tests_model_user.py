from rest_framework.test import APITestCase
from rest_framework.test import APIClient
from accounts.models import User
from accounts.tests.utils import utils


class TestModelUser(APITestCase):

    def setUp(self):
        self.user_data = utils.create_user() 

    def tests_create_user(self):
        """
            test of model creation the user
        """
        user = User.objects.create(**self.user_data)
        get_user = User.objects.get(id=user.id)            
        self.assertEqual(get_user.username, user.username, "error not the same")