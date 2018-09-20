from rest_framework.test import APITestCase
from rest_framework.test import APIClient
from accounts import models as accounts_models
from accounts.tests.utils import utils


class TestLoginCase(APITestCase):

    def setUp(self):
        self.c = APIClient()
        self.data_user = utils.create_user()
        self.user = accounts_models.User.objects.create(**self.data_user)
    
    def tests_login_success(self):
        """
        """
        value = {"username": self.data_user.get('username'),
                 "password": "car123"}
        response = self.c.post('/accounts/signin/', value, format='json')
        self.assertEquals(response.status_code, 200, "error not equal")
        self.assertEquals(response.data.get('username'), value.get('username'), 'error not equal')
        print('\n')

    def tests_login_fail(self):
        """
            test username empty
        """
        value = {"username": "",
                 "password": "car123"}
        response = self.c.post('/accounts/signin/', value, format='json')
        self.assertEquals(response.status_code, 400, "error not equal")
        print('\n')

    def tests_login_fail1(self):
        """
            test password empty
        """
        value = {"username": self.data_user.get('username'),
                 "password": ""}
        response = self.c.post('/accounts/signin/', value, format='json')
        self.assertEquals(response.status_code, 400, "error not equal")
        print('\n')

    def tests_login_fail2(self):
        """
            test username inconrrect
        """
        value = {"username": "example",
                 "password": "car123"}
        response = self.c.post('/accounts/signin/', value, format='json')
        self.assertEquals(response.status_code, 400, "error not equal")
        print('\n')

    def tests_login_fail3(self):
        """
            test password inconrrect
        """
        value = {"username": self.data_user.get('username'),
                 "password": "car1233"}
        response = self.c.post('/accounts/signin/', value, format='json')
        self.assertEquals(response.status_code, 400, "error not equal")
        print('\n')
