from rest_framework.test import APITestCase
from rest_framework.test import APIClient
from django.contrib.auth.hashers import make_password
from accounts import models as accounts_models

data = {
    "username": "soulrac",
    "first_name": "carlos",
    "last_name": "olivero",
    "email": "carlos5_zeta@hotmail.com",
    "password": "1234qwer",
    "direction": "18 de octubre",
    "age": "1992-02-08",
    "sex": "Hombre"
}

class LoginTestCase(APITestCase):
    
    def setUp(self):
        country = accounts_models.Country.objects.create(name='Venezuela', code='VE') 
        self.c = APIClient()
        user = accounts_models.User.objects.create(
            username=data.get('username'),
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            email=data.get('email'),
            password=make_password(data.get('password')),
            direction=data.get('direction'),
            country_id=str(country.id),
            age=data.get('age'),
            sex=data.get('sex')
        )
        self.user = user

    