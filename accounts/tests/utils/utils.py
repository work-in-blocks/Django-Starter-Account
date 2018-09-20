from django.utils.crypto import get_random_string
from rest_framework.test import APITestCase, APIRequestFactory
from accounts.models import User
from rest_framework.test import force_authenticate
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password


def create_user():
    user = {
        "username": "solrac5",
        "password": make_password("car123"),
        "first_name": "carlos",
        "last_name": "olviero",
        "email": "carlos5_zeta@hotmail.com",
        "age": "1992-08-02",
        "sex": "Men"
    }   
    return user
