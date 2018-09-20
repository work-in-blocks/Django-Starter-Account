from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _


class Country(models.Model):
    """
        the model class to store country of earth.
    """
    name = models.CharField(_('Country name'), max_length=50, blank=False, null=False)
    code = models.CharField(_('Code'), max_length=2, blank=True, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class City(models.Model):
    """
        the model class to store the city belonging to a country.
    """
    country = models.ForeignKey('Country', related_name='country_city', on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(_('City name'), max_length=50, blank=False, null=False)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Phone(models.Model):
    """
        the model class store phone number
    """
    user = models.ForeignKey('User', related_name='user_phone', on_delete=models.CASCADE, null=True, blank=True)
    number = models.CharField(max_length=16, blank=True, null=True, unique=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.user.username


class User(AbstractUser):
    """
        the model class to store all user information.
    """
    SEX_MALE = "Men"
    SEX_FEMALE = "Woman"
    SEX_OTHER = "Other"
    TYPE_SEX = (
        (SEX_MALE, _('Men')),
        (SEX_FEMALE, _('Woman')),
        (SEX_OTHER, _("Other"))
    )
    country = models.ForeignKey('Country', related_name='country_user', on_delete=models.CASCADE, null=True, blank=True)
    recovery = models.CharField(_('Recovery'), max_length=15, blank=True)
    image = models.ImageField(_('image'), upload_to='profile', blank=True, null=True)
    direction = models.CharField(_('Direction'), max_length=255, blank=True, null=True)
    age = models.DateField(_('Age'), null=True, blank=True)
    sex = models.CharField(_('Type_sex'), max_length=10, choices=TYPE_SEX, default=SEX_OTHER, blank=True, null=True)
    facebook_id = models.CharField(max_length=140, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.username
