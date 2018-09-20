from django.contrib import admin
from accounts import models as accounts_models
from django.contrib.auth.admin import UserAdmin as UserAdminProfile


class UserAdmin(UserAdminProfile):
    """
        register the information of the fields of the user account in django admin.
    """
    class Meta:
        model = accounts_models.User
        ordering = ('id',)
    fieldsets = (
        (None, {'fields':
                    ('username', 'first_name', 'last_name', 'email', 'password', 'recovery', 'country', 'direction',
                     'age', 'sex', 'image', 'facebook_id')
                }),
        (('Permissions'), {'fields':
                               ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
                           }),
    )
    list_display = ('id', 'username', 'email', 'country','created',)
    search_fields = ('username', 'first_name', 'last_name', 'email',)

    def get_ordering(self, request):
        return ['id']


class CountryAdmin(admin.ModelAdmin):
    """
        register the information of the fields of country in django admin.
    """
    list_display = ('id', 'name', 'code')
    search_fields = ('name', 'code',)

    def get_ordering(self, request):
        return ['id']


class CityAdmin(admin.ModelAdmin):
    """
        register the information of the fields of city in django admin.
    """
    list_display = ('id', 'country', 'name',)
    search_fields = ('name',)
    list_filter = ('country',)

    def get_ordering(self, request):
        return ['id']


class PhoneAdmin(admin.ModelAdmin):
    """
        register the information of the fields of city in django admin.
    """
    list_display = ('id', 'user', 'number',)

    def get_ordering(self, request):
        return ['id']


admin.site.register(accounts_models.User, UserAdmin)
admin.site.register(accounts_models.Country, CountryAdmin)
admin.site.register(accounts_models.City, CityAdmin)
admin.site.register(accounts_models.Phone, PhoneAdmin)
