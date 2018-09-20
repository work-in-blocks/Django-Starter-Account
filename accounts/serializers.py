import serpy
from django.contrib.auth.models import Permission
from accounts import models as accounts_models


class CountrySerializers(serpy.Serializer):
    """
        This class convert the country data into json.
    """
    id = serpy.Field()
    name = serpy.Field()
    code = serpy.Field()


class PhoneSerializers(serpy.Serializer):
    """
        This class convert the phone user data into json.
    """
    id = serpy.Field()
    number = serpy.Field()


class ProfileUserSerializers(serpy.Serializer):
    """
        This class convert user data into json
    """
    id = serpy.Field()
    first_name = serpy.Field()
    last_name = serpy.Field()
    email = serpy.Field()
    country = serpy.MethodField()
    direction = serpy.MethodField()
    age = serpy.Field()
    sex = serpy.Field()
    image = serpy.MethodField()
    phone = serpy.MethodField()

    def get_country(self, obj):
        """
            This method returns the country where the user is living.

            :param obj: country.
            :type obj: Model User.
            :return: if country is none return empty.
            :return: country of user.
        """
        if not obj.country:
            return ""
        return CountrySerializers(obj.country, many=False).data

    def get_image(self, obj):
        """
            This method return the image profile store in user account.

            :param obj: image.
            :type obj: Model User.
            :return: if image if none return empty.
            :return: image of user.
        """
        if not obj.image:
            return ""
        return str(obj.image.url)

    def get_phone(self, obj):
        """
            This method return the phone store in user account.

            :param obj: phone.
            :type obj: Model User.
            :return: if phone if none return empty.
            :return: phone of user.
        """
        phone = accounts_models.Phone.objects.filter(user_id=obj.id).order_by('-id')
        if not phone:
            return ""
        return PhoneSerializers(phone, many=True).data

    def get_direction(self, obj):
        """
            This method return the direction store in user account.

            :param obj: direction.
            :type obj: Model User.
            :return: if direction if none return empty.
            :return: direction of user.
        """
        if not obj.direction:
            return ""
        return obj.direction


class PermissionSerializers(serpy.Serializer):
    """
        This class convert the Permission model data into json.
    """
    id = serpy.Field()
    name = serpy.Field()
    codename = serpy.Field()


class GroupSerializers(serpy.Serializer):
    """
        This class convert the Group model data into json.
    """
    id = serpy.Field()
    name = serpy.Field()
    permission = serpy.MethodField()

    def get_permission(self, obj):
        """
            This method returns the permits that belongs to this group

            :param obj: group id.
            :type obj: Model Group.
            :return: if id is none return empty.
            :return: array with all permissions.
        """
        if not obj.id:
            return ""
        permission = Permission.objects.filter(group__id=obj.id).order_by('id')
        serializer = PermissionSerializers(permission, many=True).data
        return serializer
