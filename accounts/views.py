from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import detail_route
from rest_framework.pagination import PageNumberPagination
from accounts import models as accounts_models
from accounts import serializers as accounts_serializers
from accounts import services as accounts_services
from accounts import tasks as accounts_tasks
from accounts import permissions as accounts_permissions
from django.utils.translation import gettext as _
from django.contrib.auth.models import Group, Permission
import json


class LoginView(APIView):
    """
       Get access to API with user information
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.LoginService()
        try:
            user = services.login(request.data)
        except Exception as e:
            info = json.loads(str(e))
            extract_dict = lambda x, y: {list(x)[0]: list(y)[0]}
            state = status.HTTP_400_BAD_REQUEST if info.get('status', None) is None else status.HTTP_401_UNAUTHORIZED
            return Response(extract_dict(info.keys(),info.values()), status=state)
        token, created = Token.objects.get_or_create(user=user)
        return Response({"username": user.username, "id": user.id, "token": token.key, "last_login": user.last_login},
                        status=status.HTTP_200_OK)


class LoginCaptchaView(APIView):
    """
        Get access to API with user information and captcha access token
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.LoginService()
        try:
            user = services.login_captcha(request.data)
        except Exception as e:
            info = json.loads(str(e))
            extract_dict = lambda x, y: {list(x)[0]: list(y)[0]}
            state = status.HTTP_400_BAD_REQUEST if info.get('status', None) is None else status.HTTP_401_UNAUTHORIZED
            return Response(extract_dict(info.keys(), info.values()), status=state)
        token, created = Token.objects.get_or_create(user=user)
        return Response({"username": user.username, "id": user.id, "token": token.key, "last_login": user.last_login},
                        status=status.HTTP_200_OK)


class LoginFacebookView(APIView):
    """
        Get access to API with facebook access token
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.LoginService()
        try:
            user = services.login_facebook(request.data)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        token, created = Token.objects.get_or_create(user=user)
        return Response({"username": user.username, "id": user.id, "token": token.key, "last_login": user.last_login},
                        status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
        Deletes the user's token in the system.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        services = accounts_services.LoginService()
        try:
            user = services.logout(request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        return Response({'detail': str(_('You have disconnected from the system'))}, status=status.HTTP_200_OK)


class RegisterView(APIView):
    """
        Register user in the API
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.RegisterService()
        try:
            user = services.register(request.data)
        except Exception as e:
            return Response({"detail": json.loads(str(e).replace("'", '"'))}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": str(_("The creation of your account has been successfully completed")),
                         "username": user.username}, status=status.HTTP_201_CREATED)


class PasswordRecoverEmailView(APIView):
    """
        Get code in user email to recover your password
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.PasswordRecoverService()
        try:
            user = services.password_recovery_email(request.data)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        if accounts_tasks.send_recover_password_email(user):
            return Response({'detail': str(_("The code has been sent successfully"))}, status=status.HTTP_200_OK)
        return Response({'detail': str(_("Server problems could not make the request"))},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordRecoverPhoneView(APIView):
    """
        Get code in user phone to recover your password
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.PasswordRecoverService()
        try:
            user = services.password_recovery_phone(request.data)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        if accounts_tasks.send_recover_password_phone(user):
            return Response({'detail': str(_("The code has been sent successfully"))}, status=status.HTTP_200_OK)
        return Response({'detail': str(_("Server problems could not make the request"))},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordRecoverView(APIView):
    """
        With the code that the user got in his email or phone, he can recover his password
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        services = accounts_services.PasswordRecoverService()
        try:
            user = services.password_recover(request.data)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        return Response({'detail': str(_("The password has been successfully changed"))}, status=status.HTTP_200_OK)


class ProfileViewSet(viewsets.ModelViewSet):
    """
        This main class for the complete management of the user profile.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = accounts_serializers.ProfileUserSerializers
    queryset = accounts_models.User.objects.all()

    def list(self, request, *args, **kwargs):
        services = accounts_services.ProfileUserServices()
        try:
            users = services.list(user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        paginator = PageNumberPagination()
        context = paginator.paginate_queryset(users, request)
        serializer = self.get_serializer(context, many=True).data
        return paginator.get_paginated_response(serializer)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class GroupViewSet(viewsets.ModelViewSet):
    """
        Crud where the admin user can create, view, edit, delete and assignment permission or delete them
        of groups django.
    """
    permission_classes = (permissions.IsAuthenticated, accounts_permissions.AdminUser)
    serializer_class = accounts_serializers.GroupSerializers
    queryset = Group.objects.all()

    def list(self, request, *args, **kwargs):
        services = accounts_services.GroupServices()
        try:
            groups = services.list(user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        paginator = PageNumberPagination()
        context = paginator.paginate_queryset(groups, request)
        serializer = self.get_serializer(context, many=True).data
        return paginator.get_paginated_response(serializer)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        services = accounts_services.GroupServices()
        try:
            group = services.create(request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(group, many=False).data
        serializer['detail'] = str(_("You have successfully added a group to admin server"))
        return Response(serializer, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        services = accounts_services.GroupServices()
        try:
            group = services.update(instance, request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(group, many=False).data
        serializer['detail'] = str(_("Your group information has been successfully edited"))
        return Response(serializer, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        services = accounts_services.GroupServices()
        try:
            group = services.destroy(instance, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status)
        return Response({"detail": str(_("Group has been successfully deleted"))},
                        status=status.HTTP_200_OK)

    @detail_route(methods=['PUT'], url_path='add-permission/(?P<permission_id>[0-9]+)',
                  permission_classes=(permissions.IsAuthenticated, accounts_permissions.AdminUser,))
    def add_permission(self, request, pk=None, permission_id=None):
        instance = self.get_object()
        services = accounts_services.GroupServices()
        try:
            group = services.add_permission(instance, permission_id, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(group, many=False).data
        serializer['detail'] = str(_("You have add new permission to selected group"))
        return Response(serializer, status=status.HTTP_200_OK)

    @detail_route(methods=['DELETE'], url_path='delete-permission/(?P<permission_id>[0-9]+)',
                  permission_classes=(permissions.IsAuthenticated, accounts_permissions.AdminUser,))
    def delete_permission(self, request, pk=None, permission_id=None):
        instance = self.get_object()
        services = accounts_services.GroupServices()
        try:
            group = services.delete_permission(instance, permission_id, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(group, many=False).data
        serializer['detail'] = str(_("You have delete permission to selected group"))
        return Response(serializer, status=status.HTTP_200_OK)


class PermissionViewSet(viewsets.ModelViewSet):
    """
        crud where the admin user can create, view, edit and delete permissions
    """
    permission_classes = (permissions.IsAuthenticated, accounts_permissions.AdminUser,)
    serializer_class = accounts_serializers.PermissionSerializers
    queryset = Permission.objects.all()

    def list(self, request, *args, **kwargs):
        services = accounts_services.PermissionServices()
        try:
            permission = services.list(user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        paginator = PageNumberPagination()
        context = paginator.paginate_queryset(permission, request)
        serializer = self.get_serializer(context, many=True).data
        return paginator.get_paginated_response(serializer)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        services = accounts_services.PermissionServices()
        try:
            permission = services.create(request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(permission, many=False).data
        serializer['detail'] = str(_("Permission have successfully added"))
        return Response(serializer, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        services = accounts_services.PermissionServices()
        try:
            permission = services.update(instance, request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(permission, many=False).data
        serializer['detail'] = str(_("Permission has been successfully edited"))
        return Response(serializer, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        services = accounts_services.PermissionServices()
        try:
            permission = services.destroy(instance, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status)
        return Response({"detail": str(_("Permission has been successfully deleted"))},
                        status=status.HTTP_200_OK)


class UserGroupView(APIView):
    """
        Assign or delete user into groups django
    """
    permission_classes = (permissions.IsAuthenticated, accounts_permissions.AdminUser,)

    def post(self, request):
        services = accounts_services.UserGroupServices()
        try:
            group = services.add_user_group(request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": str(_("You have add the user to group "))+"{}".format(group.name)},
                        status=status.HTTP_200_OK)

    def delete(self, request):
        services = accounts_services.UserGroupServices()
        try:
            group = services.delete_user_group(request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": str(_("You have remove the user the group ")) + "{}".format(group.name)},
                        status=status.HTTP_200_OK)


class UserPermissionView(APIView):
    """
       Assign or delete user permissions
    """
    permission_classes = (permissions.IsAuthenticated, accounts_permissions.AdminUser,)

    def post(self, request):
        services = accounts_services.UserPermissionServices()
        try:
            permission = services.add_user_permission(request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": str(_("You have added permission to the user"))}, status=status.HTTP_200_OK)

    def delete(self, request):
        services = accounts_services.UserPermissionServices()
        try:
            permission = services.delete_user_permission(request.data, user=request.user)
        except Exception as e:
            return Response(json.loads(str(e)), status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": str(_("You have remove the user the permission"))}, status=status.HTTP_200_OK)
