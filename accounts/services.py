from accounts import models as accounts_models
from accounts import validations as accounts_validations
from accounts import tasks as accounts_task
from accounts import utils
from accounts.permissions import is_active_user
from django.contrib.auth.hashers import make_password
from django.db.models import Q
from app import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _
from django.core import files
import datetime as datetime_modules
import re
import logging
import requests
import json
import tempfile

# inicializate a logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class LoginService:
    """
        Main class service that contains methods that verify the user's information and give access to the api.
    """
    def login(self, data: dict) -> accounts_models.User:
        """
            Get access user into api.
            Raise exception if user or password are incorrect or user does not exist.

            :param data: username and password of user.
            :type: dict.
            :return: user.
            :raises: ValueError.
        """
        username = data.get("username", None)
        password = data.get("password", None)
        logger.info("Verify is user data is not empty or not exist")
        if username is None or not username:
            logger.error("OPEN:Error username is empty", exc_info=True)
            raise ValueError('{"detail":"'+str(_("The username cannot be empty"))+'"}')
        if password is None or not password:
            logger.error("OPEN:Error password is empty", exc_info=True)
            raise ValueError('{"detail":"'+str(_("The password cannot be empty"))+'"}')
        logger.info("OPEN:Verify is user data if correct to provide access into API")
        try:
            # Obtain user from database if exist
            user = accounts_models.User.objects.get(Q(username=username) | Q(email=username.lower()))
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN:Error in petition to login user %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"'+str(_("The username or password is incorrect"))+'"}')
        # Verify is user is active
        if not user.is_active:
            logger.error("OPEN:Error %s accounts is inactive" % user.username, exc_info=True)
            raise ValueError(
                '{"detail":"' + str(_("Account inactive, or your account is blocked")) + '","status":"401"}')
        # Verify if password match
        if not user.check_password(password):
            logger.error("OPEN:Error %s password doesnot match " % user.username, exc_info=True)
            raise ValueError('{"detail":"' + str(_("The username or password is incorrect")) + '"}')
        logger.debug('OPEN: %s login correctly into API' % user.username)
        user = authenticate(username=user.username, password=password)
        return user

    def login_captcha(self, data: dict)->accounts_models.User:
        """
            Get access user into api, verifying if this is not a robot.
            raise exception if user or password are incorrect or user does not exist.

            :param data: username, password and token captcha
            :type: dict.
            :return: user.
            :raises: ValueError.
        """
        logger.info("verify captcha")
        captcha = data.get('callback', None)
        if captcha is None or not captcha:
            raise ValueError('{"detail":"'+str(_("reCAPTCHA field cant not be empty"))+'"}')
        try:
            response = requests.post(
                settings.RECAPTCHA_CAPTCHA_URL,
                {'secret': settings.RECAPTCHA_PRIVATE_KEY, 'response': captcha}
            )
        except Exception as e:
            logger.error("OPEN:Error in petition, %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(e) + '"}')
        if not json.loads(response.content.decode())['success']:
            raise ValueError('{"detail":"'+str(_("Invalid reCAPTCHA. Please try again."))+'"}')
        logger.info("captcha has successfully passed")
        username = data.get("username", None)
        password = data.get("password", None)
        logger.info("Verify is user data is not empty or not exist")
        if username is None or not username:
            logger.error("OPEN:Error username is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("The username cannot be empty")) + '"}')
        if password is None:
            logger.error("OPEN:Error password is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("The password cannot be empty")) + '"}')
        logger.info("OPEN:Verify is user data if correct to provide access into API")
        try:
            # obtain user from database if exist
            user = accounts_models.User.objects.get(Q(username=username.lower()) | Q(email=username.lower()))
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN:Error in petition to login user %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("The username or password is incorrect")) + '"}')
        if not user.is_active:
            logger.error("OPEN:Error %s accounts is inactive" % user.username, exc_info=True)
            raise ValueError(
                '{"detail":"' + str(_("Account inactive, or your account is blocked")) + '","status":"401"}')
        if not user.check_password(password):
            logger.error("OPEN:Error %s password doesnot match " % user.username, exc_info=True)
            raise ValueError('{"detail":"' + str(_("The username or password is incorrect")) + '"}')
        logger.debug('OPEN: %s login correctly into API' % user.username)
        return user

    def login_facebook(self, data: dict) -> accounts_models.User:
        """
            Register and get access user into api with facebook information.
            Raises exception if facebook token access is incorrect.

            :param data: facebook access token
            :type: dict.
            :return: user.
            :raises: ValueError.
        """
        facebook_token_user = data.get('access_token', None)
        if facebook_token_user is None or not facebook_token_user:
            raise ValueError('{"detail":"' + str(_("The access_token field can not be empty")) + '"}')

        # Requests to Facebook API
        get_code_url = 'https://graph.facebook.com/oauth/client_code'
        access_token_url = 'https://graph.facebook.com/v3.1/oauth/access_token'
        graph_api_url = 'https://graph.facebook.com/v3.1/me?' \
                        'fields=id,name,email,picture.height(480).width(480),birthday,gender'
        params = {
            'client_id': settings.FACEBOOK_CLIENT_ID,
            'redirect_uri': "127.0.0.1",
            'client_secret': settings.FACEBOOK_SECRET,
            'access_token': facebook_token_user
        }
        r = requests.get(graph_api_url, params=params)
        if r.status_code == 400:
            raise ValueError('{"detail":"' + str(_("The access token does not belong to that user")) + '"}')
        # Data obtained by calling Facebook API with user token
        profile = json.loads(r.text)
        # verified if user exists
        user_register = accounts_models.User.objects.filter(facebook_id=profile.get('id'))
        if user_register.exists():
            return user_register[0]
        else:
            # verified id user exist with the same email
            band = True
            try:
                user_register = accounts_models.User.objects.get(email=profile.get('email'))
            except accounts_models.User.DoesNotExist:
                band = False
            if band:
                user_register.facebook_id = profile.get('id')
                user_register.save()
                return user_register
        # get username
        username = utils.random_generator(profile.get('email').split("@")[0])
        # validate_age
        age = profile.get('birthday')
        if not age:
            age = datetime_modules.date(2000, 1, 1).strftime('%Y-%m-%d')
        else:
            age = datetime_modules.datetime.strptime(age, "%m/%d/%Y").strftime("%Y-%m-%d")
        # validate_gender
        sex = profile.get('gender')
        if not sex:
            sex = accounts_models.User.SEX_OTHER
        else:
            if sex == 'male':
                sex = accounts_models.User.SEX_MALE
            elif sex == 'female':
                sex = accounts_models.User.SEX_FEMALE
            else:
                sex = accounts_models.User.SEX_OTHER
        # creation of user
        try:
            user = accounts_models.User.objects.create(
                username=username,
                password=make_password(utils.code_generator(10)),
                first_name=profile.get('name'),
                email=profile.get('email'),
                age=age,
                sex=sex,
                facebook_id=profile.get('id')
            )
        except Exception as e:
            raise ValueError('{"detail":"' + str(_("An error occurred while saving the user")) + '"}')
        # validate_image
        url = profile.get('picture').get('data').get('url')
        if url:
            img_data = requests.get(url).content
            if img_data:
                image_name = 'facebook_picture_' + utils.code_generator(10) + '.jpeg'
                # Create a temporary file
                temporal_file = tempfile.NamedTemporaryFile()
                temporal_file.write(img_data)
                # stored image
                user.image.save(image_name, files.File(temporal_file))
        # send email to user
        accounts_task.send_welcome_email(user)
        return user
    
    def login_likedin(self, data: dict) -> accounts_models.User:
        """

            :param data:
            :type: dict.
            :return:
        """
        return True
    
    def login_google(self, data: dict) -> accounts_models.User:
        """

            :param data:
            :type: dict.
            :return:
        """
        return True
    
    def login_github(self, data: dict) -> accounts_models.User:
        """

            :param data:
            :type: dict.
            :return:
        """
        return True

    @is_active_user
    def logout(self, user: accounts_models.User = None) -> accounts_models.User:
        """
            Remove token access to user into app.
            Raises exception if user is inactive.

            :param user: User into app
            :type: Model User.
            :return: User.
            :raises: ValueError.
        """
        if user is None or user.is_active is False:
            raise ValueError('{"detail":"' + str(_("A Valid and Active User must be provided")) + '"}')
        logger.info("add date to user when he has logout")
        user.last_login = datetime_modules.datetime.now()
        user.save()
        logger.info("remove token access to %s" % user.username)
        user.auth_token.delete()
        logger.debug("OPEN: %s has been logout to app correctly" % user.username)
        return user


class RegisterService:
    """
        Main class service have contain method to register a user in app
    """
    def register(self, data: dict)->accounts_models.User:
        """
            Obtain all information of user to then register in app.
            Raises an exception if the user's data is incorrect or the email with which the user
            registers exist in database.

            :param data: user information.
            :type: dict.
            :return: user.
            :raises: ValueError.
        """
        logger.info("Validate all data of user to complete registration")
        validator = accounts_validations.RegisterValidator(data)
        if validator.validation() is False:
            errors = validator.mistakes()
            for value in errors:
                errors[value] = validator.change_value(errors[value])
            logger.error("OPEN:Error in validation, for any of these fields %s" % errors, exc_info=True)
            raise ValueError(errors)
        # Verify is email exist in database
        if accounts_models.User.objects.filter(email=data.get('email').lower()).exists():
            logger.error("OPEN:Error in petition, exist a user with this email", exc_info=True)
            raise ValueError('{"email":"' + str(_("Mail exists, please enter another email")) + '"}')
        # verify if username exist in database
        if accounts_models.User.objects.filter(username=data.get('username').lower()).exists():
            logger.error("OPEN:Error in petition,username already exist", exc_info=True)
            raise ValueError('{"username":"' + str(_("Username exists, please enter another username")) + '"}')
        #remove phone of data
        phone_number = data.get('phone')
        del data['phone']
        logger.info("register user in app")
        data['email'] = data['email'].lower()
        # Encrypt password
        data['password'] = make_password(data['password'])
        try:
            # Save user in app
            user = accounts_models.User.objects.create(**data)
        except Exception as e:
            logger.error("OPEN:Error in creation, %s" % str(e), exc_info=True)
            raise ValueError('{"user":"' + str(_("An error occurred while saving the user")) + '"}')
        logger.info("create phone number to user")
        try:
            accounts_models.Phone.objects.create(
                user_id=user.id,
                number=phone_number
            )
        except Exception as e:
            logger.error("OPEN:Error in creation, %s" % str(e), exc_info=True)
            pass
        logger.info("send email to user")
        accounts_task.send_welcome_email(user)
        logger.debug("OPEN: user has been register correctly %s" % user.username)
        return user


class PasswordRecoverService:
    """
        Main class service to controlled the sending of code to recover password of user and verification he self.
    """
    def password_recovery_email(self, data: dict):
        """
            this method verifies that the email sent by the user exists in the database,
            raise a exception if the email does not exist

            :param data: user's email
            :type data: dict
            :return: Model User
            :raises: ValueError.
        """
        logger.info("Verify is email is not empty")
        email = data.get('email', None)
        if email is None or not email:
            logger.error("OPEN:Error, email is empty")
            raise ValueError('{"detail":"' + str(_("The email field can not be empty")) + '"}')
        logger.info("Find user with the email request")
        try:
            user = accounts_models.User.objects.get(email=email.lower())
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN: Error in petition, %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("The email is not registered in the system")) + '"}')
        # verify if user is active
        if user is None or user.is_active is False:
            logger.error("OPEN:Error user does not exist or is not inactive")
            raise ValueError('{"detail":"' +
                             str(_("In order to perform this operation, your account must be active")) + '"}')
        logger.debug("Verification of email is correct user: %s" % user.username)
        return user

    def password_recovery_phone(self, data: dict):
        """
            This method verifies that the phone number sent by the user exist in the database, raise a exception
            if the phone number does not exist

            :param data: username and phone number of user.
            :type: dict.
            :return: user
            :raises: ValueError.
        """
        logger.info("Verify data is not empty")
        username = data.get('username', None)
        phone_number = data.get('phone', None)
        if username is None or not username:
            logger.error("OPEN: Error username empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("The username cannot be empty")) + '"}')
        if phone_number is None or not phone_number:
            logger.error("OPEN: Error phone number empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("The phone number cannot be empty")) + '"}')
        try:
            #search user in database
            user = accounts_models.User.objects.get(Q(username=username) | Q(email=username.lower()))
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN: Error user not register or incorrect %s" % str(e), exc_info = True)
            raise ValueError('{"detail":"' + str(_("Username does not exist")) + '"}')
        # verify if user is active
        if user is None or user.is_active is False:
            logger.error("OPEN:Error user does not exist or is not inactive")
            raise ValueError('{"detail":"' +
                             str(_("In order to perform this operation, your account must be active")) + '"}')
        # verify if phone number of user, exist
        if user.user_phone.all()[0].number != phone_number:
            logger.error("OPEN: Error phone number %s does not belong to this user or does not exist" % phone_number,
                         exc_info=True)
            raise ValueError('{"detail":"' + str(_("Phone number incorrect")) + '"}')
        logger.debug("OPEN: verification of phone number correct")
        return user

    def password_recover(self, data: dict)->accounts_models.User:
        """
            this method obtain user code and password if code match with store in your account change your password,
            in another case raise exception the code does not belong to this user

            :param data: code and new password of user.
            :type: dict.
            :return: user
            :raises: ValueError.
        """
        logger.info("OPEN: verify is code ans password not empty")
        code = data.get('code', None)
        password = data.get('password', None)
        if code is None or not code:
            raise ValueError('{"detail":"' + str(_("The code cannot be empty")) + '"}')
        if password is None or not password:
            raise ValueError('{"detail":"' + str(_("The password cannot be empty")) + '"}')
        logger.info("find user with the code, which he has generated by email or phone")
        try:
            user = accounts_models.User.objects.get(recovery=code)
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN: Error in petition, %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' +
                             str(_("Code you sent does not match the one registered in your account")) + '"}')
        # verify if user is active
        if user is None or user.is_active is False:
            logger.error("OPEN:Error user does not exist or is not inactive")
            raise ValueError('{"detail":"' +
                             str(_("In order to perform this operation, your account must be active")) + '"}')
        # Changing password of user
        user.password = make_password(password)
        user.recovery = ''
        user.save()
        logger.debug("%s your password has been change successfully" % user.username)
        return user


class ProfileUserServices:
    """
        Main class service contain method to view, create, update and block a user into app
    """

    @is_active_user
    def list(self, user: accounts_models.User):
        """
            method to see all user register into app.

            :param user: user in app
            :type: Model user.
            :return: list of user.
        """
        logger.info("verify if the user who made the request is admin")
        if user.is_staff:
            users = accounts_models.User.objects.all().order_by('-id')
        else:
            users = accounts_models.User.objects.all().exclude(is_superuser=True).order_by('-id')
        return users


class GroupServices:
    """
        Main class service contain method to create, update, view, delete  groups into django,
        also to add and delete permission belong to group.
    """

    @is_active_user
    def list(self, user: accounts_models.User = None):
        """
            Get the list of group register into app.

            :param user: user admin of app.
            :type: Model User.
            :return: groups django.
        """
        logger.info("OPEN: get all groups with permission inside app")
        groups = Group.objects.all().order_by('-id')
        return groups

    @is_active_user
    def create(self, data: dict, user: accounts_models.User):
        """
            Create a group for app.
            raises exception if group name is empty or user try to create a group with the same name.

            :param data: group name
            :type: ditc.
            :param user: user admin of app.
            :type: Model User.
            :return: Group.
            :raises: ValueError.
        """
        logger.info("Verify the name of group does not empty")
        group_name = data.get('name', None)
        if group_name is None or not group_name:
            logger.error("OPEN: Error group name is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group name cannot be empty")) + '"}')
        # Verify is group exist into app
        if Group.objects.filter(name=group_name).exists():
            logger.error("OPEN: Error group mame exist %s" % group_name, exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group name exists try by another name")) + '"}')
        logger.info("Create new group into app")
        try:
            # Creation of group django
            group = Group.objects.create(name=group_name)
        except Exception as e:
            logger.error("", exc_info=True)
            raise ValueError('{"detail":"' + str(_("An error occurred while saving the group")) + '"}')
        logger.debug("OPEN: the creation of group %s is successfully" % group.name)
        return group

    @is_active_user
    def update(self, group: Group, data: dict, user: accounts_models.User):
        """
            Edited a group django.
            Raise an exception if the name of the group you are trying to edit is already ready.

            :param group: group to update.
            :type: Model Group.
            :param data: group name
            :type: ditc.
            :param user: user admin of app.
            :type: Model User.
            :return: Group.
            :raises: ValueError.
        """
        logger.info("Verify the name of group does not empty")
        group_name = data.get('name', None)
        if group_name is None or not group_name:
            logger.error("OPEN: Error group name is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group name cannot be empty")) + '"}')
        logger.info("Verify is group name exist and is not the same as it already exists")
        # Verify if group name already belongs to another group
        if not Group.objects.filter(name=group_name).exists():
            if not Group.objects.filter(name=group.name)[0].name == group_name:
                group.name = group_name
                group.save()
        else:
            logger.error("OPEN: Error the group name %s already belongs to another group" % group_name, exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group name exists try by another name")) + '"}')
        logger.debug("OPEN: group has been update successfully")
        return group

    @is_active_user
    def destroy(self, group: Group, user: accounts_models.User):
        """
            Delete group in django.

            :param group: group to update.
            :type: Model Group.
            :param user: user admin of app.
            :type: Model User.
            :return: True.
            :raises: ValueError.
        """
        group.delete()
        logger.debug("OPEN: Group has been delete successfully")
        return True

    @is_active_user
    def add_permission(self, group: Group, permission_id: str, user: accounts_models.User):
        """
            Add a new permission to the group selected.
            Raises exception if permission id does not exist.

            :param group: group to add the new permission.
            :type: Model Group.
            :param permission_id: id of permission to added
            :type: str.
            :param user: user admin of app.
            :type: Model User.
            :return: group.
            :raises: ValueError.
        """
        logger.info("Find permission in database")
        try:
            # Search if permission exist in database
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist as e:
            logger.error("OPEN: Error permission does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission does not exist")) + '"}')
        logger.info("Verify if the group already has this permission")
        list_permission = group.permissions.all()
        for info in list_permission:
            if info.id == permission.id:
                logger.error("OPEN: Error permission (%s) has already been add to this group" % permission.name,
                             exc_info=True)
                raise ValueError('{"detail":"' + str(_("Permission has already been added to this group")) + '"}')
        # add permission to the group selected
        group.permissions.add(permission)
        logger.debug("OPEN: The permission (%s) has been added to group successfully" % permission.name)
        return group

    @is_active_user
    def delete_permission(self, group: Group, permission_id: str, user: accounts_models.User):
        """
            Remove permission to the group selected.
            Raises exception if permission id does not exist.

            :param group: group to delete the permission.
            :type: Model Group.
            :param permission_id: id of permission to delete.
            :type: str.
            :param user: user admin of app.
            :type: Model User.
            :return: group.
            :raises: ValueError.
        """
        # Verify if the group not have any permission to delete
        list_permission = group.permissions.all()
        if len(list_permission) == 0:
            logger.error("OPEN: Error group %s don`t have any permission to delete" %group.name, exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group don`t have any permission to delete")) + '"}')
        logger.info("Find permission in database")
        try:
            # Search if permission exist in database
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist as e:
            logger.error("OPEN: Error permission does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission does not exist")) + '"}')
        # Verify if  the permission to delete inside in group selected
        band = False
        for info in list_permission:
            if info.id == permission.id:
                # Remove permission to the group selected
                group.permissions.remove(permission)
                logger.debug("OPEN: The permission (%s) has been remove successfully" % permission.name)
                return group
            else:
                band = True
        if band:
            logger.error("OPEN: Error The permission %s to delete does not exist inside the group" % permission.name)
            raise ValueError('{"detail":"' + str(_("The permission to delete does not exist inside the group")) + '"}')


class PermissionServices:
    """
        Main class service to contain method to create, view, update and destroy permission into django app
    """

    @is_active_user
    def list(self, user: accounts_models.User = None):
        """
            Get list of permission register in app.

            :param user: user admin.
            :type: Model User.
            :return: list of permission.
            :raises: ValueError.
        """
        # Get the list of permission in app
        permission = Permission.objects.all().order_by('-id')
        logger.debug("OPEN: obtain the list with all permission register")
        return permission

    @is_active_user
    def create(self, data: dict, user: accounts_models.User):
        """
            create a new permission to django app.
            raises exception if permission or code name is empty.

            :param data: permission and code name to add.
            :type: dict.
            :param user: user admin.
            :type: Model User.
            :return: permission.
            :raises: ValueError.
        """
        logger.info("Verify if permission name and code name not empty")
        permission_name = data.get('name', None)
        code_name = data.get('codename', None)
        if permission_name is None or not permission_name:
            logger.error("OPEN: Error permission name is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission name cannot be empty")) + '"}')
        if code_name is None or not code_name:
            logger.error("OPEN: Error code name is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Code name cannot be empty")) + '"}')
        #verify underscore
        if re.fullmatch(r'^[^_][a-zA-Z_]+[^_]', code_name):
            if code_name.find('_') == -1:
                logger.error("OPEN: code name must contain underscrore %s" % code_name, exc_info=True)
                raise ValueError('{"detail":"' + str(_('Code name must contain underscore')) + '"}')
        else:
            logger.error("OPEN: Error code name must not contain a underscore when starting and ending  %s"% code_name,
                         exc_info=True)
            raise ValueError('{"detail":"' +
                             str(_('Code name must not contain a underscore when starting and ending')) + '"}')
        # verify is permission name and code name exist in database
        # because all two are unique
        if Permission.objects.filter(name=permission_name).exists() or \
                Permission.objects.filter(codename=code_name).exists():
            logger.error("OPEN: Error permission or codename exist", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission name or code name exists try by another name")) + '"}')
        # Code to add permission to group
        content_type = ContentType.objects.get_for_model(accounts_models.User)
        try:
            permission = Permission.objects.create(name=permission_name, codename=code_name, content_type=content_type)
        except Exception as e:
            logger.error("OPEN: Error to try stored permission %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("An error occurred while saving permission")) + '"}')
        logger.debug("OPEN: Permission has been register successfully %s" % permission.name)
        return permission

    @is_active_user
    def update(self, permission: Permission, data: dict, user: accounts_models.User):
        """
            Update permission to django app.
            raises exception if permission or code name is empty.

            :param permission: permission and code name to update.
            :type: Model Permission.
            :param data: permission and code name to add.
            :type: dict.
            :param user: user admin.
            :type: Model User.
            :return: permission.
            :raises: ValueError.
        """
        logger.info("Verify if permission name and code name not empty")
        permission_name = data.get('name', None)
        code_name = data.get('codename', None)
        if permission_name is None or not permission_name:
            logger.error("OPEN: Error permission name is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission name cannot be empty")) + '"}')
        if code_name is None or not code_name:
            logger.error("OPEN: Error code name is empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Code name cannot be empty")) + '"}')
        # verify underscore
        if re.fullmatch(r'^[^_][a-zA-Z_]+[^_]', code_name):
            if code_name.find('_') == -1:
                logger.error("OPEN: code name must contain underscrore %s" % code_name, exc_info=True)
                raise ValueError('{"detail":"' + str(_('Code name must contain underscore')) + '"}')
        else:
            logger.error("OPEN: Error code name must not contain a underscore when starting and ending  %s" % code_name,
                         exc_info=True)
            raise ValueError('{"detail":"' +
                             str(_('Code name must not contain a underscore when starting and ending')) + '"}')
        # Update permission to group
        if not Permission.objects.filter(name=permission_name).exists() and \
                not Permission.objects.filter(codename=code_name).exists():
            if not Permission.objects.filter(name=permission.name)[0].name == permission_name:
                permission.name = permission_name
            if not Permission.objects.filter(codename=permission.codename)[0].codename == code_name:
                permission.codename = code_name
            permission.save()
        else:
            logger.error("OPEN: Error Permission name or code name exists", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission name or code name exists try by another name")) + '"}')
        logger.debug("OPEN: permission has been update successfully")
        return permission

    @is_active_user
    def destroy(self, permission: Permission, user: accounts_models.User):
        """
            Delete permission of django app.

            :param permission: permission and code name to update.
            :type: Model Permission.
            :param user: user admin.
            :type: Model User.
            :return: True.
            :raises: ValueError.
        """
        permission.delete()
        logger.debug("OPEN: Permission has been delete successfully")
        return True


class UserGroupServices:
    """
        Main class service to add and delete groups inside user in app
    """

    @is_active_user
    def add_user_group(self, data: dict, user: accounts_models.User):
        """
            Add group to user.
            raise exception if group or user does not exist and when adding the same group to the user

            :param data: group id and user id.
            :type: dict.
            :param user: user admin.
            :type: Model User.
            :return: group
            :raises: ValueError.
        """
        user_id = data.get('user_id', None)
        group_id = data.get('group_id', None)
        logger.info("Verify if group id and user id does not empty")
        if user_id is None or not user_id:
            logger.error("OPEN: Error user id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id cannot be empty")) + '"}')
        if group_id is None or not group_id:
            logger.error("OPEN: Error group id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group id cannot be empty")) + '"}')
        # Verify is user id and group id both of them are number
        if not re.fullmatch(r'[0-9]+', user_id) and re.fullmatch(r'[0-9]+', group_id):
            logger.error("OPEN: Error user id or group id is not a number", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id or group is not a number")) + '"}')
        try:
            # Find group with ID sent by the user admin
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist as e:
            logger.error("OPEN: Error group does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group you search does not exist")) + '"}')
        try:
            # Find user with ID sent by the user admin
            users = accounts_models.User.objects.get(id=user_id)
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN: Error user does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("User you search does not exist")) + '"}')
        # Verify that the group has already been added to the user
        list_group_user = users.groups.all()
        # find group if them exist, raise error
        for info in list_group_user:
            if info.id == group.id:
                logger.error("OPEN: Error group has been add to this user %s" % group.name, exc_info=True)
                raise ValueError('{"detail":"' + str(_("This user already has this group added")) + '"}')
        # Add group to user
        users.groups.add(group)
        logger.debug("OPEN: group has been added correctly to user %s" % users.username)
        return group

    @is_active_user
    def delete_user_group(self, data: dict, user: accounts_models.User):
        """
            Delete a group from the user
            Raises exception if group or user does not exist and try to eliminate a group
            from the user and this user doesn't have group to eliminate

            :param data: group id and user id.
            :type: dict.
            :param user: user admin.
            :type: Model User.
            :return: group
            :raises: ValueError.
        """
        user_id = data.get('user_id', None)
        group_id = data.get('group_id', None)
        logger.info("Verify if group id and user id does not empty")
        if user_id is None or not user_id:
            logger.error("OPEN: Error user id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id cannot be empty")) + '"}')
        if group_id is None or not group_id:
            logger.error("OPEN: Error group id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group id cannot be empty")) + '"}')
        # Verify is user id and group id both of them are number
        if not re.fullmatch(r'[0-9]+', user_id) and re.fullmatch(r'[0-9]+', group_id):
            logger.error("OPEN: Error user id or group id is not a number", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id or group is not a number")) + '"}')
        try:
            # Find group with ID sent by the user admin
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist as e:
            logger.error("OPEN: Error group does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("Group you search does not exist")) + '"}')
        try:
            # Find user with ID sent by the user admin
            users = accounts_models.User.objects.get(id=user_id)
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN: Error user does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("User you search does not exist")) + '"}')
        # Verify is user don't have any group
        if len(users.groups.all()) == 0:
            logger.error("OPEN: Error user don`t have any group to eliminate", exc_info=True)
            raise ValueError('{"detail":"' + str(_("This user does not have any group to deleted")) + '"}')
        # Verify that the group has already been added to the user
        list_group_user = users.groups.all()
        band = False
        # Find group to remove inside user
        for info in list_group_user:
            if info.id == group.id:
                # remove group to user
                users.groups.remove(group)
                return group
            else:
                band = True
        # if flag is true then group to remove does not exist
        if band:
            logger.error("OPEN: Error group name to remove does not exist or has been removed %s" % group.name,
                         exc_info=True)
            raise ValueError('{"detail":"' +
                             str(_("This group has been removed for this user or has never been added")) + '"}')
        logger.debug("OPEN: group has been remove from the user correctly")
        return group


class UserPermissionServices:
    """
        Main class service to contain method to add and delete permission from the user
    """
    @is_active_user
    def add_user_permission(self, data: dict, user: accounts_models.User):
        """
            Add permission to user.
            raise exception if permission or user does not exist and when adding the same permission to the user

            :param data: user id and permission id.
            :type: dict.
            :param user: user admin.
            :type: Model User.
            :return: True
            :raises: ValueError.
        """
        user_id = data.get('user_id', None)
        permission_id = data.get('permission_id', None)
        logger.info("Verify if permission id and user id does not empty")
        if user_id is None or not user_id:
            logger.error("OPEN: Error user id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id cannot be empty")) + '"}')
        if permission_id is None or not permission_id:
            logger.error("OPEN: Error permission id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission id cannot be empty")) + '"}')
        # Verify is user id and permission id both of them are number
        if not re.fullmatch(r'[0-9]+', user_id) and re.fullmatch(r'[0-9]+', permission_id):
            logger.error("OPEN: Error user id or permission id is not a number", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id or permission is not a number")) + '"}')
        try:
            # Find permission with ID sent by the user admin
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist as e:
            logger.error("OPEN: Error permission does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission you search does not exist")) + '"}')
        try:
            # Find user with ID sent by the user admin
            users = accounts_models.User.objects.get(id=user_id)
        except accounts_models.User.DoesNotExist as e:
            logger.error("OPEN: Error user does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("User you search does not exist")) + '"}')
        # Verify that the group has already been added to the user
        list_permission_user = users.user_permissions.all()
        # Find permission if them exist, raise error
        for info in list_permission_user:
            if info.id == permission.id:
                logger.error("OPEN: Error permission has been add to this user %s" % permission.name, exc_info=True)
                raise ValueError('{"detail":"' + str(_("This user already has this permission added")) + '"}')
        # Add group to user
        users.user_permissions.add(permission)
        logger.debug("OPEN: permission has been added correctly to user %s" % users.username)
        return True

    @is_active_user
    def delete_user_permission(self, data: dict, user: accounts_models.User):
        """
            Delete a permission from the user
            Raises exception if permission or user does not exist and try to eliminate a permission
            from the user and this user doesn't have permission to eliminate

            :param data: user id and permission id.
            :type: dict.
            :param user: user admin.
            :type: Model User.
            :return: True
            :raises: ValueError.
        """
        user_id = data.get('user_id', None)
        permission_id = data.get('permission_id', None)
        logger.info("Verify if permission id and user id does not empty")
        if user_id is None or not user_id:
            logger.error("OPEN: Error user id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id cannot be empty")) + '"}')
        if permission_id is None or not permission_id:
            logger.error("OPEN: Error permission id empty", exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission id cannot be empty")) + '"}')
        # Verify is user id and permission id both of them are number
        if not re.fullmatch(r'[0-9]+', user_id) and re.fullmatch(r'[0-9]+', permission_id):
            logger.error("OPEN: Error user id or permission id is not a number", exc_info=True)
            raise ValueError('{"detail":"' + str(_("User id or permission is not a number")) + '"}')
        try:
            # Find permission with ID sent by the user admin
            permission = Permission.objects.get(id=permission_id)
        except Permission.DoesNotExist as e:
            logger.error("OPEN: Error permission does not exist %s" % str(e), exc_info=True)
            raise ValueError('{"detail":"' + str(_("Permission you search does not exist")) + '"}')
        try:
            # Find user with ID sent by the user admin
            users = accounts_models.User.objects.get(id=user_id)
        except accounts_models.User.DoesNotExist:
            logger.error("OPEN: Error permission has been add to this user %s" % permission.name, exc_info=True)
            raise ValueError('{"detail":"' + str(_("User you search does not exist")) + '"}')
        # Verify is user don't have any group
        if len(users.user_permissions.all()) == 0:
            logger.error("OPEN: Error user don`t have any permission to eliminate", exc_info=True)
            raise ValueError('{"detail":"' + str(_("This user does not have any permission to deleted")) + '"}')
        # Verify that the group has already been added to the user
        list_permission_user = users.user_permissions.all()
        band = False
        # Find permission to remove inside user
        for info in list_permission_user:
            if info.id == permission.id:
                # remove permission to user
                users.user_permissions.remove(permission)
                return True
            else:
                band = True
        # if flag is true then permission to remove does not exist
        if band:
            logger.error("OPEN:Error permission name to remove does not exist or has been removed %s" % permission.name,
                         exc_info=True)
            raise ValueError('{"detail":"' +
                             str(_("This permission has been removed for this user or has never been added")) + '"}')
        logger.debug("OPEN: permission has been remove correctly to user %s" % users.username)
        return True
