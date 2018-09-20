from django.contrib import admin
from django.urls import path, re_path, include
from accounts import views

urlpatterns = [
    path('signin/', views.LoginView.as_view(), name='login'),
    path('signin-captcha/', views.LoginCaptchaView.as_view(), name='login_captcha'),
    path('signin-facebook/', views.LoginFacebookView.as_view(), name="login_facebook"),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('signup/', views.RegisterView.as_view(), name='register'),
    path('request-password-email/', views.PasswordRecoverEmailView.as_view(), name='password_recovery_email'),
    path('request-password-phone/', views.PasswordRecoverPhoneView.as_view(), name='password_recovery_email'),
    path('recover-password/', views.PasswordRecoverView.as_view(), name='password_recover'),
    path('group/', views.UserGroupView.as_view(), name='user groups'),
    path('permission/', views.UserPermissionView.as_view(), name='user groups'),
]
