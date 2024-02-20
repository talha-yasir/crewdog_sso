from django.urls import path, include, re_path

from .views import *

urlpatterns=[
    path('register',CreateUser.as_view()),
    path('login/', UserLogin.as_view(), name='user-login'),
    path('auth/apple/', AppleLogin.as_view(), name='apple_login'),
    path('auth/google/', GoogleLogin.as_view(), name='google_login',),
    path('linkedin/login/',LinkedInAPIView.as_view(), name='linkedin-login'),
    path('auth/linkedin',LinkedInAccessToken.as_view(), name='linkedin-access-token'),
    path('sendotp/',SendOTPEmail.as_view()),
    path('profile/update/', ProfileUpdateAPIView.as_view(), name='profile-update'),
    path('password/change/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('profile/get/',UserProfileAPIView.as_view(), name='profile-get'),
    
    
]