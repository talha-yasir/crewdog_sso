from django.shortcuts import render
from rest_framework import (
    viewsets, views,
    status, permissions
    )
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.db import transaction
from accounts.models import (
    User,OTPCode
    )
from accounts.serializers import (
    UserSerializer,ProfileUpdateSerializer,ChangePasswordSerializer
    )
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
import requests
import time
import random
from django.utils.html import format_html
from accounts.custom_utilities.helper import EmailThread
from django.utils import timezone
from datetime import datetime,timedelta
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
# Create your views here.
class CreateUser(APIView):
    permission_classes = [AllowAny]
    @transaction.atomic
    def post(self, request):
    
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            if user :
                if user.password:
                    return Response({"message": "Email address already exists", "status": status.HTTP_403_FORBIDDEN}, status=status.HTTP_403_FORBIDDEN)
                else: return Response({"message": "Email address already exists Recover your Account ", "status": status.HTTP_406_NOT_ACCEPTABLE}, status=status.status.HTTP_406_NOT_ACCEPTABLE)
        except User.DoesNotExist:
            serializers = UserSerializer(data=request.data)
            if serializers.is_valid():
                serializers.save()
                return Response({"message": "Successfully signed up", "status": status.HTTP_200_OK}, status=status.HTTP_200_OK)
class UserLogin(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({'message':'Successfully logged in ',
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'name':user.first_name,
                'status':status.HTTP_202_ACCEPTED
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
class AppleLogin(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        
        token = request.data.get('token')
        
        if not token:
            return Response({'status':False,'error': 'Access token not received from Apple'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            decoded_token = jwt.decode(token, verify=False)
        except Exception as e:
            return Response({'status':False,'error': str(e),"token":token},status=status.HTTP_400_BAD_REQUEST)
        
        try :
            email = decoded_token.get('email')
            user = User.objects.get(email=email)
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)
            tokens = {
                "refresh": str(refresh),
                "access": str(access)
            }
            return Response({"status":True, "message":"Successfully logged in","tokens":tokens}, status=status.HTTP_200_OK)
        except Exception as e:
            
            email = decoded_token.get('email')
            first_name = decoded_token.get('given_name')
            last_name = decoded_token.get('family_name')
            phone_number = decoded_token.get('phone')
            
            # user_profile = UserProfile.objects.create(phone_number=phone_number,display_name = 'first_name' , email = email)
            user = User.objects.create(email=email, username=email)
            user.save()
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)
            tokens = {
                "refresh": str(refresh),
                "access": str(access)
            }

       
        return Response({"status":True, "message":"Account was created successfully","tokens":tokens}, status=status.HTTP_200_OK)
class GoogleLogin(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        access_token = request.data.get('access_token')
        url = f'https://www.googleapis.com/oauth2/v1/userinfo/?access_token={access_token}'
        user_info={}
        response = requests.get(url)
        if response.status_code != 200:
            return Response({"status":False , "message" : "Invalid Account"})
        user_info = response.json()
        
        try :
            email = user_info.get('email')
            user = User.objects.get(email=email)
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)
            tokens = {
            "refresh": str(refresh),
            "access": str(access)
        }
            return Response({"status":True, "message":"Successfully logged in","tokens":tokens}, status=status.HTTP_200_OK)
        except Exception as e:
            
            email = user_info.get('email')
            first_name = user_info.get('given_name')
            last_name = user_info.get('family_name')
            try:
                user = User.objects.create(email=email, first_name = first_name,username=email)
                user.save()

                refresh = RefreshToken.for_user(user)
                access = str(refresh.access_token)
                tokens = {
                "refresh": str(refresh),
                "access": str(access)
                }
            except Exception as e:
                return Response({"status":False, "message" : "This email is already registered. Login with password"},status=status.HTTP_403_FORBIDDEN)

            return Response({"status":True, "message":"Account was created successfully","tokens":tokens}, status=status.HTTP_200_OK)
        else:
            return Response({"status":False , "message" : "Invalid Account"})
class LinkedInAPIView(APIView):
    def post(self, request, *args, **kwargs):
        code = request.data.get('code')
        access_token_url = 'https://backend.crewdog.ai/api/auth/linkedin'
        
        token_response = requests.get(access_token_url, params={'code': code})

        if token_response.status_code == 200:
            
            token_data = token_response.json()
            
        else: return Response({"message":"Auth token is invalid or expired"} , status=status.HTTP_401_UNAUTHORIZED)


        access_token = token_data['token']
        # access_token = "AQUYZ9kro6I0bhRDh2IawwejxoJ-3263QJcKOKGD3Y6KsEltJG6qw8w6k5bry1lOKT-SMyfBCwweIczmmBJgi6GRfsUOw_uo4hzsoCGcZCtrnV1AppoImWHKWFtL4lnmrqrqaTGscYoXXdNwJDEin2c7knOzmEqJr4WbAIGqtlI5AHYrybo8OcY56LMqmIH8JXw84bcI8wnwxs1Oy4UelCX7CjYBg0j87juOEbJXrWpGBoiWlRARyLjtYJXsWxpKGTTYvQzAhMoXsFqWX9KGMftLEKSxRsOhEZ6mdw7CW1aIPq_fhRbbkK-uydK4-2oGDKAmuh2CVeHgkd7zjU1N00QFQcfV_A"
    
        api_url = 'https://api.linkedin.com/v2/me'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Connection': 'Keep-Alive',
            }
        
        time.sleep(5)
        response = requests.get(api_url, headers=headers)
        # print("=====",response.json())
        if response.status_code==200:
            response_data = response.json()
            first_name = response_data.get('firstName', {}).get('localized', {}).get('en_US')  
            last_name = response_data.get('lastName', {}).get('localized', {}).get('en_US')   
            profile_picture = response_data.get('profilePicture', {}).get('displayImage')
            
            email_url = 'https://api.linkedin.com/v2/clientAwareMemberHandles?q=members&projection=(elements*(true,EMAIL,handle~,emailAddress))'
            email_response = requests.get(email_url, headers=headers)
            email_data = email_response.json()
            email_address = email_data['elements'][0]['handle~']['emailAddress']
            try :
                
                user = User.objects.get(email=email_address)
                if user.password:
                    return Response({"status":False, "message" : "This email is already registered. Login with password"},status=status.HTTP_400_BAD_REQUEST)
                refresh = RefreshToken.for_user(user)
                access = str(refresh.access_token)
                tokens = {
                "refresh": str(refresh),
                "access": str(access)
            }
                return Response({"status":True, "message":"Successfully logged in","tokens":tokens}, status=status.HTTP_200_OK)
            except Exception as e:
                
                try:
                    user = User.objects.create(email=email_address, first_name = first_name,username=email_address,last_name = last_name)
                    user.save()

                    refresh = RefreshToken.for_user(user)
                    access = str(refresh.access_token)
                    tokens = {
                    "refresh": str(refresh),
                    "access": str(access)
                    }
                except Exception as e:
                    return Response({"status":False, "message" : "This email is already registered. Login with password"},status=status.HTTP_400_BAD_REQUEST)

                return Response({"status":True, "message":"Account was created successfully","tokens":tokens}, status=status.HTTP_200_OK)
        else:
            return Response({"status":False , "message" : "Invalid Account"})
class LinkedInAccessToken(APIView):
    def get(self, request):
        code = request.GET.get('code')
        
        if code:
            url = "https://www.linkedin.com/oauth/v2/accessToken"
            payload = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
                'client_id': settings.LINKEDIN_CLIENT_ID,
                'client_secret': settings.LINKEDIN_CLIENT_SECRET,
            }
            response = requests.post(url, data=payload)
           
            if response.status_code == 200:
                data = response.json()
                access_token = data.get('access_token')
                
                # expires_in = data.get('expires_in')
                # refresh_token = data.get('refresh_token')
                

                return Response({'token':access_token},status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Failed to obtain access token'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Authorization code is missing'})
class SendOTPEmail(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if email:
            try:
                user = User.objects.get(email = email)
                
                code = random.randint(1000, 9999)
                expiration_period = timedelta(minutes=5)  
                expiration_time = timezone.now() + expiration_period
                # otp = OTPCode.objects.create(user=user,code = code,expiration_time=expiration_time)
                # otp.save()
                otp, created = OTPCode.objects.get_or_create(user=user, defaults={'code': code, 'expiration_time': expiration_time})
                # Update the code and expiration time if it already existed
                if not created:
            
                    otp.code = code
                    otp.expiration_time = expiration_time
                    otp.save()

                subject = 'Reset Password OTP Code'
                message = format_html(
                    f"""
                    Hello {user.first_name},

                    You have requested a password reset for your account. Please use the following OTP code to reset your password:

                    <strong>OTP Code: {otp.code }</strong>

                    Please note that this OTP code is valid for a limited time. It will expire in 5 minutes. If you did not request this password reset, please disregard this email.

                    If you have any questions or need further assistance, please contact our support team at [Your Support Email or Contact Information].

                    Thank you for using our services.
                    """,
                    user=user, code=otp
                )
                EmailThread(subject=subject, html_message=message, recipient_list=[user.email,]).start()
                return Response({'status':True, 'message':'An OTP code has been send to your email address '},status=status.HTTP_200_OK)
            except Exception as e:
                print(e) 
                return Response({'status':False, 'message':'Account with this email address does not exist'}, status=status.HTTP_404_NOT_FOUND)       
        else:
            return Response({'message': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
class ProfileUpdateAPIView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ProfileUpdateSerializer
    permission_classes = (IsAuthenticated,)
    def get_object(self):
        return self.request.user
    def update(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data)
        else:
            return Response({'error': 'Authentication credentials not provided'}, status=status.HTTP_401_UNAUTHORIZED)
class ChangePasswordAPIView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)
    def get_object(self):
        return self.request.user
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')
        if not instance.check_password(old_password):
            return Response({'detail': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        instance.set_password(new_password)
        instance.save()
        return Response({'detail': 'Password changed successfully.'}, status=status.HTTP_200_OK)
class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user_profile = request.user  
        serializer = ProfileUpdateSerializer(user_profile)
        return Response(serializer.data)