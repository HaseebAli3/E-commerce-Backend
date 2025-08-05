from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, OTP
import random
import datetime
from django.core.mail import send_mail
from django.conf import settings

class UserRegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        # Check if email already exists
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({"email": "User with this email already exists."})
        
        # Check if username with this email exists
        if User.objects.filter(username=data['username'], email=data['email']).exists():
            raise serializers.ValidationError({"username": "Username with this email already exists."})
        
        return data
    
    def create(self, validated_data):
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        expires_at = datetime.datetime.now() + datetime.timedelta(minutes=10)
        
        # Save OTP
        OTP.objects.create(
            email=validated_data['email'],
            otp=otp,
            expires_at=expires_at,
            purpose='register'
        )
        
        # Send OTP email
        send_mail(
            'Verify Your Email',
            f'Your OTP for registration is: {otp} (valid for 10 minutes)',
            settings.EMAIL_HOST_USER,
            [validated_data['email']],
            fail_silently=False,
        )
        
        return validated_data

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    username = serializers.CharField(max_length=150, required=False)
    password = serializers.CharField(write_only=True, required=False)
    
    def validate(self, data):
        try:
            otp_obj = OTP.objects.filter(
                email=data['email'], 
                purpose='register'
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError("OTP not found or expired")
        
        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError("Invalid OTP")
        
        if otp_obj.expires_at < datetime.datetime.now(otp_obj.expires_at.tzinfo):
            raise serializers.ValidationError("OTP expired")
        
        return data

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        
        if not user.is_active:
            raise serializers.ValidationError("Account not active. Please contact support.")
        
        refresh = RefreshToken.for_user(user)
        
        return {
            'email': user.email,
            'username': user.username,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate(self, data):
        if not User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("User not found")
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        expires_at = datetime.datetime.now() + datetime.timedelta(minutes=10)
        
        # Save OTP
        OTP.objects.create(
            email=data['email'],
            otp=otp,
            expires_at=expires_at,
            purpose='reset'
        )
        
        # Send OTP email
        send_mail(
            'Password Reset OTP',
            f'Your OTP for password reset is: {otp} (valid for 10 minutes)',
            settings.EMAIL_HOST_USER,
            [data['email']],
            fail_silently=False,
        )
        
        return data

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        try:
            otp_obj = OTP.objects.filter(
                email=data['email'], 
                purpose='reset'
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError("OTP not found or expired")
        
        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError("Invalid OTP")
        
        if otp_obj.expires_at < datetime.datetime.now(otp_obj.expires_at.tzinfo):
            raise serializers.ValidationError("OTP expired")
        
        return data