from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, OTP
import random
import datetime
from django.core.mail import send_mail
from django.conf import settings

import datetime
import random
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from .models import OTP, User


def generate_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'email': user.email,
        'username': user.username
    }


class UserRegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("Email already registered.")
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already taken.")
        return data

    def create(self, validated_data):
        otp = f"{random.randint(100000, 999999):06d}"
        expires_at = timezone.now() + datetime.timedelta(minutes=10)

        # Remove previous OTPs
        OTP.objects.filter(email=validated_data['email'], purpose='register').delete()

        # Store temporarily (note: password stored hashed)
        OTP.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
            password=make_password(validated_data['password']),
            otp=otp,
            expires_at=expires_at,
            purpose='register'
        )

        # Send OTP
        send_mail(
            subject='Your OTP Code',
            message=f'Your OTP code is {otp}',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[validated_data['email']],
            fail_silently=False,
        )

        return validated_data


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            otp_obj = OTP.objects.filter(otp=data['otp'], purpose='register').latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired OTP.")

        if otp_obj.expires_at < timezone.now():
            raise serializers.ValidationError("OTP has expired.")

        data['otp_obj'] = otp_obj
        return data

    def create(self, validated_data):
        otp_obj = validated_data['otp_obj']

        # Create the user
        user = User.objects.create(
            email=otp_obj.email,
            username=otp_obj.username,
            password=otp_obj.password  # Already hashed
        )

        # Clean up OTP
        otp_obj.delete()

        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])

        if not user:
            raise serializers.ValidationError("Invalid credentials.")

        if not user.is_active:
            raise serializers.ValidationError("Account is not active.")

        return generate_tokens_for_user(user)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def create(self, validated_data):
        # Generate OTP
        otp = f"{random.randint(100000, 999999):06d}"
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)

        # Save OTP for password reset (invalidate previous)
        OTP.objects.filter(email=validated_data['email'], purpose='password_reset').delete()
        OTP.objects.create(
            email=validated_data['email'],
            otp=otp,
            expires_at=expires_at,
            purpose='password_reset'
        )

        # Send OTP email
        send_mail(
            subject='Password Reset OTP',
            message=f'Your OTP for password reset is: {otp} (valid for 15 minutes)',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[validated_data['email']],
            fail_silently=False,
        )

        return {"email": validated_data['email']}

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            otp_obj = OTP.objects.filter(
                email=data['email'],
                purpose='password_reset'
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"otp": "OTP not found. Please request a new one."})

        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError({"otp": "Invalid OTP."})

        if otp_obj.expires_at < datetime.datetime.now(datetime.timezone.utc):
            raise serializers.ValidationError({"otp": "OTP expired."})

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User not found."})

        data['user'] = user
        return data

    def save(self):
        user = self.validated_data['user']
        user.set_password(self.validated_data['new_password'])
        user.save()
        # consume OTP
        OTP.objects.filter(email=self.validated_data['email'], purpose='password_reset').delete()
        return user
