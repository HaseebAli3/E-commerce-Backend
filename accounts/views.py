from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .models import User, OTP
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    VerifyOTPSerializer,
    PasswordResetRequestSerializer,
    PasswordResetSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken

class UserRegistrationView(generics.GenericAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response({
            "message": "OTP sent to your email for verification",
            "email": request.data['email'],
        }, status=status.HTTP_200_OK)

class VerifyOTPView(generics.GenericAPIView):
    serializer_class = VerifyOTPSerializer
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        # Combine registration data with OTP data
        data = request.data.copy()
        if 'username' not in data:
            data['username'] = request.data.get('username')
        if 'password' not in data:
            data['password'] = request.data.get('password')
            
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        
        # Create user after OTP verification
        user = User.objects.create_user(
            email=serializer.validated_data['email'],
            username=data['username'],
            password=data['password']
        )
        user.is_active = True
        user.save()
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            "message": "Account created and verified successfully",
            "email": user.email,
            "username": user.username,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }, status=status.HTTP_201_CREATED)

class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return Response({
            "message": "OTP sent to your email for password reset"
        }, status=status.HTTP_200_OK)

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Reset password after OTP verification
        user = User.objects.get(email=serializer.validated_data['email'])
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        # Generate new tokens after password reset
        refresh = RefreshToken.for_user(user)
        
        return Response({
            "message": "Password reset successfully",
            "email": user.email,
            "username": user.username,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }, status=status.HTTP_200_OK)