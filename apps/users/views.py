# from django.shortcuts import render
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
from rest_framework.views import APIView
# from django.utils.encoding import force_str
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
    parser_classes,
)
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, CreateUserSerializer, UpdateProfileSerializer
from djoser.serializers import SetPasswordRetypeSerializer
from djoser.compat import get_user_email
from .serializers import TokenRefreshSerializer
from django.contrib.auth import (
    authenticate,
    logout,
)
# from django.template.loader import render_to_string
# from .custom_permissions import IsAdmin, IsImam, IsAssociate, IsSuperAdmin
# from django.contrib.auth.models import Permission
# from django.utils.text import slugify

User = get_user_model()


# Gets new access token else should return 401
# to get a new refresh token, login
@api_view(["GET"])
@permission_classes([AllowAny])
def refresh_token_view(request):
    # Access the refresh_token from the cookies sent with the request
    refresh_token = request.COOKIES.get("refresh_token")
    # if not refresh_token:
    #     return Response({"error": "Refresh token not found."}, status=400)

    # Prepare data for TokenRefreshView
    data = {"refresh": refresh_token}
    # Check simplejwt docs if this doesnt work
    serializer = TokenRefreshSerializer(data=data)
    try:
        serializer.is_valid(raise_exception=True)
    except TokenError:
        return Response(status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.validated_data, status=status.HTTP_200_OK)


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
def login_view(request):
    """Login view for local authentication"""
    email = request.data.get("email")
    password = request.data.get("password")

    # Authenticate the user by email and password
    user = authenticate(request, email=email, password=password)

    if user is not None:
        # Check if the user is in a role that requires OTP
        # if user.roles in [User.Roles.ADMIN, User.Roles.IMAM, User.Roles.ASSCOCIATE]:
        #     user.generate_otp_code()
        #     send_mail(
        #         "Your OTP Code",
        #         f"Dear {user.get_full_name}, your OTP code is {user.otp_code}.",
        #         settings.DEFAULT_FROM_EMAIL,
        #         [user.email],
        #     )
        #     return Response(
        #         {"message": "OTP sent. Please check your email to verify.",
        #          "roles": user.roles,},
        #         status=status.HTTP_200_OK,
        #     )

        # If the user is verified, generate a JWT token and log them in
        if user.is_verified and user.is_active:
            token = RefreshToken.for_user(user)
            response = Response(
                {
                    "User": user.get_full_name,
                    "roles": user.roles,
                    "is_verified": user.is_verified,
                    "access": str(token.access_token),
                }
            )
            response.set_cookie(
                key=settings.SIMPLE_JWT["AUTH_COOKIE"],
                value=str(token),
                httponly=True,
            )
            return response

        return Response(
            {"detail": "Account not verified or inactive. Please verify your account."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    return Response(
        {"detail": "Invalid credentials. Please try again."},
        status=status.HTTP_401_UNAUTHORIZED,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp_view(request):
    email = request.data.get("email")
    otp = request.data.get("otp")

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if user.verify_otp_code(otp):
        token = RefreshToken.for_user(user)
        response = Response(
            {
                "User": user.get_full_name,
                "roles": user.roles,
                "access": str(token.access_token),
            }
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=str(token),
            httponly=True,
        )
        return response

    return Response({"detail": "Invalid OTP code"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([AllowAny])
def request_new_otp_view(request):
    email = request.data.get("email")

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # Generate a new OTP code
    user.generate_otp_code()
    user.save()

    # Send the new OTP code to the user's email
    send_mail(
        "Your New OTP Code",
        f"Dear User, your new OTP code is {user.otp_code}",
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )

    return Response({"detail": "New OTP code sent successfully"}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([AllowAny])
@authentication_classes([JWTAuthentication])
def get_all_users(request):
    serializer = UserSerializer(data=User.objects.all(), many=True)
    serializer.is_valid()
    return Response({"users": serializer.data}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
@transaction.atomic
# @parser_classes([MultiPartParser, FormParser])
def signup_view(request):
    """Register view for local authentication"""
    user_data = {
        # "profile_pic": request.data.get("profile_pic"),
        "first_name": request.data.get("first_name"),
        "other_name": request.data.get("other_name"),
        "last_name": request.data.get("last_name"),
        "email": request.data.get("email"),
        "password": request.data.get("password"),
        "confirm_password": request.data.get("confirm_password"),
        "phone_number": request.data.get("phone_number"),
        "roles": request.data.get("roles", User.Roles.USER),
        "is_verified": request.data.get("is_verified", False),
        # Add other fields as needed
    }
    serializer = CreateUserSerializer(data=user_data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    if user:
        # Generate OTP code if it doesn't exist
        if not user.otp_code:
            user.generate_otp_code()
            print(f"Generated new OTP: {user.otp_code}")  # Log the generated OTP for debugging
        else:
            print(f"Using existing OTP: {user.otp_code}")  # Log the existing OTP for debugging

        send_mail(
            "Your OTP Code",
            f"Dear User, your OTP code is {user.otp_code}",
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )
        print(f"Sent OTP to: {user.email}")  # Log the email address to which the OTP was sent
        # If account creation successful, issue JWT token
        token = RefreshToken().for_user(user)
        response = Response(
            {
                "access": str(token.access_token),
                # user: serializer.data
            }
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=str(token),
            httponly=True,
        )
        return response
    return Response(
        {"detail": "Account creation failed"}, status=status.HTTP_400_BAD_REQUEST
    )


@api_view(["DELETE"])
def delete_user(request, id):
    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    if user.is_verified:
        user.is_active = False
        user.save()
        return Response(
            {"message": "User has been deactivated"}, status=status.HTTP_200_OK
        )
    else:
        user.delete()
        return Response(
            {"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )

class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]
    # parser_classes = [MultiPartParser, FormParser]

    def patch(self, request, *args, **kwargs):
        user = request.user
        serializer = UpdateProfileSerializer(user, data=request.data, partial=True)  # Allow partial updates
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def get_logged_in_user(request):
    serializer = UserSerializer(instance=request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def logout_view(request):
    drf_response = Response(status=status.HTTP_200_OK)
    drf_response.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])
    return drf_response


class SetPassword(APIView):
    def post(self, request):
        data = self.request.data 
        print(data)
        serializer = SetPasswordRetypeSerializer(
            context={"request": self.request}, data=data
        )
        serializer.is_valid(raise_exception=True)

        self.request.user.set_password(serializer.data["new_password"])
        self.request.user.save()

        if settings.PASSWORD_CHANGED_EMAIL_CONFIRMATION:
            context = {"user": self.request.user}
            to = [get_user_email(self.request.user)]
            settings.EMAIL.password_changed_confirmation(self.request, context).send(to)

        if settings.LOGOUT_ON_PASSWORD_CHANGE:
            logout(self.request)
        elif settings.CREATE_SESSION_ON_LOGIN:
            update_session_auth_hash(self.request, self.request.user)
        return Response({"status": 200}, status=status.HTTP_200_OK)


# class ResetPassword(generics.GenericAPIView):
#     # serializer_class = ResetPasswordSerializer
#     permission_classes = []

#     def post(self, request, token):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         data = serializer.validated_data
        
#         new_password = data['new_password']
#         confirm_password = data['confirm_password']
        
#         if new_password != confirm_password:
#             return Response({"error": "Passwords do not match"}, status=400)
        
#         reset_obj = User.objects.filter(token=token).first()
        
#         if not reset_obj:
#             return Response({'error':'Invalid token'}, status=400)
        
#         user = User.objects.filter(email=reset_obj.email).first()
        
#         if user:
#             user.set_password(request.data['new_password'])
#             user.save()
            
#             reset_obj.delete()
            
#             return Response({'success':'Password updated'})
#         else: 
#             return Response({'error':'No user found'}, status=404)

@api_view(["POST"])
@transaction.atomic
def custom_password_reset_view(request):
    email = request.data.get("email")
    user = User.objects.filter(email=email).first()

    # If the user exists, send a password reset email
    if user:
        # Generate password reset token and UID
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Construct the password reset link (to be sent via email)
        reset_link = f"{settings.DOMAIN}/api/auth/password-reset-confirm/{uid}/{token}/"

        # Send an email with the password reset link
        send_mail(
            subject="Password Reset for Your Account",
            message=f"Please click the following link to reset your password: {reset_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )

    # Always return a 200 OK response, even if the user doesn't exist
    return Response(
        {"message": "If the email exists, a password reset link has been sent."},
        status=status.HTTP_200_OK,
    )