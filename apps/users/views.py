# from django.shortcuts import render
# from django.contrib.auth import update_session_auth_hash, logout
import email
import html
import token
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import update_session_auth_hash
from django.utils.encoding import force_bytes
from django.utils import timezone
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.db import transaction
from django.template.loader import render_to_string
from numpy import full

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
    # parser_classes,
)

# from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated

from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import (
    CreateUserSerializer,
    UserDetailSerializer,
    UpdateProfileSerializer,
)

# from djoser.serializers import SetPasswordRetypeSerializer
# from djoser.compat import get_user_email
from .serializers import TokenRefreshSerializer
from .models import User
from loguru import logger

log = logger.bind(name="users")


@api_view(["GET"])
@permission_classes([AllowAny])
def refresh_token_view(request):
    refresh_token = request.COOKIES.get("refresh_token")
    data = {"refresh": refresh_token}
    serializer = TokenRefreshSerializer(data=data)
    try:
        serializer.is_valid(raise_exception=True)
    except TokenError:
        return Response(status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.validated_data, status=status.HTTP_200_OK)

# helper function to issue tokens
def issue_tokens(user):
    """Generates JWT tokens and creates a response with refresh cookie."""
    token = RefreshToken.for_user(user)
    serializer = UserDetailSerializer(instance=user)
    response = Response(serializer.data)

    # set refresh token in http only cookie
    response.set_cookie(
        key=settings.SIMPLE_JWT["AUTH_COOKIE"],
        value=str(token),
        httponly=True,
        secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
        samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        domain=settings.SIMPLE_JWT["AUTH_COOKIE_DOMAIN"],
    )
    response.data["access"] = str(token.access_token)
    logger.info(f"Tokens issued for user {user.get_full_name}")
    return response


# helper function to send otp to user
def send_otp(user):
    if not user.otp_code:
        logger.warning(f"failed to send otp email for user {user.get_full_name}")
        return False
    
    email_context = {
        "user": user,
        "otp_code": user.otp_code,
    }
    subject = "Your Verification Code"
    try:
        email_body = render_to_string("email/otp_email.html", email_context)
        send_mail(
            subject=subject,
            message=f"Your verification code is {user.otp_code}",
            html_message=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False, # set to True in production
        )
        logger.info(f"OTP email sent to {user.get_full_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.get_full_name}: {e}")
        return False

@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def get_logged_in_user(request):
    serializer = UserDetailSerializer(instance=request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def logout_view(request):
    drf_response = Response(status=status.HTTP_200_OK)
    drf_response.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])
    return drf_response


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def get_all_users(request):
    if request.user.is_superuser or request.user.is_staff:
        users = User.objects.all()
        serializer = UserDetailSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(
        {"detail": "You do not have permission to perform this action."},
        status=status.HTTP_403_FORBIDDEN,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    email = request.data.get("email")
    password = request.data.get("password")
    logger.info(f"Authenticating User {user.get_full_name}")

    user = authenticate(request, email=email, password=password)
    """
    returns token and user data if user is authenticated
    if user is not verified, send OTP code to email
    """
    if user is None:
        logger.warning(f"Authenticate for user {user.get_full_name} successful")
        if not user.is_active:
            logger.warning(f"Login attempt failed: Account inactive for: {user.get_full_name}")
            return Response(
                {"detail": "Account inactive. Please contact support."},
                status=status.HTTP_403_FORBIDDEN,
            )
        
        if user._is_verified:
            # user is active but verified, proceed to login
            logger.info(f"Login attempt successful: proceed to login: {user.get_full_name}")
            return issue_tokens(user)
        else:
            # user is active but not verified
            logger.warning(f"login attempt: uer {user.get_full_name} not verified")

            # check otp status
            otp_valid = False
            if user.otp_code and user.otp_expiry and user.otp_expiry > timezone.now():
                otp_valid = True

            if otp_valid:
                # otp exists and is valid
                logger.info(f"Existing OTP code is still valid, prompting user: {user.get_full_name} to verify")
                return Response(
                    {
                        "detail": "OTP code already sent. Please check your email.",
                        # print otp here for testing, remove it in production
                        "otp_code": user.otp_code,
                    },
                    status=status.HTTP_401_UNAUTHORIZED, # 401 UNAUTHORIZED, but guide user through the process to verify
                    # print otp here for testing, remove it in production
                    
                )
            else:
                # otp has exipred or doesnt exist
                logger.info(f"OTP code expired or does not exist, generating a new one for user: {user.get_full_name}")
                user.generate_otp_code()
                if send_otp(user):
                    return Response(
                        {
                            "detail": "Your account is not verified. Please check your email for a new code to verify your email.",
                        },
                        status=status.HTTP_401_UNAUTHORIZED, # 401 UNAUTHORIZED, but guide user through the process to verify
                    )
                else:
                    logger.error(f"Failed to send OTP email to {user.get_full_name}")
                    return Response(
                        {
                            "detail": "Account not verified. Failed to send verification code. Please try again later or contact support.",
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
    else:
        # authentication failed
        logger.warning(f"Login attempt failed: Invalid credentials for user {user.email}")
        return Response(
            {
                "detail": "Invalid credentials. Please try again.",
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )
    # if user is not None:
    #     if user.roles in [User.Roles.ADMIN, User.Roles.BIKER]:
    #         # Send OTP code to email
    #         user.generate_otp_code()
    #         email_context = {
    #             "user": user,
    #             "otp_code": user.otp_code,
    #         }
    #         email_body = render_to_string("email/otp_email.html", email_context)
    #         send_mail(
    #             subject="Activate Your Account",
    #             message="",  # Plain text version (optional)
    #             html_message=email_body,
    #             from_email=settings.DEFAULT_FROM_EMAIL,
    #             recipient_list=[user.email],
    #         )
    #         return Response(
    #             {"message": "OTP sent. Please check your email to verify."},
    #             status=status.HTTP_200_OK,
    #         )
    #     # Check if user is verified and active
    #     if user.is_verified and user.is_active:
    #         token = RefreshToken.for_user(user)
    #         response = Response(
    #             {
    #                 "email": user.email,
    #                 "full_name": user.get_full_name,
    #                 "is_verified": user.is_verified,
    #                 "access": str(token.access_token),
    #             }
    #         )
    #         response.set_cookie(
    #             key=settings.SIMPLE_JWT["AUTH_COOKIE"],
    #             value=str(token),
    #             httponly=True,
    #         )
    #         return response

    #     return Response(
    #         {"detail": "Account not verified or inactive. Please verify your account."},
    #         status=status.HTTP_401_UNAUTHORIZED,
    #     )

    # return Response(
    #     {"detail": "Invalid credentials. Please try again."},
    #     status=status.HTTP_401_UNAUTHORIZED,
    # )


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp_view(request):
    email = request.data.get("email")
    otp = request.data.get("otp")

    try:
        # Get user by email, else return 404
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # Verify OTP code if email exists
    if user.verify_otp_code(otp):
        token = RefreshToken.for_user(user)
        response = Response(
            {
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
    """
    This function sends a new OTP code to the user's email.
    """
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    user.generate_otp_code()
    user.save()

    email_context = {
        "user": user,
        "otp_code": user.otp_code,
    }
    email_body = render_to_string("email/otp_email.html", email_context)
    send_mail(
        subject="Your New OTP Code",
        message="",  # Plain text version (optional)
        html_message=email_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
    )

    return Response(
        {"detail": "New OTP code sent successfully"}, status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([AllowAny])
@transaction.atomic
# @parser_classes([MultiPartParser, FormParser])
def signup_view(request):
    # Get user data from request
    user_data = {
        "first_name": request.data.get("first_name"),
        "other_name": request.data.get("other_name"),
        "last_name": request.data.get("last_name"),
        "email": request.data.get("email"),
        "password": request.data.get("password"),
        "confirm_password": request.data.get("confirm_password"),
        "phone_number": request.data.get("phone_number"),
        # "roles": request.data.get("roles", User.Roles.USER),
        # "is_verified": request.data.get("is_verified", False),
    }
    serializer = CreateUserSerializer(data=user_data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    logger.info(f"User {user.get_full_name, user.email, user.id} created successfully")

    if user:
        user.generate_otp_code()
        email_context = {
            "user": user,
            "otp_code": user.otp_code,
        }
        logger.info(f"OTP code sent to {user.email}")
        email_body = render_to_string("email/otp_email.html", email_context)
        send_mail(
            subject="Your OTP Code",
            message="",  # Plain text version (optional)
            html_message=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )
        token = RefreshToken().for_user(user)
        response = Response(
            {
                "message": "Account created successfully. Please verify your account.",
                "access": str(token.access_token),
                "email": user.email,
                "full_name": user.get_full_name,
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


# password reset for when the user is authenticated and wants to change their password
class AuthenticatedPasswordResetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        # Validate current password
        if not check_password(current_password, user.password):
            return Response(
                {"detail": "Current password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate new password and confirmation
        if new_password != confirm_password:
            return Response(
                {"detail": "New password and confirmation do not match."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update the password
        user.password = make_password(new_password)
        user.save()

        # Update session to prevent logout
        update_session_auth_hash(request, user)

        return Response(
            {"message": "Password reset successfully."},
            status=status.HTTP_200_OK,
        )

# password reset for when the user is not authenticated, url will be sent to their email address
class RequestPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")
        user = User.objects.filter(email=email).first()

        if not user:
            return Response(
                {"detail": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Generate a password reset token
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Build the reset link
        reset_url = reverse(
            "password-reset-confirm", kwargs={"uidb64": uid, "token": token}
        )
        reset_link = f"{settings.DOMAIN}{reset_url}"  # Replace with your frontend URL

        # Send the reset link via email
        email_body = f"""
        You requested a password reset. Click the link below to reset your password:
        {reset_link}
        """
        send_mail(
            subject="Password Reset Request",
            message=email_body.strip(),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )

        return Response(
            {"message": "Password reset link sent to your email."},
            status=status.HTTP_200_OK,
        )


class ConfirmPasswordResetView(APIView):
    def post(self, request, uidb64, token):
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"detail": "Invalid user or token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate the token
        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response(
                {"detail": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate new password and confirmation
        if new_password != confirm_password:
            return Response(
                {"detail": "New password and confirmation do not match."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update the password
        user.password = make_password(new_password)
        user.save()

        return Response(
            {"message": "Password reset successfully."},
            status=status.HTTP_200_OK,
        )


@api_view(["DELETE"])
def delete_user(request, id):
    try:
        user = User.objects.get(id=id)
        logger.debug(f"User {user.get_full_name, user.email, user.id} found")
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    if user.is_verified:
        user.is_active = False
        user.save()
        logger.info(f"User {user.get_full_name, user.email, user.id} deactivated")
        return Response(
            {"message": "User has been deactivated"}, status=status.HTTP_200_OK
        )
    else:
        user.delete()
        logger.info(f"User {user.get_full_name, user.email, user.id} deleted")
        return Response(
            {"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )


class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        user = request.user
        logger.debug(f"User {user.get_full_name, user.email, user.id} data retrieved")
        serializer = UpdateProfileSerializer(
            user, data=request.data, partial=True
        )  # Allow partial updates
        serializer.is_valid(raise_exception=True)
        serializer.save()
        logger.info(f"User {user.get_full_name, user.email} updated")
        return Response(serializer.data, status=status.HTTP_200_OK)
