# from django.shortcuts import render
# from django.contrib.auth import update_session_auth_hash, logout
import html
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
        "otp_code": user.otp_code
    }
    subject = "Your Verification Code"
    try:
        email_body = render_to_string("emails/otp_email.html", email_context)
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
    email = request.data.get("email", "").lower().strip()
    logger.info(f"Login attempt initiated for email: {email}")

    try:
        user = authenticate(request, email=email, password=request.data.get("password"))
        
        if user is None:
            logger.warning(f"Authentication failed for email: {email}")
            return Response(
                {"detail": "Invalid credentials. Please try again."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        logger.info(f"User {user.email} authenticated successfully")
        
        if not user.is_active:
            logger.warning(f"Blocked login attempt for inactive account: {user.email}")
            return Response(...)
            
        if not user.is_verified:
            logger.warning(f"Unverified user attempt: {user.email}")
            return Response(
                {"detail": "Please verify your email address."},
                status=status.HTTP_403_FORBIDDEN
            )
            
        logger.info(f"Successful login for {user.email}")
        return issue_tokens(user)
        
    except Exception as e:
        logger.error(f"Unexpected error during login for {email}: {str(e)}", exc_info=True)
        return Response(
            {"detail": "An unexpected error occurred."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

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
    email_body = render_to_string("emails/otp_email.html", email_context)
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
def signup_view(request):
    # Get user data from request
    # user_data = {
    #     "first_name": request.data.get("first_name"),
    #     "other_name": request.data.get("other_name"),
    #     "last_name": request.data.get("last_name"),
    #     "email": request.data.get("email"),
    #     "password": request.data.get("password"),
    #     "confirm_password": request.data.get("confirm_password"),
    #     "phone_number": request.data.get("phone_number"),
    #     # "is_verified": request.data.get("is_verified", False),
    # }
    serializer = CreateUserSerializer(data=request.data)
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
        email_body = render_to_string("emails/otp_email.html", email_context)
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
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email", "").lower().strip()
        logger.debug(f"Password reset request received for email: {email}")

        if not email:
            return Response(
                {"detail": "Email is required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            logger.warning(f"Password reset request: User not found for email {email}")
            # Return generic message to prevent email enumeration
            return Response(
                {"message": "If an account exists for this email, a password reset link has been sent."},
                status=status.HTTP_200_OK,
            )

        if not user.is_active:
            logger.warning(f"Password reset request: Account inactive for {user.email}")
            return Response(
                {"message": "If an account exists for this email, a password reset link has been sent."},
                status=status.HTTP_200_OK,
            )

        # Generate token and URL
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Use your frontend URL here (configured in settings)
        reset_path = reverse("password-reset-confirm", kwargs={"uidb64": uid, "token": token})
        reset_link = f"{settings.DOMAIN}{reset_path}"

        # Prepare email context
        email_context = {
            "user": user,
            "reset_link": reset_link,
            "domain": settings.DOMAIN,
            "protocol": "https",
        }

        try:
            email_body = render_to_string("emails/password_reset_email.html", email_context)
            send_mail(
                subject="Password Reset Request",
                message=f"Please click here to reset your password: {reset_link}",  # Plain text fallback
                html_message=email_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.info(f"Password reset email sent to {user.email}")
            return Response(
                {"message": "If an account exists for this email, a password reset link has been sent."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
            return Response(
                {"detail": "Failed to send password reset email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
