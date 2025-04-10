from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenVerifyView

urlpatterns = [
    path("jwt/refresh/", views.refresh_token_view, name="jwt-refresh"),
    path("jwt/verify/", TokenVerifyView.as_view(), name="jwt-verify"),
    path("jwt/create/", views.login_view, name="login"),
    path("users/", views.signup_view, name="register"),
    path("users/me/", views.get_logged_in_user, name="get_logged_in"),
    path("users/logout/", views.logout_view, name="logout"),
    path("users/all/", views.get_all_users, name="get_all_users"),
    # path("password-reset/", views.custom_password_reset_view),
    # path("password-reset-confirm/", views.SetPassword.as_view()),
    path("delete/<int:id>", views.delete_user, name="delete_user"),
    path("update-profile/", views.UpdateProfileView.as_view(), name="update-profile"),
    path("verify-otp/", views.verify_otp_view, name="verify_otp"),
    path("request-new-otp/", views.request_new_otp_view, name="request-new-otp"),
    # path("users/filter/", views.GetUsersPerRole.as_view(), name="create_superadmin"),
]

