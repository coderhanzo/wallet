# admin.py (Refactored)
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html # For potential future image display

from .forms import CustomUserChangeForm, CustomUserCreationForm
from .models import User

# Unregister the default Group model if you're not using it extensively with Unfold
# from django.contrib.auth.models import Group
# admin.site.unregister(Group)

@admin.register(User) # Use decorator for registration
class UserAdmin(BaseUserAdmin):
    ordering = ["last_name", "first_name", "email"] # Add more for consistency
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = User
    list_display = [
        "id",
        "email",
        "first_name",
        "last_name",
        "is_staff", # Important flag
        "is_verified",
        "is_active",
        "date_joined", # Show join date
    ]
    list_display_links = ["id", "email"]
    list_filter = [
        "is_staff",
        "is_superuser",
        "is_active",
        "is_verified",
        "date_joined", # Filter by date
        # Add 'roles' here if implemented
    ]
    # Keep standard fieldsets, but ensure they match your model
    # Make sure 'email' is the first field as it's the USERNAME_FIELD
    fieldsets = (
        (None, {"fields": ("email", "password")}), # Password field handled by Django Admin
        (_("Personal info"), {"fields": ("first_name", "last_name", "other_name", "phone_number")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_verified", # Add custom field
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        # Add roles fieldset if implemented
        # (_("Roles"), {"fields": ("roles",)}),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    # Add form fieldsets should reflect the fields in CustomUserCreationForm
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                 # Match fields in CustomUserCreationForm + password fields
                "fields": ("email", "first_name", "last_name", "other_name", "phone_number", "password", "password2"),
            },
        ),
    )
    search_fields = ["email", "first_name", "last_name", "phone_number"]
    readonly_fields = ["last_login", "date_joined"] # Standard readonly fields

