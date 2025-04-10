from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager
from datetime import timedelta
from django.utils import timezone
import random
import string


class User(AbstractUser):
    username = None  # Remove username
    email = models.EmailField(verbose_name=_("Email Address"), unique=True)

    first_name = models.CharField(verbose_name=_("First Name"), max_length=250)
    last_name = models.CharField(verbose_name=_("Last Name"), max_length=250)
    other_name = models.CharField(
        verbose_name=_("Other Name"), max_length=250, blank=True, null=True
    )
    phone_number = models.CharField(
        verbose_name=_("Phone Number"),
        max_length=30,
        blank=True,
        null=True,
        unique=True,
    )
    password = models.CharField(verbose_name=_("Password"), max_length=250)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    is_verified = models.BooleanField(_("Is Verified"), default=False)
    created_at = models.DateTimeField(_("Date Joined"), auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name", "phone_number"]

    objects = CustomUserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ["-date_joined"]

    def generate_otp_code(self):
        self.otp_code = "".join(random.choices(string.digits, k=6))
        self.otp_expiry = timezone.now() + timedelta(minutes=5)
        self.save()

    def verify_otp_code(self, otp):
        if self.otp_code == otp and self.otp_expiry > timezone.now():
            self.is_verified = True
            self.otp_code = None
            self.otp_expiry = None
            self.save()
            return True
        return False

    @property
    def get_full_name(self):
        return f"{self.first_name} {self.other_name or ''} {self.last_name}".strip()

    def __str__(self):
        return self.get_full_name
