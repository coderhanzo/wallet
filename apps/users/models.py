from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager
from phonenumber_field.modelfields import PhoneNumberField
from datetime import timedelta
from django.utils import timezone
# from django.core.exceptions import ValidationError
import random
import string

# Create your models here


def upload_to(instance, filename):
    return "profile/{filename}".format(filename=filename)


class User(AbstractUser):
    username = None

    class Roles(models.TextChoices):
        ADMIN = "ADMIN", _("Admin")
        IMAM = "IMAM", _("Imam")
        ASSCOCIATE = "ASSOCIATE", _("Associate")
        USER = "USER", _("User")

    # profile_pic = models.ImageField(
    #     _("Profile Picture"),
    #     upload_to=upload_to,
    #     blank=True,
    #     null=True,
    #     default="profile/default.jpg",
    # )
    first_name = models.CharField(verbose_name=_("First Name"), max_length=250)
    last_name = models.CharField(verbose_name=_("Last Name"), max_length=250)
    other_name = models.CharField(
        verbose_name=_("Other Name"), max_length=250, blank=True, null=True
    )
    email = models.EmailField(verbose_name=_("Email Address"), unique=True)
    phone_number = PhoneNumberField(
        verbose_name=_("Phone Number"),
        max_length=30,
        blank=True,
        null=True,
        unique=True,
    )
    roles = models.CharField(
        max_length=10,
        choices=Roles.choices,
        default=Roles.USER,
        verbose_name=_("User Roles"),
    )
    password = models.CharField(verbose_name=_("Password"), max_length=250)
    confirm_password = models.CharField(
        verbose_name=_("Confirm Password"), max_length=250
    )
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    is_verified = models.BooleanField(_("Is Verified"), default=False)
    # last_login = models.DateTimeField(_("Last Login"), auto_now=True)
    # verification_code = models.CharField(max_length=6, blank=True, null=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
        "phone_number",
    ]

    objects = CustomUserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def generate_otp_code(self):
        self.otp_code = "".join(random.choices(string.digits, k=6))
        self.otp_expiry = timezone.now() + timedelta(minutes=5)
        self.save()

    def verify_otp_code(self, otp):
        # is_valid = self.otp_code == otp and self.otp_expiry > datetime.now()
        if self.otp_code == otp and self.otp_expiry > timezone.now():
            self.is_verified = True
            self.otp_code = None
            self.otp_expiry = None
            self.save()
            return True
        return False

    def __str__(self):
        return f"{self.first_name} {self.other_name} {self.last_name}"

    @property
    def get_full_name(self):
        return f"{self.first_name} {self.other_name} {self.last_name}"
