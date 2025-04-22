from django.db import models

# Create your models here.
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model

User = get_user_model()

class Currency(models.Model):
    """
    Model representing a currency.
    """
    CURRENCY=(
        ('USD', _('United States Dollar')),
        ('GBP', _('British Pound Sterling')),
        ('GHS', _('Ghana Cedis')),
        ('EUR', _('Euro')),
    )
    code = models.TextChoices(choices=CURRENCY ,max_length=3, unique=True)
    name = models.CharField(max_length=50, unique=True)
    symbol = models.CharField(max_length=5, unique=True)

    def __str__(self):
        return self.code


class Card(models.Model):
    """
    Model representing a card.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='cards')
    card_number = models.CharField(max_length=16, unique=True)
    expiry_date = models.DateField()
    cvv = models.CharField(max_length=3)
    currency = models.ForeignKey(Currency, on_delete=models.PROTECT)
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    def __str__(self):
        return f"{self.user.username}'s Card {self.card_number}"

class Wallet(models.Model):
    """
    Model representing a wallet.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='wallets')
    currency = models.ForeignKey(Currency, on_delete=models.CASCADE)
    card = models.ForeignKey(Card, on_delete=models.CASCADE, related_name='wallets')
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    def __str__(self):
        return f"{self.user.username}'s {self.currency.code} Wallet"