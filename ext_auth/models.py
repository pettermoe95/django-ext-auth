from django.contrib.auth.models import User
from django.db import models
from ext_auth.choices import ExternalAuthType

class UserProfile(models.Model):

    user: User = models.OneToOneField(User, on_delete=models.CASCADE)
    display_name = models.CharField(max_length=100, null=True, blank=True)
    department = models.CharField(max_length=100, null=True, blank=True)
    ext_auth = models.IntegerField(
        blank=True, null=True, choices=ExternalAuthType.choices, default=None)

    def __str__(self):
        return self.user.username
