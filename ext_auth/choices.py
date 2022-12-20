from django.db import models

class ExternalAuthType(models.IntegerChoices):
        AZURE_AD = 1, "AZURE_AD"