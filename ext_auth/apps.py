from django.apps import AppConfig
import ext_auth.default_settings as defaults
from django.conf import settings


class ExtAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ext_auth'
    verbose_name = "Django External Authentication"

    def ready(self):
        for name in dir(defaults):
            if name.isupper() and not hasattr(settings, name):
                setattr(settings, name, getattr(defaults, name))
                print('setting ->', getattr(defaults, name), 'for ->', name)
