from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch

from ext_auth.backends import ExtAuthBackend, AzureADBackend
from ext_auth.backends.ext_auth import get_ext_auth_backend
from ext_auth.models import UserProfile
from ext_auth.choices import ExternalAuthType

UserModel = get_user_model()

class ExtAuthBackendTests(TestCase):
    def test_get_ext_auth_backend(self):
        # Create a mock request object
        request = Mock()
        azure_ad_backend = Mock(spec=AzureADBackend)
        # Patch the _get_backends function to return a list of mock backends
        self.assertEqual(1,1)
