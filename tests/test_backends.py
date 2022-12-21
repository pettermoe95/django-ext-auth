from django.test import TestCase
from unittest.mock import Mock, patch

from ext_auth.backends.ext_auth import ExtAuthBackend, get_ext_auth_backend
from ext_auth.models import UserProfile

class ExtAuthBackendTests(TestCase):
    def test_save_user(self):
        # Create a mock ExtAuthBackend instance
        ext_auth_backend = Mock(ExtAuthBackend)

        # Create a mock user instance
        user = Mock()
        user.save.return_value = user
        user.first_name = "John"
        user.last_name = "Doe"

        # Create a mock user profile instance
        user_profile = Mock()
        user_profile.user = user

        # Set the return value of the save_user_profile method to the user_profile instance
        ext_auth_backend.save_user_profile.return_value = user_profile

        # Call the save_user method
        returned_user_profile = ext_auth_backend.save_user(user)

        # Assert that the save_user_profile method was called with the correct arguments
        ext_auth_backend.save_user_profile.assert_called_with(
            UserProfile(
                user, "John Doe", "", ext_auth_backend.ext_auth_type
            )
        )

        # Assert that the correct user profile instance is returned
        self.assertEqual(returned_user_profile, user_profile)

    def test_get_ext_auth_backend(self):
        # Create a mock request object
        request = Mock()

        # Patch the _get_backends function to return a list of mock backends
        with patch("ext_auth_backend._get_backends", return_value=[Mock(), Mock()]) as mock_get_backends:
            # Call the get_ext_auth_backend function with the mock request object
            ext_auth_backend = get_ext_auth_backend(request)

            # Assert that the _get_backends function was called with the correct arguments
            mock_get_backends.assert_called_with(request=request, return_tuples=True)

            # Assert that the returned backend is an instance of ExtAuthBackend
            self.assertIsInstance(ext_auth_backend, ExtAuthBackend)
