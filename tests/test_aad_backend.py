from django.test import TestCase
from django.contrib.auth import get_user_model
from django.conf import settings
from unittest.mock import Mock, patch

from ext_auth.backends import ExtAuthBackend, AzureADBackend
from ext_auth.backends.ext_auth import get_ext_auth_backend
from ext_auth.models import UserProfile
from ext_auth.choices import ExternalAuthType
from ext_auth.services.ms_graph import get_graph_user

UserModel = get_user_model()

USER_DICT = {
    'userPrincipalName': 'johndoe@example.com',
    'givenName': 'John',
    'surname': 'Doe',
    'displayName': 'John Doe',
    'department': 'Sales'
}

class AzureADBackendTests(TestCase):

    @patch('ext_auth.backends.providers.aad.get_graph_user')
    def test_get_ext_user(self, mock_get_graph_user):
        # Set up the mock return value for the get_graph_user function
        mock_get_graph_user.return_value = USER_DICT

        # Call the get_ext_user function with the mock token
        result = AzureADBackend().get_ext_user(None, 'mock-token')
        expected_dict = {
            'username': USER_DICT.get('userPrincipalName'),
            'email': USER_DICT.get('userPrincipalName'),
            'firstName': USER_DICT.get('givenName'),
            'lastName': USER_DICT.get('surname'),
            'department': USER_DICT.get('department')
        }

        # Assert that the returned dictionary has the expected values
        self.assertEqual(result, expected_dict)

    def test_no_auth_callback_code(self):
        request = Mock()
        request.GET = {}
        result =AzureADBackend().ext_authenticate(request)
        self.assertEqual(result, None)
    
    @patch('ext_auth.backends.providers.aad.AzureADBackend.get_token_from_code')
    def test_ext_authenticate_no_access_token(self, mock_get_token_from_code):
        request = Mock()
        request.GET = {'code': 'supercode'}
        backend = AzureADBackend()
        result = backend.ext_authenticate(request)
        self.assertEqual(result, None)

    @patch('ext_auth.backends.providers.aad.AzureADBackend.get_token_from_code')
    def test_ext_authenticate_with_access_token(self, mock_get_token_from_code):
        request = Mock()
        request.GET = {'code': 'supercode'}
        token = 'supertoken'
        mock_get_token_from_code.return_value = {
            settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY: token
        }
        with patch('ext_auth.backends.providers.aad.AzureADBackend.get_ext_user') as mock_ext_user:
            expected_dict = {
                'username': USER_DICT.get('userPrincipalName'),
                'email': USER_DICT.get('userPrincipalName'),
                'firstName': USER_DICT.get('givenName'),
                'lastName': USER_DICT.get('surname'),
                'department': USER_DICT.get('department')
            }
            mock_ext_user.return_value = expected_dict
            result = AzureADBackend().ext_authenticate(request)
            self.assertEqual(result, expected_dict)
            mock_ext_user.assert_called_with(
                request,
                token
            )
