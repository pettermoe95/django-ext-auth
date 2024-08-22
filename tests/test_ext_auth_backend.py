from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch

from ext_auth.backends import ExtAuthBackend, AzureADBackend
import ext_auth.backends.ext_auth as ext_auth
from ext_auth.choices import ExternalAuthType

UserModel = get_user_model()

class TestBackend(ExtAuthBackend):
    ext_auth_type = -1

    def get_redirect_uri(request) -> str:
        ...

    def ext_authenticate(self, request, **kwargs) -> dict:
        ...

    def get_ext_user(self, request, **kwargs):
        ...

USER_DICT = {
    'userPrincipalName': 'johndoe@example.com',
    'givenName': 'John',
    'surname': 'Doe',
    'displayName': 'John Doe',
    'department': 'Sales'
}

class ExtAuthBackendTests(TestCase):

    @patch('ext_auth.backends.ext_auth._get_backends')
    def test_get_ext_auth_backend(self, mock_get_backends):
        
        request = Mock()
        backend = AzureADBackend()
        mock_get_backends.return_value = [(backend, Mock())]
        
        result = ext_auth.get_ext_auth_backend(request)
        self.assertEqual(result,backend)

    @patch('ext_auth.backends.ext_auth._get_backends')
    def test_get_specific_ext_auth_backend(self, mock_get_backends):
        request = Mock()

        aad_backend = AzureADBackend()
        test_backend = TestBackend()
        mock_get_backends.return_value = [(aad_backend, Mock()), (test_backend, Mock())]
        
        test_result = ext_auth.get_ext_auth_backend(request, -1)
        aad_result = ext_auth.get_ext_auth_backend(request, ExternalAuthType.AZURE_AD)
        none_result = ext_auth.get_ext_auth_backend(request, -2)
        self.assertEqual(aad_result, aad_backend)
        self.assertEqual(test_result, test_backend)
        self.assertEqual(none_result, None)
    
    def test_create_get_user(self):

        username = 'leomessi'
        email = 'leomessi@gmail.com' 

        aad_backend = AzureADBackend()
        result_user = aad_backend.create_user(username, email)
        self.assertEqual(result_user.username, username)
        self.assertEqual(result_user.email, email)
        
        get_user_result = aad_backend.get_user(result_user.id)
        self.assertEqual(get_user_result, result_user)

    def test_get_user_by_email(self):

        username = 'leomessi'
        email = 'leomessi@gmail.com' 
        aad_backend = AzureADBackend()

        aad_backend.create_user(username, email)

        get_user_by_username_result = aad_backend.get_user_by_username(username)
        self.assertEqual(get_user_by_username_result.username, username)
    
    @patch(
        'ext_auth.backends.providers.aad.'
        'AzureADBackend.ext_authenticate'
    )
    def test_authenticate(self, mock_ext_authenticate):
        request = Mock()
        aad_backend = AzureADBackend()
        mock_ext_authenticate.return_value = {
            'username': USER_DICT.get('userPrincipalName'),
            'email': USER_DICT.get('userPrincipalName'),
            'firstName': USER_DICT.get('givenName'),
            'lastName': USER_DICT.get('surname'),
            'department': USER_DICT.get('department')
        }
        with patch(
            'ext_auth.backends.ext_auth.ExtAuthBackend.create_user'
        ) as mock_create_user:
            aad_backend.authenticate(request)
            mock_create_user.assert_called_once()
            mock_create_user.assert_called_with(
                USER_DICT.get('userPrincipalName'),
                USER_DICT.get('userPrincipalName')
            )
    
    def test_create_get_user_profile(self):

        username = 'leomessi'
        email = 'leomessi@gmail.com' 

        aad_backend = AzureADBackend()
        result_user = aad_backend.create_user(username, email)
        self.assertEqual(result_user.userprofile.ext_auth, ExternalAuthType.AZURE_AD)

    def test_user_exists(self):
        username = 'leomessi'
        email = 'leomessi@gmail.com' 

        aad_backend = AzureADBackend()
        aad_backend.create_user(username, email)
        user_exists = aad_backend.user_exists(email)
        # Test that user exists
        self.assertEqual(user_exists, True)
        # Test that it does not exist
        user_does_not_exist = aad_backend.user_exists('shouldnotexist')
        self.assertEqual(user_does_not_exist, False)

    def test_random_password(self):
        pw = ext_auth.make_random_password()
        self.assertEqual(len(pw), 16)
