from abc import ABC, abstractmethod
import secrets
import string

from django.contrib.auth import get_user_model, _get_backends
from django.http import HttpResponseRedirect
from django.contrib.auth.backends import ModelBackend

from ext_auth.models import UserProfile
from ext_auth.choices import ExternalAuthType

UserModel = get_user_model()

def make_random_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


class AuthenticationException(Exception):
    pass


class ExtAuthBackend(ABC, ModelBackend):
    """
    Abstract Class that defines a set of methods that needs
    to be implemented for evert external authentication
    provider.
    """

    ext_auth_type: ExternalAuthType

    def create_user(self, username: str, email: str, **kwargs) -> UserModel:
        user = UserModel.objects.create_user(
            username=username,
            email=email,
            password=make_random_password(length=14)
        )
        user_profile = UserProfile(
            user=user,
            display_name=" ".join([user.first_name, user.last_name]),
            department="",
            ext_auth=self.ext_auth_type
        )
        self.save_user_profile(user_profile)
        return user
        

    def save_user_profile(self, user_profile: UserProfile) -> UserProfile:
        user_profile = user_profile.save()
        return user_profile

    def user_exists(self, email: str, **kwargs) -> bool:
        try:
            UserModel.objects.get(email=email)
            return True
        except UserModel.DoesNotExist:
            return False

    def init_auth(self, request) -> HttpResponseRedirect:
        redirect = self.get_redirect_uri(request)
        return HttpResponseRedirect(redirect)

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticates the user using ext auth backend
        Can raise a AuthenticationException
        """
        user_dict = self.ext_authenticate(request, **kwargs)
        if not user_dict or 'email' not in user_dict:
            raise AuthenticationException("Authentication did not return a valid user dict...")
        # user_dict should have username and email keys
        if not self.user_exists(user_dict.get('email')):
            user = self.create_user(
                user_dict.get('username'),
                user_dict.get('email')
            )
            return user

        return self.get_user_by_username(user_dict.get('username'))

    def get_user_by_username(self, username):
        try:
            user = UserModel._default_manager.get(username=username)
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None

    @abstractmethod
    def get_redirect_uri(request) -> str:
        ...

    @abstractmethod
    def ext_authenticate(self, request, **kwargs) -> dict:
        """
        This method should handle authenticating the user.
        It is being called from the ModelBackend's own
        authenticate method, which again gets called on a redirect
        callback.

        Should just return dict representation of the
        external authentication response:
        key: email
        key: username
        """
        ...

    @abstractmethod
    def get_ext_user(self, request, **kwargs) -> dict:
        """
        Simply fetches the user from this authentication provider.
        """
        ...


def get_ext_auth_backend(request, type: ExternalAuthType = None) -> ExtAuthBackend:
    for backend, backend_path in _get_backends(return_tuples=True):
        if isinstance(backend, ExtAuthBackend):
            if not type:
                return backend
            
            # If type spe
            if type == backend.ext_auth_type:
                return backend

