from abc import ABC, abstractmethod

from django.contrib.auth import get_user_model, _get_backends
from django.http import HttpResponseRedirect
from django.contrib.auth.backends import ModelBackend

from ext_auth.models import UserProfile
from ext_auth.choices import ExternalAuthType

UserModel = get_user_model()

class ExtAuthBackend(ABC, ModelBackend):
    """
    Protocol that defines a set of methods that needs
    to be implemented for evert external authentication
    provider.
    """

    ext_auth_type: ExternalAuthType

    def save_user(self, user: UserModel):
        user = user.save()
        user_profile = UserProfile(
            user,
            " ".join([user.first_name, user.last_name]),
            "",
            self.provider.ext_auth_type
        )
        self.save_user_profile(user_profile)
        

    def save_user_profile(self, user_profile: UserProfile):
        ...

    def user_exists(self, user: UserModel) -> bool:
        return True

    def init_auth(self, request) -> HttpResponseRedirect:
        redirect = self.get_redirect_uri(request)
        return HttpResponseRedirect(redirect)

    def authenticate(self, request, username=None, password=None, **kwargs):

        user = self.ext_authenticate(request, **kwargs)
        if not self.user_exists(user):
            self.save_user(user)
        
        return user

    @abstractmethod
    def get_redirect_uri(request) -> str:
        ...

    @abstractmethod
    def ext_authenticate(self, request, **kwargs) -> UserModel:
        """
        This method should handle authenticating the user.
        It is being called from the ModelBackend's own
        authenticate method, which again gets called on a redirect
        callback.
        """
        ...

    @abstractmethod
    def get_ext_user(self, request, **kwargs):
        """
        Simply fetches the user from this authentication provider.
        """
        ...


def get_ext_auth_backend(request) -> ExtAuthBackend:
    for backend, backend_path in _get_backends(return_tuples=True):
        if isinstance(backend, ExtAuthBackend):
            return backend
