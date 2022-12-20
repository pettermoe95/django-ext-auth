from enum import Enum
from abc import ABC, abstractmethod

from django.contrib.auth import get_user_model, _get_backends
from django.conf import settings
from django.http import HttpResponseRedirect
from ext_auth.backends.providers.aad import AzureADProvider

from ext_auth.models import UserProfile

UserModel = get_user_model()

class ExtAuthProviders(Enum):
    AZURE_AD = 1

class ExtAuthBackend(ABC):
    """
    Protocol that defines a set of methods that needs
    to be implemented for evert external authentication
    provider.
    """

    ext_auth_type: UserProfile.ExternalAuthType

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
        ...

    def init_auth(self, request) -> HttpResponseRedirect:
        redirect = self.get_redirect_uri(request)
        return HttpResponseRedirect(redirect)

    def authenticate(self, request, username=None, password=None, **kwargs):

        self.ext_authenticate(request, **kwargs)
        user = self.get_user()
        if not self.user_exists():
            self.save_user(user)
        
        return user

    @abstractmethod
    def get_redirect_uri(request) -> str:
        ...

    @abstractmethod
    def ext_authenticate(self, request, **kwargs) -> str | None:
        """
        This method should handle authenticating the user.
        It is being called from the ModelBackend's own
        authenticate method, which again gets called on a redirect
        callback.

        If any further information is needed to get user info, save
        it as an attribute here, so it can be used in the get_user method,
        which is called after authentication.
        
        Optionally return access token from this method.
        """
        ...

    @abstractmethod
    def get_user(self, request, **kwargs):
        """
        Simply fetches the user from this authentication provider.
        """
        ...



def get_provider(request):
    ret_provider = None
    for provider in ExtAuthProviders:
        if provider == settings.EXT_AUTH_PROVIDER:
            match provider:
                case ExtAuthProviders.AZURE_AD:
                    ret_provider = AzureADProvider()
    return ret_provider

def get_ext_auth_backend(request) -> ExtAuthBackend:
    for backend, backend_path in _get_backends(return_tuples=True):
        if isinstance(backend, ExtAuthBackend):
            provider = get_provider(request)
            setattr(backend, 'provider', provider)
            return backend
