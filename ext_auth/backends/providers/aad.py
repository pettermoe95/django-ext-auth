from typing import Union
from msal import (
    SerializableTokenCache,
    ConfidentialClientApplication
)

from django.contrib.auth.models import User
from django.conf import settings

#import ext_auth.services.ms_graph as ms_graph
from ext_auth.services.ms_graph import get_graph_user
from ext_auth.backends.ext_auth import ExtAuthBackend, get_ext_auth_backend, AuthenticationException
from ext_auth.choices import ExternalAuthType
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

UserModel = get_user_model()

def load_token_cache(request):
    # Check for a token cache in the session
    cache = SerializableTokenCache()
    if request.session.get(settings.EXT_AUTH_AAD_TOKEN_CACHE_KEY):
        cache.deserialize(
            request.session[settings.EXT_AUTH_AAD_TOKEN_CACHE_KEY])

    return cache

def save_token_cache(request, cache):
    # If cache has changed, persist back to session
    if cache.has_state_changed:
        request.session[settings.EXT_AUTH_AAD_TOKEN_CACHE_KEY] = cache.serialize()

def clear_session(request):
    """
    Clears the current users session data, which will force new auth
    """
    request.session.pop(settings.EXT_AUTH_AAD_TOKEN_CACHE_KEY)

def has_external_auth(request) -> bool:
    return bool(request.session.get('user'))

def validate_user_dict(user_dict: dict) -> bool:
    return bool(user_dict.get('userPrincipalName'))

def get_sign_in_flow(request):
    backend = get_ext_auth_backend(request)
    return backend.get_sign_in_flow(request)

def get_token(request) -> str:
    backend = get_ext_auth_backend(request)

    return backend.get_token(request)


class AzureADBackend(ExtAuthBackend):
    """
    Implementation of Azure AD single tenant authentication
    """

    ext_auth_type = ExternalAuthType.AZURE_AD

    def get_redirect_uri(self, request) -> str:
         # Get the sign-in flow
        flow = get_sign_in_flow(request)
        # Save the expected flow, so we can use it in the callback
        try:
            request.session[settings.EXT_AUTH_AAD_AUTH_FLOW_KEY] = flow
        except Exception as e:
            print(e)
        # Redirect to the Azure sign-in page
        if 'next' in request.GET:
            request.session['ext_auth_next'] = request.GET['next']

        return flow['auth_uri']

    def ext_authenticate(self, request, **kwargs) -> dict:
        flow = request.session.pop(settings.EXT_AUTH_AAD_AUTH_FLOW_KEY, {})
        if 'code' not in request.GET:
            raise AuthenticationException("Tried to authenticate, but auth code was not in request")
        try:
            result = self.get_token_from_code(request, flow)
            if settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY in result:
                token = result.get(
                        settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY)
                return self.get_ext_user(request, token)
            elif 'error' in result:
                error_msg = f"""
                        Failed to authenticate using msal app: {result.get('error')} \n
                        Dict error result {result.__str__()}
                """
                raise AuthenticationException(error_msg)
            else:
                raise AuthenticationException("""No valid result, not error received,
                authentication not succesfull for unknown reason""")
        except ValueError as e:
            logger.error("Could not get token from code...")
            logger.error(e)
            raise AuthenticationException("Got value error while getting result from msal app...")

    def get_ext_user(self, request, token, **kwargs) -> dict:
        graph_user = get_graph_user(token)
        return {
            'username': graph_user.get('userPrincipalName'),
            'email': graph_user.get('userPrincipalName'),
            'firstName': graph_user.get('givenName'),
            'lastName': graph_user.get('surname'),
            'department': graph_user.get('department')
        }

    def client_id(self, request):
        return settings.EXT_AUTH_AAD_CLIENT_ID

    def client_secret(self, request):
        return settings.EXT_AUTH_AAD_CLIENT_SECRET

    def authority(self, request):
        return settings.EXT_AUTH_AAD_AUTH_AUTHORITY

    def get_msal_app(self, cache=None, request=None) -> ConfidentialClientApplication:
        # Initialize the MSAL confidential client
        auth_app = ConfidentialClientApplication(
            client_id=self.client_id(request),
            authority=self.authority(request),
            client_credential=self.client_secret(request),
            token_cache=cache)

        return auth_app

    def get_sign_in_flow(self, request):
        auth_app = self.get_msal_app(request=request)

        return auth_app.initiate_auth_code_flow(
            settings.EXT_AUTH_AAD_SCOPES,
            redirect_uri=settings.EXT_AUTH_AAD_REDIRECT_URI)

    # Method to exchange auth code for access token
    def get_token_from_code(self, request, flow):
        cache = load_token_cache(request)
        auth_app = self.get_msal_app(cache)
        # Get the flow saved in session
        result = auth_app.acquire_token_by_auth_code_flow(
            flow, request.GET)

        save_token_cache(request, cache)
        return result

    def get_token(self, request) -> Union[str, None]:
        cache = load_token_cache(request)
        auth_app = self.get_msal_app(cache)

        accounts = auth_app.get_accounts()
        if accounts:
            result = auth_app.acquire_token_silent(
                settings.EXT_AUTH_AAD_SCOPES,
                account=accounts[0])

            # This can happen for various reasons, error or token not present in cache
            if not result:
                logger.error("No result from acquire_token_silent...")
                auth_app.remove_account(accounts[0])
                clear_session(request)
                return

            # If for some weird reason, token is not in the validated dict
            token = result.get(settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY)
            if not token:
                logger.error("No token from acquire_token_silent...")
                auth_app.remove_account(accounts[0])
                clear_session(request)
                return

            # If everything went well, save the new state to session data
            save_token_cache(request, cache)
            return token
