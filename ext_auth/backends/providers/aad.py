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
from ext_auth.keys import EXT_AUTH_AAD_AUTH_FLOW_KEY, EXT_AUTH_AAD_TOKEN_CACHE_KEY, EXT_AUTH_AAD_ACCESS_TOKEN_KEY
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

UserModel = get_user_model()

def load_token_cache(request):
    # Check for a token cache in the session
    cache = SerializableTokenCache()
    if request.session.get(EXT_AUTH_AAD_TOKEN_CACHE_KEY):
        cache.deserialize(
            request.session[EXT_AUTH_AAD_TOKEN_CACHE_KEY])

    return cache

def save_token_cache(request, cache):
    # If cache has changed, persist back to session
    if cache.has_state_changed:
        request.session[EXT_AUTH_AAD_TOKEN_CACHE_KEY] = cache.serialize()

def clear_session(request):
    """
    Clears the current users session data, which will force new auth
    """
    request.session.pop(EXT_AUTH_AAD_TOKEN_CACHE_KEY)

def has_external_auth(request) -> bool:
    return bool(request.session.get('user'))

def validate_user_dict(user_dict: dict) -> bool:
    return bool(user_dict.get('userPrincipalName'))

def get_sign_in_flow(request):
    backend = get_ext_auth_backend(request)
    return backend.get_sign_in_flow(request)

class TokenResult:
    access_token: str
    id_token_claims: dict

    def __init__(self, access_token, id_token_claims) -> None:
        self.access_token = access_token
        self.id_token_claims = id_token_claims


def get_token_result(request) -> Union[TokenResult, None]:
    backend = get_ext_auth_backend(request)
    if isinstance(backend, AzureADBackend):
        aad_backend: AzureADBackend = backend
        result = aad_backend.get_token_result(request)
        if result and EXT_AUTH_AAD_ACCESS_TOKEN_KEY in result:
            return TokenResult(result.get(EXT_AUTH_AAD_ACCESS_TOKEN_KEY), result.get("id_token_claims"))


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
            request.session[EXT_AUTH_AAD_AUTH_FLOW_KEY] = flow
        except Exception as e:
            print(e)
        # Redirect to the Azure sign-in page
        if 'next' in request.GET:
            request.session['ext_auth_next'] = request.GET['next']

        return flow['auth_uri']

    def ext_authenticate(self, request, **kwargs) -> dict:
        flow = request.session.pop(EXT_AUTH_AAD_AUTH_FLOW_KEY, {})
        if 'code' not in request.GET:
            raise AuthenticationException("Tried to authenticate, but auth code was not in request")
        try:
            result = self.get_token_from_code(request, flow)
            if EXT_AUTH_AAD_ACCESS_TOKEN_KEY in result:
                return self.get_ext_user(result)
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
            logger.error(f"Error response: {e}")
            raise AuthenticationException("Got value error while getting result from msal app...")

    def get_ext_user(self, token_response) -> dict:
        claims_key = "id_token_claims"
        if claims_key not in token_response:
            raise ValueError(f"Missing '{claims_key}' in token response")

        id_token_claims = token_response[claims_key]
        if 'email' not in id_token_claims:
            raise ValueError(f"Missing 'email' in id_token_claims")

        if 'oid' not in id_token_claims:
            raise ValueError(f"Missing 'oid' in id_token_claims")

        username = id_token_claims.get('oid')
        email = id_token_claims.get('email')
        return {
            'username': username,
            'email': email,
            'firstName': '',
            'lastName': '',
            'department': ''
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

    def get_token_result(self, request) -> Union[dict, None]:
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
            token = result.get(EXT_AUTH_AAD_ACCESS_TOKEN_KEY)
            if not token:
                logger.error("No token from acquire_token_silent...")
                auth_app.remove_account(accounts[0])
                clear_session(request)
                return

            # If everything went well, save the new state to session data
            save_token_cache(request, cache)
            return result
