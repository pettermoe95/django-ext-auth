from msal import (
    SerializableTokenCache,
    ConfidentialClientApplication
)

from django.contrib.auth.models import User
from django.conf import settings

from ext_auth.services.ms_graph import get_graph_user
from ext_auth.backends.ext_auth import ExtAuthBackend, get_ext_auth_backend

from django.contrib.auth import get_user_model

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


def store_user(request, user):
    try:
        request.session['user'] = {
            'is_authenticated': True,
            'name': user['displayName'],
            'email': user['userPrincipalName'],
            'givenName': user['givenName'],
            'surname': user['surname'],
            'department': user['department'],
        }
    except Exception as e:
        print(e)


def get_user_by_email(email) -> User:
    return User.objects.get(email=email)


def has_external_auth(request) -> bool:
    return bool(request.session.get('user'))


def get_ext_user_from_session(session) -> dict:
    return session.get('user')


def validate_user_dict(user_dict: dict) -> bool:
    return bool(user_dict.get('userPrincipalName'))


def create_user_from_dict(user_dict: dict) -> User:
    user: User = User.objects.create_user(
        username=user_dict.get('userPrincipalName'),
        email=user_dict.get('userPrincipalName'),
        # Using a random password here, as it's needed
        password=User.objects.make_random_password(length=14)
    )
    return user


def get_user_from_dict(user_dict: dict) -> User:
    try:
        return User.objects.get(email=user_dict.get('userPrincipalName'))
    except UserModel.DoesNotExist:
        if validate_user_dict(user_dict):
            return create_user_from_dict(user_dict)

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
            print('LAGRER next i session', request.GET['next'])
            request.session['ext_auth_next'] = request.GET['next']
        
        return flow['auth_uri']

    def ext_authenticate(self, request, **kwargs):
        flow = request.session.pop(settings.EXT_AUTH_AAD_AUTH_FLOW_KEY, {})
        if 'code' not in request.GET:
            return

        result = self.get_token_from_code(request, flow)
        if settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY in result:
            token = result.get(
                    settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY)
            return self.get_ext_user(request, token)

        
    
    def get_ext_user(self, request, token, **kwargs):
        
        graph_user = get_graph_user(token)
        print('------------------ GRAPH USER -------------------')
        print(graph_user)
        return get_user_from_dict(graph_user)

    def client_id(self, request):
        return settings.EXT_AUTH_AAD_CLIENT_ID

    def client_secret(self, request):
        return settings.EXT_AUTH_AAD_CLIENT_SECRET

    def authority(self, request):
        return settings.EXT_AUTH_AAD_AUTH_AUTHORITY

    def get_msal_app(self, cache=None, request=None):
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
        result = auth_app.acquire_token_by_auth_code_flow(flow, request.GET)
        save_token_cache(request, cache)
        return result

    def get_token(self, request) -> str:
        cache = load_token_cache(request)
        auth_app = self.get_msal_app(cache)

        accounts = auth_app.get_accounts()
        if accounts:
            result = auth_app.acquire_token_silent(
                settings.EXT_AUTH_AAD_SCOPES,
                account=accounts[0])

            save_token_cache(request, cache)
            return result[settings.EXT_AUTH_AAD_ACCESS_TOKEN_KEY]