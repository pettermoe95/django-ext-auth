from ext_auth.backends.providers.aad import get_token_result
from django.contrib.auth import logout
from ext_auth.keys import EXT_AUTH_AAD_AUTH_FLOW_KEY
from ext_auth.views import auth_failed_error

def access_token_middleware(get_response):
    def middleware(request):
        # Before view is called
        # This check is so that we don't try to get access token before the user has authenticated
        # If the auth flow key is in the session it means authentication is in progress with auth code flow
        if request.user.is_authenticated and EXT_AUTH_AAD_AUTH_FLOW_KEY not in request.session:
            token_result = get_token_result(request)
            if not token_result:
                # If no access token is present we need to login again
                logout(request)
            elif token_result:
                request.access_token = token_result.access_token
                request.id_token_claims = token_result.id_token_claims
            else:
                return auth_failed_error()
        response = get_response(request)
        # After view is called

        return response

    return middleware
