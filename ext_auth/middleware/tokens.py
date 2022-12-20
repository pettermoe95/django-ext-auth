from ext_auth.backends.providers.aad import get_token
from django.contrib.auth import logout
from django.conf import settings

        
def graph_token_middleware(get_response):
    def middleware(request):
        # Before view is called
        token = get_token(request)
        if not token and settings.EXT_AUTH_AAD_AUTH_FLOW_KEY not in request.session:
            # If no access token is present we need to login again
            logout(request)

        request.graph_token = token

        response = get_response(request)
        # After view is called

        return response

    return middleware
