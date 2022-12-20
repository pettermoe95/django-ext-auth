from ext_auth.backends.providers.aad import get_token


def graph_token_middleware(get_response):
    def middleware(request):
        # Before view is called
        token = get_token(request)
        request.graph_token = token

        response = get_response(request)
        # After view is called

        return response

    return middleware
