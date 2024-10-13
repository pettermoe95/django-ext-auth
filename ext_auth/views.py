from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from ext_auth.backends.ext_auth import get_ext_auth_backend, AuthenticationException
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


def sign_in(request):
    backend = get_ext_auth_backend(request)
    http_response_redirect = backend.init_auth(request)

    if 'next' in request.GET:
        request.session['ext_auth_next'] = request.GET['next']

    # Redirect to ext auth signin
    return http_response_redirect


@login_required
def sign_out(request):
    logout(request)
    return HttpResponseRedirect(reverse("home"))


def auth_failed_error() -> HttpResponse:
    html_content = b"<html><body><h1>Authentication failed...</h1></body></html>"
    return HttpResponse(html_content)


def callback(request):
    # callback with code received use it to authenticate the user
    try:
        user = authenticate(request)
        if not user:
            logger.error("Did not get a user dict back from auth backend...")
            return auth_failed_error()

        login(request, user)

        if 'ext_auth_next' in request.session:
            return HttpResponseRedirect(request.session.pop('ext_auth_next'))

        return HttpResponseRedirect(settings.EXT_AUTH_POST_LOGIN_REDIRECT_URI)
    except AuthenticationException as e:
        logger.error("Failed to authenticate in callback...")
        logger.error(e)
        return auth_failed_error()

