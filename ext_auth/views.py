from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from ext_auth.backends.ext_auth import get_ext_auth_backend


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


def callback(request):
    # callback with code received use it to authenticate the user
    user = authenticate(request)
    if user:
        login(request, user)

    if 'ext_auth_next' in request.session:
        return HttpResponseRedirect(request.session.pop('ext_auth_next'))

    return HttpResponseRedirect(settings.EXT_AUTH_POST_LOGIN_REDIRECT_URI)
