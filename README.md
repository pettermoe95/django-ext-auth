# django-ext-auth
Django Ext Auth is a package that lets you integrate external authentication providers into your django project.

---
# Overview
If you want to enable authentication against against Azure AD, Google and more, fully compatible with the django authentication backend and session system, this is the package for you.

## Supported providers
- [X] Azure AD (single tenant)
- [ ] Azure AD (multi tenant)
- [ ] Google
- [ ] Facebook
- [ ] Vipps
- [ ] BankID

# Requirements
Python 3.12, 3.11, 3.10, 3.9
Django 5.1 <= 4.0

I have not tested lower versions of django and python, so it might be compatible with more versions.

# Installation
This is not yet available in pip, so you need to manually clone the repo/download this package.

Place the package in your django project, side by side with your other django apps.

## Installed Apps
Add ´ext_auth´ to your INSTALLED_APPS in your settings.py:
```python
INSTALLED_APPS = [
    ...
    'ext_auth',
    ...
]
```
## Middleware
It is also important to add the ´graph_token_middleware´, somewhere after the Session and Authentication middleware:
```python
MIDDLEWARE = [
    ...
    'django.contrib.sessions.middleware.SessionMiddleware',
    ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'ext_auth.middleware.tokens.graph_token_middleware',
]
```
## AzureADBackend
Now add the AzureADBackend to your AUTHENTICATION_BACKENDS:
```python
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'ext_auth.backends.AzureADBackend'
]
```

## Urls
ext_auth comes with a sign_in view. For it to work you need to include the urls and set LOGIN_URL.
setting the urls:
```python
urlpatterns = [
    ...
    path('admin', admin_site.urls),
    path('auth/', include('ext_auth.urls')),
    ...
]
```

set the LOGIN_URL in settings.py:
```python
LOGIN_URL = '/auth/signin'
```

## Secrets
Finally we need to set some values in the django settings to be able to contact your provider and complete authentications:
### Azure AD
```python
EXT_AUTH_AAD_CLIENT_ID = 'XXXXX-XXXXX-XXXXX-XXXXXX' # The ´Client ID´ for your Azure AD App Registration
EXT_AUTH_AAD_TENANT_ID = 'XXXXX-XXXXX-XXXXX-XXXXXX' # Your Azure AD ´Tenant ID´
EXT_AUTH_AAD_AUTH_AUTHORITY = f"https://login.microsoftonline.com/{EXT_AUTH_AAD_TENANT_ID}" # For single tenant 
EXT_AUTH_AAD_REDIRECT_URI = '/auth/callback' # Should be the path to you callback view
EXT_AUTH_AAD_CLIENT_SECRET = XXXXXXXXXXXXXXXXXXXXX # The client secret from your Azure App Registration
EXT_AUTH_POST_LOGIN_REDIRECT_URI = '/home' # The url that the user will be sent back to after auth is finished
EXT_AUTH_AAD_SCOPES = ["user.read"] # The scoped permissions you want your user to have. user.read is needed to get user data.
```
