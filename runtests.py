#!/usr/bin/env python
import os
import sys

import django
from django.conf import settings
from django.core.management import call_command

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}

default_settings = {
    'DATABASES': DATABASES,
    'INSTALLED_APPS': [
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'django.contrib.sites',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.admin.apps.SimpleAdminConfig',
        'django.contrib.staticfiles',
        'ext_auth',
    ],
    'ROOT_URLCONF': '',  # tests override urlconf, but it still needs to be defined
    'LOGIN_URL': '/auth/signin',
    'AUTHENTICATION_BACKENDS': [
        'django.contrib.auth.backends.ModelBackend',
        'ext_auth.backends.AzureADBackend'
    ],
    'MIDDLEWARE': [
        'django.middleware.security.SecurityMiddleware',
        'whitenoise.middleware.WhiteNoiseMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        "corsheaders.middleware.CorsMiddleware",
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'ext_auth.middleware.tokens.access_token_middleware',
        'portal.middleware.extend_user_attr_middleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ],
    'TEMPLATES': [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
            'APP_DIRS': True,
            'OPTIONS': {
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        },
    ],
}


def runtests():
    if not settings.configured:
        # Choose database for settings

        # Configure test environment
        settings.configure(
            **default_settings
        )

    if django.VERSION >= (4, 0):
        django.setup()
    failures = call_command(
        'test', 'tests', interactive=False, failfast=False, verbosity=2)

    sys.exit(bool(failures))


if __name__ == '__main__':
    runtests()
