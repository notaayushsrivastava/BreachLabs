"""Django settings for django_store project.

INTENTIONALLY VULNERABLE DEMO TARGET FOR BREACHLABS.
Local demonstration use only — never deploy to production.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Vulnerability: Hardcoded production secret key (BL-SAST-007) ---
SECRET_KEY = 'django-insecure-hardcoded-secret-key-9876543210-do-not-use-in-prod'

# --- Vulnerability: Debug mode enabled in application (BL-SAST-004) ---
DEBUG = True

# --- Vulnerability: Permissive host policy ---
ALLOWED_HOSTS = ['*']

# --- Vulnerability: Permissive CORS policy (BL-SAST-005) ---
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_store',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # Note: CSRF middleware deliberately omitted for certain endpoints to demonstrate CSRF risks
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

ROOT_URLCONF = 'django_store.urls'

TEMPLATES = [
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
]

WSGI_APPLICATION = 'django_store.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
