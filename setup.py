from setuptools import setup, find_packages
from pathlib import Path

__version__ = "2.0.1"

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()
setup(
    name="django-auth-providers",
    version=__version__,
    description=(
        "django-auth-providers is a django app that lets you"
        " authenticate to external authentication providers"
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="Petter Elenius Moe",
    author_email="pettermoe9530@gmail.com",
    url="https://github.com/pettermoe95/django-ext-auth/tree/main",
    packages=['ext_auth'] + ['ext_auth.' + pkg for pkg in find_packages('ext_auth')],
    install_requires=[
        'Django>=5.1',
        'msal>=1.31.0',
        'djangorestframework>=3.0.0',
        'requests>=2.32.3'
    ]
)
