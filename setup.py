from setuptools import setup, find_packages
from pathlib import Path

__version__ = "1.0.8"

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
)
