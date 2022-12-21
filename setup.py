from setuptools import setup

__version__ = "1.0"

setup(
    name="django-ext-auth",
    version=__version__,
    description=(
        "djang-ext-auth is a django app that lets you"
        " authenticate to external authentication providers"
    ),
    author="Petter Elenius Moe",
    author_email="pettermoe9530@gmail.com",
    url="https://github.com/pettermoe95/django-ext-auth/tree/main",
    packages=('ext_auth',),
)