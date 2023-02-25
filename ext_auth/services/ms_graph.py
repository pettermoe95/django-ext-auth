import requests
from itertools import chain
from django.conf import settings
graph_url = "https://graph.microsoft.com/v1.0"


def has_advanced_user_info():
    return "user.read.all" in settings.EXT_AUTH_AAD_SCOPES


def get_user_query_params():
    if has_advanced_user_info():
        return "displayName,userPrincipalName,profilePhoto,department,givenName,surname"
    return "displayName,userPrincipalName"


def get_graph_user(token) -> dict:
    # Send GET to /me
    user = requests.get(
        "{0}/me".format(graph_url),
        headers={"Authorization": "Bearer {0}".format(token)},
        params={
            "$select": get_user_query_params()},
    )
    # Return the JSON result
    json_user = user.json()
    return json_user


def get_all_users(token):
    users = []
    next_link = f"{graph_url}/users"
    params = {"$select": get_user_query_params()}
    while next_link:
        new_users = requests.get(
            next_link,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        ).json()

        next_link = new_users.get("@odata.nextLink")
        users = chain(users, new_users.get("value", []))
        params = None

    return list(users)


def id_in_group(token, guid):
    response = requests.get(
        "{0}/me/memberOf".format(graph_url),
        headers={"Authorization": "Bearer {0}".format(token)},
        params={"$filter": "id eq '" + guid + "'"},
    )

    if "value" in response.json():
        for value in response.json()["value"]:
            if "id" in value:
                if value["id"] == guid:
                    return True

    return False


def get_profile_pic(token):
    profile_picture = requests.get(
        "{0}//me/photo/$value".format(graph_url),
        headers={"Authorization": "Bearer {0}".format(token)},
        params={},
    )
    return profile_picture


def get_graph_user_by_email(token, email) -> dict:
    # Send GET to /me
    user = requests.get(
        "{0}/users('{1}')".format(graph_url, email),
        headers={"Authorization": "Bearer {0}".format(token)},
        params={
            "$select": get_user_query_params()},
    )
    # Return the JSON result
    json_user = user.json()
    return json_user


def user_in_group(token, guid):
    if guid is None:
        return False

    response = requests.get(
        '{0}/me/memberOf'.format(graph_url),
        headers={
            'Authorization': 'Bearer {0}'.format(token)
        },
        params={
            '$filter': "id eq '" + guid + "'"
        })

    for value in response.json().get('value', []):
        if value.get('id', None) == guid:
            return True

    return False
