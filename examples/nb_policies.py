#!/usr/bin/env python
import sys
import json
import duo_client
import pprint
# from six.moves import input


argv_iter = iter(sys.argv[1:])

'''
def get_next_arg(prompt):
    try:
        return next(argv_iter)
    except StopIteration:
        return input(prompt)

=
admin_api = duo_client.Admin(
    ikey=get_next_arg('Admin API integration key ("DI..."): '),
    skey=get_next_arg("integration secret key: "),
    host=get_next_arg('API hostname ("api-....duosecurity.com"): '),
)
'''
admin_api = duo_client.Admin(
    ikey=('DI49RFWHV1YAQM6V9AWH'),
    skey=('FBmUWStvquGpX9AS74rLg9qo5z5Q2odw7YRgyF8X'),
    host=('api-b4801a5f.duosecurity.com'),
)

def create_empty_policy(name, print_response=False):
    """
    Create an empty policy with a specified name.
    """

    json_request = {
        "policy_name": name,
    }
    response = admin_api.create_policy_v2(json_request)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    return response.get("policy_key")


def create_policy_browsers(name, app_integration_key, group_id_list, print_response=False):
    """
    Create a policy that blocks internet explorer browsers. Requires
    Access or Beyond editions.
    """

    json_request = {
        "policy_name": name,
        "sections": {
            "browsers": {
                "blocked_browsers_list": [
                    "ie",
                ],
            },
        },
    }
    response = admin_api.create_policy_v2(json_request)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    return response.get("policy_key")

def nb_create_policy_ecmsiteamssms(name, print_response=False):
    """
    Creates the ECMSI TEAMS SMS policy
    """

    json_request = {
        "policy_name": name,
        "sections": {
            "authentication_methods": {
                "allowed_auth_list": [
                    "hardware-token",
                    "sms",
                    "duo-passcode",
                    
                ],
                "blocked_auth_list": [
                    "webauthn-platform",
                    "webauthn-roaming",
                    "duo-push",
                    "phonecall",
                
                ],
            },
        },
    }

    response = admin_api.create_policy_v2(json_request)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    return response.get("policy_key")

def nb_update_policy_ecmsiteamssms(policy_key, app_integration_key, group_id_list, print_response=True):
    """
    Applies the ECMSI TEAMS SMS policy to all applications
    """

    json_request = {
        "apply_to_groups_in_apps": {
            "apply_group_policies_list": [
                {
                    "app_integration_key": app_integration_key,
                    "group_id_list": group_id_list,
                }
            ]
        }
    }

    response = admin_api.update_policy_v2(policy_key, json_request)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    return response.get("policy_key")

def nb_create_group_admingroup(name, print_response=False):
    """
    Creates the Admin Group
    """
    response = admin_api.create_group(name)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    return response.get("policy_key")

def copy_policy(name1, name2, copy_from, print_response=False):
    """
    Copy the policy `copy_from` to two new policies.
    """
    response = admin_api.copy_policy_v2(copy_from, [name1, name2])
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    policies = response.get("policies")
    return (policies[0].get("policy_key"), policies[1].get("policy_key"))

def bulk_delete_section(policy_keys, print_response=False):
    """
    Delete the section "browsers" from the provided policies.
    """
    response = admin_api.update_policies_v2("", ["browsers"], policy_keys)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)

def update_policy_with_device_health_app(policy_key, print_response=False):
    """
    Update a given policy to include Duo Device Health App policy
    settings. Requires Access or Beyond editions.
    """

    json_request = {
        "sections": {
            "device_health_app": {
                "enforce_encryption": ["windows"],
                "enforce_firewall": ["windows"],
                "prompt_to_install": ["windows"],
                "requires_DHA": ["windows"],
                "windows_endpoint_security_list": ["cisco-amp"],
                "windows_remediation_note": "Please install Windows agent",
            },
        },
    }
    response = admin_api.update_policy_v2(policy_key, json_request)
    if print_response:
        pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
        print(pretty)
    return response.get("policy_key")


def get_policy(policy_key):
    """
    Fetch a given policy.
    """

    response = admin_api.get_policy_v2(policy_key)
    pretty = json.dumps(response, indent=4, sort_keys=True, default=str)
    print(pretty)


def iterate_all_policies():
    """
    Loop over each policy.
    """

    print("#####################")
    print("Iterating over all policies...")
    print("#####################")
    iter = sorted(
        admin_api.get_policies_v2_iterator(), key=lambda x: x.get("policy_name")
    )
    for policy in iter:
        print(
            "##################### {} {}".format(
                policy.get("policy_name"), policy.get("policy_key")
            )
        )
        pretty = json.dumps(policy, indent=4, sort_keys=True, default=str)
        print(pretty)

def check_variable_type(variable, variable_name):
    if isinstance(variable, list):
        print(f"{variable_name} is a list.")
    elif isinstance(variable, dict):
        print(f"{variable_name} is a dictionary.")
    else:
        print(f"{variable_name} is neither a list nor a dictionary.")


def main():

    '''
    # Create two empty policies
    policy_key_a = create_empty_policy("Test New Policy - a")
    policy_key_b = create_empty_policy("Test New Policy - b")

    # Update policy with Duo Device Health App settings.
    update_policy_with_device_health_app(policy_key_b)

    # Create an empty policy and delete it.
    policy_key_c = create_empty_policy("Test New Policy - c")
    admin_api.delete_policy_v2(policy_key_c)

    # Create a policy with browser restriction settings.
    policy_key_d = create_policy_browsers("Test New Policy - d")

    # Copy a policy to 2 new policies.
    policy_key_e, policy_key_f = copy_policy("Test New Policy - e", "Test New Policy - f", policy_key_d)

    # Delete the browser restriction settings from 2 policies.
    bulk_delete_section([policy_key_e, policy_key_f])

    # Fetch the global and other custom policy.
    get_policy("global")
    get_policy(policy_key_b)

    # Loop over each policy.
    iterate_all_policies()
    '''

    # Create ECMSI TEAMS SMS
    policy_key_ecmsiTeamsSMS = nb_create_policy_ecmsiteamssms("ECMSI TEAMS SMS")
    print(policy_key_ecmsiTeamsSMS)
    print('Created ECMSI Teams SMS Policy')

    # Create Admin Group
    create_admingroup = nb_create_group_admingroup("Admin Group")
    print('Created the Admin Group')
    
    # Get Admin Group Group ID
    get_ecmsi_admin_groupid = admin_api.get_groups()
    desired_group_name = 'Admin Group'
    group_id_value = None  # Initialize the variable outside the loop
    # Check if the list is not empty before searching
    if get_ecmsi_admin_groupid:
        # Iterate through the list of dictionaries
        for group_info in get_ecmsi_admin_groupid:
            if group_info.get('name') == desired_group_name:
                group_id_value = group_info['group_id']
                print(f"Group ID for '{desired_group_name}': {group_id_value}")
                break  # Exit the loop once the desired group is found
        else:
            print(f"No group with the name '{desired_group_name}' found.")
    else:
        print("No groups found.")


    # Create User Accounts, add phone object for ECMSI Teams MFA Number
    USERNAMES = ["helpdesk1", "helpdesk2", "administrator", "probe"]
    ECMSI_TEAMS_NUMBER = '3305363581'
    PHONE_TYPE = 'mobile'

    # Create and return a new phone object.
    phone = admin_api.add_phone(
        number=ECMSI_TEAMS_NUMBER,
        type=PHONE_TYPE,
    )
    # print('Created phone:')
    # pprint.pprint(phone)

    # Create and return a new user object.
    for USERNAME in USERNAMES:
        user = admin_api.add_user(
            username=USERNAME,
            realname=USERNAME,
        )
        print('Created user: ', USERNAME)
        # pprint.pprint(user)

        # Associate the user with the phone.
        admin_api.add_user_phone(
            user_id=user['user_id'],
            phone_id=phone['phone_id'],
        )
        print('Added phone', phone['number'], 'to user', user['username'])

        # Add the users to the group

        add_to_admin_group = admin_api.add_user_group(
            user_id=user['user_id'],
            group_id=group_id_value
        )


    # Create Applications ==============================================
    rdp_integration = admin_api.create_integration(
    name='Microsoft RDP',
    integration_type='rdp',
    username_normalization_policy='Simple',
    )
    rdp_server_integration = admin_api.create_integration(
    name='Microsoft RDP - Servers',
    integration_type='rdp',
    username_normalization_policy='Simple',
    )
    passportal_websdk_integration = admin_api.create_integration(
    name='Passportal - Web SDK',
    integration_type='websdk',
    username_normalization_policy='Simple',
    )
    passportal_authapi_integration = admin_api.create_integration(
    name='Passportal - Auth API',
    integration_type='authapi',
    username_normalization_policy='Simple',
    )
    print('Created Application integrations')

    group_id_list = [group_id_value]
    policy_key = policy_key_ecmsiTeamsSMS
    response = admin_api.get_integrations()
    app_integration_keys = [entry["integration_key"] for entry in response]
    for app_integration_key in app_integration_keys:
        update_policies_ecmsiteamssms = nb_update_policy_ecmsiteamssms(policy_key, app_integration_key, group_id_list)



if __name__ == "__main__":
    main()

