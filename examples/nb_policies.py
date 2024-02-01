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

def nb_update_policy_ecmsiteamssms(policy_key, app_integration_key, group_id_list, print_response=False):
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



def main():

    # Update the Timezone
    admin_api.update_settings(timezone="US/Eastern")

    # Create the ECMSI TEAMS SMS policy
    policy_key_ecmsiTeamsSMS = nb_create_policy_ecmsiteamssms("ECMSI TEAMS SMS")
    print(policy_key_ecmsiTeamsSMS)
    print('Created ECMSI Teams SMS Policy')

    # Create the Admin Group
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


    # Create Protected Applications ==============================================
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
    print('Created the Protected Applications')


    # Apply the ECMSI TEAMS SMS group policy to the Protected Applications
    group_id_list = [group_id_value]
    policy_key = policy_key_ecmsiTeamsSMS
    response = admin_api.get_integrations()
    app_integration_keys = [entry["integration_key"] for entry in response]
    for app_integration_key in app_integration_keys:
        update_policies_ecmsiteamssms = nb_update_policy_ecmsiteamssms(policy_key, app_integration_key, group_id_list)
    print('Applied the ECMSI TEAMS SMS group policy to the Portected Applications')

    Print('=== Automation Complete! ===')
  


if __name__ == "__main__":
    main()

