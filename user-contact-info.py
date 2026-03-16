#!/usr/bin/env python3

import csv
import sys
from time import sleep
import comanage_utils as utils

OSPOOL_USERS_ACTIVE_ID = 204
AP40_LOGIN_ID = 3442
AP41_LOGIN_ID = 7731
AP42_LOGIN_ID = 4121
AP43_LOGON_ID = 7733


ENDPOINT = "https://registry.cilogon.org/registry/"
USER = "co_7.script_testing"
PASSFILE = "./passfile.txt"
LDAP_SERVER = "ldaps://ldap.cilogon.org"
LDAP_USER = "uid=readonly_user,ou=system,o=OSG,o=CO,dc=cilogon,dc=org"
OSG_CO_ID = 7
UNIX_CLUSTER_ID = 1
LDAP_TARGET_ID = 6

OUTFILE = "./ospool_users_info.csv"

def person_id_from_group_mem(group_member_dict):
    return group_member_dict["Person"]["Id"]

def member_pids_from_gid(gid, auth_str):
    group_members = utils.get_co_group_members(gid, ENDPOINT, auth_str)
    return {person_id_from_group_mem(group_member) for group_member in group_members["CoGroupMembers"]}

def main(args):
    contact_info = []

    user, passwd = utils.getpw(USER, None, PASSFILE)
    auth_str = utils.mkauthstr(user, passwd)
    
    active_users_members =  member_pids_from_gid(OSPOOL_USERS_ACTIVE_ID, auth_str)
    ap40_members =  member_pids_from_gid(AP40_LOGIN_ID, auth_str)
    ap41_members =  member_pids_from_gid(AP41_LOGIN_ID, auth_str)
    ap42_members =  member_pids_from_gid(AP42_LOGIN_ID, auth_str)
    ap43_members =  member_pids_from_gid(AP43_LOGON_ID, auth_str)

    ap_users = set.union(ap40_members, ap41_members, ap42_members, ap43_members)
    ospool_users = active_users_members.intersection(ap_users)
    
    max_names = 1
    max_emails = 1
    max_orgs = 1

    #ospool_users = list(ospool_users)[0:20]

    for group_member in ospool_users:
        user_identifiers = utils.get_co_person_identifiers(group_member, ENDPOINT, auth_str)["Identifiers"]
        user_username = utils.identifier_from_list(user_identifiers, "osguser")
        if user_username is None:
            print(f"skipping user id {group_member}")
            continue
        user_co_person = utils.core_api_co_person_read(user_username, OSG_CO_ID, ENDPOINT, auth_str)

        user_names = {f"{email["given"]} {email["family"]}" for email in user_co_person["Name"]}
        max_names = max(max_names, len(user_names))

        user_emails = {email["mail"].lower() for email in user_co_person["EmailAddress"]}
        max_emails = max(max_emails, len(user_emails))

        user_orgs = {email["o"] for email in user_co_person["OrgIdentity"]}
        max_orgs = max(max_orgs, len(user_orgs))


        user_data = {"Names" : user_names, "Emails" : user_emails, "Organizations" : user_orgs}

        contact_info.append(user_data)

    with open(OUTFILE, "w", newline="") as outfile:
        writer = csv.writer(outfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)

        writer.writerow(["Names"] + [""] * (max_names -1) + ["Emails"] + [""] * (max_emails -1) + ["Organizations"] + [""] * (max_orgs -1))
        for contact in contact_info:
            empty_name_cols = max_names - len(contact["Names"])
            names_list = list(contact["Names"]) + ([""] * empty_name_cols)

            empty_email_cols =  max_emails - len(contact["Emails"])
            emails_list = list(contact["Emails"]) + ([""] * empty_email_cols)

            empty_org_cols = max_orgs - len(contact["Organizations"])
            orgs_list = list(contact["Organizations"]) + ([""] * empty_org_cols)

            row =  names_list + emails_list + orgs_list
            writer.writerow(row)
            outfile.flush()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as e:
        sys.exit(e)
