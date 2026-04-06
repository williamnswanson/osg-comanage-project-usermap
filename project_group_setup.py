#!/usr/bin/env python3.11

import os
import sys
import getopt
import comanage_utils as utils

SCRIPT = os.path.basename(__file__)
ENDPOINT = "https://registry.cilogon.org/registry/"
OSG_CO_ID = 7
UNIX_CLUSTER_ID = 1
LDAP_TARGET_ID = 6

OSPOOL_PROJECT_PREFIX_STR = "Yes-"
PROJECT_GIDS_START = 200000


_usage = f"""\
usage: [PASS=...] {SCRIPT} [OPTIONS]

OPTIONS:
  -u USER[:PASS]      specify USER and optionally PASS on command line
  -c OSG_CO_ID        specify OSG CO ID (default = {OSG_CO_ID})
  -g CLUSTER_ID       specify UNIX Cluster ID (default = {UNIX_CLUSTER_ID})
  -l LDAP_CONFIG_PATH specify path to LDAP Config file for fallback-search servers
  -t LDAP_TARGET      specify LDAP Provsion ID (defult = {LDAP_TARGET_ID})
  -d passfd           specify open fd to read PASS
  -f passfile         specify path to file to open and read PASS
  -e ENDPOINT         specify REST endpoint
                        (default = {ENDPOINT})
  -o outfile          specify output file (default: write to stdout)
  -h                  display this help text

PASS for USER is taken from the first of:
  1. -u USER:PASS
  2. -d passfd (read from fd)
  3. -f passfile (read from file)
  4. read from $PASS env var

{utils.LDAP_CONFIG_USAGE_MESSAGE}

"""


def usage(msg=None):
    if msg:
        print(f"{msg}\n", file=sys.stderr)

    print(_usage, file=sys.stderr)
    sys.exit()


class Options:
    endpoint = ENDPOINT
    user = "co_7.project_script"
    osg_co_id = OSG_CO_ID
    ucid = UNIX_CLUSTER_ID
    provision_target = LDAP_TARGET_ID
    outfile = None
    authstr = None
    project_gid_startval = PROJECT_GIDS_START
    ldap_config = None


options = Options()


def parse_options(args):
    try:
        ops, args = getopt.getopt(args, "u:c:g:l:t:a:d:f:e:o:h")
    except getopt.GetoptError:
        usage()

    if args:
        usage("Extra arguments: %s" % repr(args))

    passfd = None
    passfile = None

    for op, arg in ops:
        if op == "-h":
            usage()
        if op == "-u":
            options.user = arg
        if op == "-c":
            options.osg_co_id = int(arg)
        if op == "-g":
            options.ucid = int(arg)
        if op == "-t":
            options.provision_target = int(arg)
        if op == '-l':
            ldap_config_path   = arg
        if op == "-d":
            passfd = int(arg)
        if op == "-f":
            passfile = arg
        if op == "-e":
            options.endpoint = arg
        if op == "-o":
            options.outfile = arg

    try:
        user, passwd = utils.getpw(options.user, passfd, passfile)
        options.authstr = utils.mkauthstr(user, passwd)
    except PermissionError:
        usage("PASS required")

    try:
        options.ldap_config = utils.read_ldap_conffile(ldap_config_path)
    except utils.EmptyConfiguration:
        usage("LDAP Config File Required. Was empty or lacked a valid server configuration.")


def append_if_project(project_groups, group):
    """If this group has a ospoolproject id, and it starts with "Yes-", it's a project"""
    if utils.identifier_matches(group["ID_List"], "ospoolproject", (OSPOOL_PROJECT_PREFIX_STR + "*")):
        # Add a dict of the relavent data for this project to the project_groups list
        project_groups.append(group)


def update_highest_osggid(highest_osggid, group):
    # Get the value of the osggid identifier, if this group has one
    osggid = utils.identifier_from_list(group["ID_List"], "osggid")
    # If this group has a osggid, keep a hold of the highest one we've seen so far
    try:
        return max(highest_osggid, int(osggid))
    except TypeError:
        return highest_osggid


def get_comanage_data():
    projects_list = []
    highest_osggid = 0

    co_groups = utils.get_osg_co_groups(options.osg_co_id, options.endpoint, options.authstr)["CoGroups"]
    for group_data in co_groups:
        identifier_list = utils.get_co_group_identifiers(group_data["Id"], options.endpoint, options.authstr)
        if identifier_list is not None:
            # Store this groups data in a dictionary to avoid repeated API calls
            group = {"Gid": group_data["Id"], "Name": group_data["Name"], "ID_List": identifier_list["Identifiers"]}

            # Add this group to the project list if it's a project, otherwise skip.
            append_if_project(projects_list, group)

            # Update highest_osggid, if this group has an osggid and it's higher than the current highest osggid.
            highest_osggid = update_highest_osggid(highest_osggid, group)
    return (projects_list, highest_osggid)


def get_projects_needing_identifiers(project_groups):
    projects_needing_identifiers = []
    for project in project_groups:
        # If this project doesn't have an osggid already assigned to it...
        if utils.identifier_from_list(project["ID_List"], "osggid") is None:
            # Prep the project to have the proper identifiers added to it
            projects_needing_identifiers.append(project)
    return projects_needing_identifiers


def get_projects_needing_cluster_groups(project_groups):
    # CO Groups associated with a UNIX Cluster Group
    clustered_group_ids = utils.get_unix_cluster_groups_ids(options.ucid, options.endpoint, options.authstr)
    try:
        # All project Gids
        project_gids = set(project["Gid"] for project in project_groups)
        # Project Gids for projects without UNIX cluster groups
        project_gids_lacking_cluster_groups = project_gids.difference(clustered_group_ids)
        # All projects needing UNIX cluster groups
        projects_needing_unix_groups = (
            project
            for project in project_groups
            if project["Gid"] in project_gids_lacking_cluster_groups
        )
        return projects_needing_unix_groups
    except TypeError:
        print("ERROR: TypeError raised while trying to determine which projects need UNIX cluster groups\n"
              +f"clustered group ids: {clustered_group_ids} and project_gids: {project_gids}")
        return set()
    

def get_projects_needing_provisioning(project_groups):
    # project groups provisioned in LDAP
    ldap_group_osggids = utils.get_ldap_groups(options.ldap_config)
    try:
        # All project osggids
        project_osggids = set(
            int(utils.identifier_from_list(project["ID_List"], "osggid")) for project in project_groups
        )
        # project osggids not provisioned in ldap
        project_osggids_to_provision = project_osggids.difference(ldap_group_osggids)
        # All projects that aren't provisioned in ldap
        projects_to_provision = (
            project
            for project in project_groups
            if int(utils.identifier_from_list(project["ID_List"], "osggid")) in project_osggids_to_provision
        )
        return projects_to_provision
    except TypeError:
        print("TypeError raised while trying to determine which projects need provisioning\n"
              +f"ldap group osggids: {ldap_group_osggids} and project osggids: {project_osggids}")
        return set()


def add_missing_group_identifier(project, id_type, value):
    # If the group doesn't already have an id of this type ...
    if utils.identifier_from_list(project["ID_List"], id_type) is None:
        # ... add the identifier to the group
        utils.add_identifier_to_group(project["Gid"], id_type, value, options.endpoint, options.authstr)
        print(f'project {project["Gid"]}: added id {value} of type {id_type}')


def assign_identifiers_to_project(project, id_dict):
    for k, v in id_dict.items():
        # Add an identifier of type k and value v to this group, if it doesn't have them already
        add_missing_group_identifier(project, k, v)
    # Update the project object to include the new identifiers
    new_identifiers = utils.get_co_group_identifiers(project["Gid"], options.endpoint, options.authstr)["Identifiers"]
    project["ID_List"] = new_identifiers


def assign_identifiers(project_list, highest_osggid):
    highest = highest_osggid
    for project in project_list:
        # Project name identifier is the CO Group name in lower case
        project_name = project["Name"].lower()

        # Determine what osggid to assign this project,
        # based on the starting range and the highest osggid seen in existing groups
        osggid_to_assign = max(highest + 1, options.project_gid_startval)
        highest = osggid_to_assign

        identifiers_to_add = {"osggid": osggid_to_assign, "osggroup": project_name}

        assign_identifiers_to_project(project, identifiers_to_add)


def create_unix_cluster_groups(project_list):
    for project in project_list:
        utils.add_unix_cluster_group(project["Gid"], options.ucid, options.endpoint, options.authstr)
        print(f'project group {project["Gid"]}: added UNIX Cluster Group')


def provision_groups(project_list):
    for project in project_list:
        utils.provision_group(project["Gid"], options.provision_target, options.endpoint, options.authstr)
        print(f'project group {project["Gid"]}: Provisioned Group')


def main(args):
    parse_options(args)

    # Make all of the necessary calls to COManage's API for the data we'll need to set up projects.
    # Projects is a List of dicts with keys Gid, Name, and Identifiers, the project's list of identifiers.
    # Highest_current_osggid is the highest OSGGID that's currently assigned to any CO Group.
    projects, highest_current_osggid = get_comanage_data()

    # From all the project groups in COManage, find the ones that need OSGGIDs or OSG GroupNames,
    # then assign them the identifiers that they're missing.
    projects_needing_identifiers = get_projects_needing_identifiers(projects)
    assign_identifiers(projects_needing_identifiers, highest_current_osggid)

    # From all the project groups in COManage, find the ones that don't have UNIX Cluster Groups,
    # then create UNIX Cluster Groups for them.
    projects_needing_cluster_groups = get_projects_needing_cluster_groups(projects)
    create_unix_cluster_groups(projects_needing_cluster_groups)

    # From all the project groups in COManage, find the ones that aren't already provisioned in LDAP,
    # then have COManage provision the project/UNIX Cluster Group in LDAP.
    projects_needing_provisioning = get_projects_needing_provisioning(projects)
    provision_groups(projects_needing_provisioning)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as e:
        sys.exit(e)
