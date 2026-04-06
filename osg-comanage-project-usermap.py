#!/usr/bin/env python3.11

import os
import re
import sys
import getopt
import requests
import comanage_utils as utils


SCRIPT = os.path.basename(__file__)
ENDPOINT = "https://registry-test.cilogon.org/registry/"
TOPOLOGY_ENDPOINT = "https://topology.opensciencegrid.org/"
OSG_CO_ID = 8
CACHE_FILENAME = "COmanage_Projects_cache.txt"
CACHE_LIFETIME_HOURS = 0.5


_usage = f"""\
usage: {SCRIPT} [OPTIONS]

OPTIONS:
  -u USER[:PASS]      specify USER and optionally PASS on command line
  -c OSG_CO_ID        specify OSG CO ID (default = {OSG_CO_ID})
  -l LDAP_CONFIG_PATH        specify path to LDAP Config file for fallback-search servers
  -d passfd           specify open fd to read PASS
  -f passfile         specify path to file to open and read PASS
  -e ENDPOINT         specify REST endpoint
                        (default = {ENDPOINT})
  -o outfile          specify output file (default: write to stdout)
  -g filter_group     filter users by group name (eg, 'ap1-login')
  -m localmaps        specify a comma-delimited list of local HTCondor mapfiles to merge into outfile
  -n min_users        Specify minimum number of users required to update the output file (default: 100)
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
        print(msg + "\n", file=sys.stderr)

    print(_usage, file=sys.stderr)
    sys.exit()


class Options:
    endpoint = ENDPOINT
    user = "co_7.project_script"
    osg_co_id = OSG_CO_ID
    outfile = None
    authstr = None
    filtergrp = None
    ldap_config = None
    min_users = 100 # Bail out before updating the file if we have fewer than this many users
    localmaps = []


options = Options()


# api call results massagers

def get_osg_co_groups__map():
    #print("get_osg_co_groups__map()")
    resp_data = utils.get_osg_co_groups(options.osg_co_id, options.endpoint, options.authstr)
    data = utils.get_datalist(resp_data, "CoGroups")
    return { g["Name"]: g["Id"] for g in data }


def parse_options(args):
    try:
        ops, args = getopt.getopt(args, 'u:c:l:d:f:g:e:o:h:n:m:')
    except getopt.GetoptError:
        usage()

    if args:
        usage("Extra arguments: %s" % repr(args))

    passfd = None
    passfile = None
    ldap_auth_path = None

    for op, arg in ops:
        if op == '-h': usage()
        if op == '-u': options.user       = arg
        if op == '-c': options.osg_co_id  = int(arg)
        if op == '-l': ldap_config_path   = arg
        if op == '-d': passfd             = int(arg)
        if op == '-f': passfile           = arg
        if op == '-e': options.endpoint   = arg
        if op == '-o': options.outfile    = arg
        if op == '-g': options.filtergrp  = arg
        if op == '-m': options.localmaps  = arg.split(",")
        if op == '-n': options.min_users  = int(arg)

    try:
        user, passwd = utils.getpw(options.user, passfd, passfile)
        options.authstr = utils.mkauthstr(user, passwd)
    except PermissionError:
        usage("PASS required")
    
    try:
        options.ldap_config = utils.read_ldap_conffile(ldap_config_path)
    except utils.EmptyConfiguration:
        usage("LDAP Config File Required. Was empty or lacked a valid server configuration.")

def _deduplicate_list(items):
    """ Deduplicate a list while maintaining order by converting it to a dictionary and then back to a list. 
    Used to ensure a consistent ordering for output group lists, since sets are unordered.
    """
    return list(dict.fromkeys(items))

def get_osguser_groups(filter_group_name=None):
    ldap_users = utils.get_ldap_active_users_and_groups(filter_group_name=filter_group_name, config=options.ldap_config)
    topology_projects = requests.get(f"{TOPOLOGY_ENDPOINT}/miscproject/json").json()
    project_names = topology_projects.keys()
    
    # Get COManage group IDs to preserve ordering from pre-LDAP migration script behavior
    groups_ids = get_osg_co_groups__map()
    return {
        user: sorted([g for g in groups if g in project_names], key = lambda g: groups_ids.get(g, 0)) 
        for user, groups in ldap_users.items()
        if any(g in project_names for g in groups)
    }


def parse_localmap(inputfile):
    user_groupmap = dict()
    with open(inputfile, 'r', encoding='utf-8') as file:
        for line in file:
            # Split up 3 semantic columns
            split_line = line.strip().split(maxsplit=2)
            if split_line[0] == "*" and len(split_line) == 3:
                line_groups = re.split(r'[ ,]+', split_line[2])
                if split_line[1] in user_groupmap:
                    user_groupmap[split_line[1]] = _deduplicate_list(user_groupmap[split_line[1]] + line_groups)
                else:
                    user_groupmap[split_line[1]] = line_groups
    return user_groupmap


def merge_maps(maps):
    merged_map = dict()
    for projectmap in maps:
        for key in projectmap.keys():
            if key in merged_map:
                merged_map[key] = _deduplicate_list(merged_map[key] + projectmap[key])
            else:
                merged_map[key] = projectmap[key]
    return merged_map


def print_usermap_to_file(osguser_groups, file):
    for osguser, groups in sorted(osguser_groups.items()):
        print("* {} {}".format(osguser, ",".join(group.strip() for group in groups)), file=file)


def print_usermap(osguser_groups):
    if options.outfile:
        with open(options.outfile, "w") as w:
            print_usermap_to_file(osguser_groups, w)
    else:
        print_usermap_to_file(osguser_groups, sys.stdout)


def main(args):
    parse_options(args)

    osguser_groups = get_osguser_groups(options.filtergrp)

    maps = [osguser_groups]
    for localmap in options.localmaps:
        maps.append(parse_localmap(localmap))
    osguser_groups_merged = merge_maps(maps)

    # Sanity check, confirm we have generated a "sane" amount of user -> group mappings
    if len(osguser_groups_merged) < options.min_users:
        raise RuntimeError(f"Refusing to update output file: only {len(osguser_groups_merged)} users found")
    print_usermap(osguser_groups_merged)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as e:
        sys.exit(e)
