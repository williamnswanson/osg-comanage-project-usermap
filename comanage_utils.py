#!/usr/bin/env python3

import os
import re
import json
import time
import configparser
import urllib.error
import urllib.request
from enum import StrEnum
from pathlib import Path
from ldap3 import Server, Connection, ALL, SAFE_SYNC, Tls
from ldap3.core.exceptions import LDAPException
from dataclasses import dataclass

#PRODUCTION VALUES

# PRODUCTION_ENDPOINT = "https://registry.cilogon.org/registry/"
# PRODUCTION_LDAP_USER = "uid=readonly_user,ou=system,o=OSG,o=CO,dc=cilogon,dc=org"
# PRODUCTION_OSG_CO_ID = 7
# PRODUCTION_UNIX_CLUSTER_ID = 1
# PRODUCTION_LDAP_TARGET_ID = 6

#TEST VALUES

# TEST_ENDPOINT = "https://registry-test.cilogon.org/registry/"
# TEST_LDAP_SERVER_LIST = ["ldaps://ldap-test.cilogon.org"]
# TEST_LDAP_USER ="uid=registry_user,ou=system,o=OSG,o=CO,dc=cilogon,dc=org"
# TEST_OSG_CO_ID = 8
# TEST_UNIX_CLUSTER_ID = 10
# TEST_LDAP_TARGET_ID = 9

# Value for the base of the exponential backoff
TIMEOUT_BASE = 5
MAX_ATTEMPTS = 5

# LDAP Search Bases

# LDAP Server Connection and Search Config, required keys
class LDAP_CONFIG_KEYS(StrEnum):
    LDAP_Server_URL = "LDAPServerURl"
    LDAP_Search_Base = "SearchBase"
    LDAP_User = "User"
    LDAP_AuthTok_File = "AuthTokenFile"

LDAP_CONFIG_USAGE_MESSAGE = f"""
    file at LDAP_CONFIG_PATH should be in ini format, servers will be attempted in descending order.
    An example section of this config file follows:

    ---

    [human_server_name] # arbitrary human label for this server's config
    {LDAP_CONFIG_KEYS.LDAP_Server_URL} = ldaps://ldap-replica-1.osg.chtc.io      # URL to reach this LDAP server from
    {LDAP_CONFIG_KEYS.LDAP_Search_Base} = dc=osg-htc,dc=org                      # LDAP Search Base 
    {LDAP_CONFIG_KEYS.LDAP_User} = cn=readonly,ou=system,dc=osg-htc,dc=org       # full LDAP user DN 
    {LDAP_CONFIG_KEYS.LDAP_AuthTok_File} = /etc/ldap-secrets/osg-ldap/authtoken  # file containing authtoken for access

    ---

    Config file should contain one such section per LDAP server to communicate with.
    """


GET    = "GET"
PUT    = "PUT"
POST   = "POST"
DELETE = "DELETE"

#Exceptions
class Error(Exception):
    """Base exception class for all exceptions defined"""
    pass


class URLRequestError(Error):
    """Class for exceptions due to not being able to fulfill a URLRequest"""
    pass

class EmptyConfiguration(Error):
    """Class for exceptions due to loading an empty Config file, or one where every section lacked the required keys"""
    pass

class NoLDAPResponse(Error):
    """Class for exceptions due to being unable to get any request from any configured LDAP servers."""
    pass

def getpw(user, passfd, passfile):
    if ":" in user:
        user, pw = user.split(":", 1)
    elif passfd is not None:
        pw = os.fdopen(passfd).readline().rstrip("\n")
    elif passfile is not None:
        pw = open(passfile).readline().rstrip("\n")
    elif "PASS" in os.environ:
        pw = os.environ["PASS"]
    else:
        raise PermissionError
        #when script needs to say PASS required, raise a permission error
        #usage("PASS required")
    return user, pw


def mkauthstr(user, passwd):
    from base64 import encodebytes
    raw_authstr = "%s:%s" % (user, passwd)
    return encodebytes(raw_authstr.encode()).decode().replace("\n", "")

def get_ldap_authtok(ldap_authfile):
    if ldap_authfile is not None:
        ldap_authtok = open(ldap_authfile).readline().strip()
    else:
        raise PermissionError
    return ldap_authtok

def read_ldap_conffile(ldap_conffile_path):
    config = configparser.ConfigParser(allow_no_value=True)

    print(f"Attempting to read config from {ldap_conffile_path}")
    config.read(ldap_conffile_path)
    misconfigured_sections = list()
    for section in config.sections():
        for key in LDAP_CONFIG_KEYS:
            # All servers must have all required keys for operation
            if not config.has_option(section, key) or config.get(section, key) == "":
                print(f"Section \"{section}\": required key \"{key}\" missing, ignoring section.")
                misconfigured_sections.append(section)
                break
        # For-Else to only check key values if we know the required ones exist (i.e. we didn't break)
        else:
            # All server AuthTok files must exist, be files, and not be empty
            token_path = Path(config.get(section, LDAP_CONFIG_KEYS.LDAP_AuthTok_File))
            try:
                if not token_path.exists():
                    print(f"Section \"{section}\": AuthToken File missing or non-file, ignoring section.")
                    misconfigured_sections.append(section)
                    continue
                if token_path.stat().st_size == 0 :
                    print(f"Section \"{section}\": AuthToken File is empty, ignoring section.")
                    misconfigured_sections.append(section)
                    continue
            except OSError as e:
                print(f"Section \"{section}\": Exception raised while checking AuthTok File: {e}, skipping section.")
                misconfigured_sections.append(section)
                continue

    for section in misconfigured_sections:
        print(f"Dropping section {section}")
        config.remove_section(section)

    # if their are no servers in the file that have all required keys
    if len(config.sections()) == 0:
        #when script needs to say LDAP Config required, raise a EmptyConfiguration error
        #usage("LDAP Config File Required")
        raise EmptyConfiguration(
            f"Config file at {ldap_conffile_path} was empty or all sections lacked required keys."
        )
    print(f"Finished reading config from {ldap_conffile_path}")
    return config


def mkrequest(method, target, data, endpoint, authstr, **kw):
    url = os.path.join(endpoint, target)
    if kw:
        url += "?" + "&".join("{}={}".format(k,v) for k,v in kw.items())
    req = urllib.request.Request(url, json.dumps(data).encode("utf-8"))
    req.add_header("Authorization", "Basic %s" % authstr)
    req.add_header("Content-Type", "application/json")
    req.get_method = lambda: method
    return req


def call_api(target, endpoint, authstr, **kw):
    return call_api2(GET, target, endpoint, authstr, **kw)


def call_api2(method, target, endpoint, authstr, **kw):
    return call_api3(method, target, data=None, endpoint=endpoint, authstr=authstr, **kw)


def call_api3(method, target, data, endpoint, authstr, **kw):
    req = mkrequest(method, target, data, endpoint, authstr, **kw)
    req_attempts = 0
    current_timeout = TIMEOUT_BASE
    total_timeout = 0
    payload = None
    while req_attempts < MAX_ATTEMPTS:
        try:
            resp = urllib.request.urlopen(req, timeout=current_timeout)
        # exception catching, mainly for request timeouts, "Service Temporarily Unavailable" (Rate limiting), and DNS failures.
        except urllib.error.URLError as exception:
            req_attempts += 1
            if req_attempts >= MAX_ATTEMPTS:
                raise URLRequestError(
                    "Exception raised after maximum number of retries reached after total backoff of " + 
                    f"{total_timeout} seconds. Retries: {req_attempts}. "
                + f"Exception reason: {exception}.\n Request: {req.full_url}"
                )
            time.sleep(current_timeout)
            total_timeout += current_timeout
            current_timeout *= TIMEOUT_BASE
        else:
            payload = resp.read()
            break

    return json.loads(payload) if payload else None


def get_osg_co_groups(osg_co_id, endpoint, authstr):
    return call_api("co_groups.json", endpoint, authstr, coid=osg_co_id)


def get_co_group_identifiers(gid, endpoint, authstr):
    return call_api("identifiers.json", endpoint, authstr, cogroupid=gid)


def get_co_group_members(gid, endpoint, authstr):
    return call_api("co_group_members.json", endpoint, authstr, cogroupid=gid)


def get_co_person_identifiers(pid, endpoint, authstr):
    return call_api("identifiers.json", endpoint, authstr, copersonid=pid)


def get_co_group(gid, endpoint, authstr):
    resp_data = call_api("co_groups/%s.json" % gid, endpoint, authstr)
    grouplist = get_datalist(resp_data, "CoGroups")
    if not grouplist:
        raise RuntimeError("No such CO Group Id: %s" % gid)
    return grouplist[0]


def get_identifier(id_, endpoint, authstr):
    resp_data = call_api("identifiers/%s.json" % id_, endpoint, authstr)
    idfs = get_datalist(resp_data, "Identifiers")
    if not idfs:
        raise RuntimeError("No such Identifier Id: %s" % id_)
    return idfs[0]


def get_unix_cluster_groups(ucid, endpoint, authstr):
    return call_api("unix_cluster/unix_cluster_groups.json", endpoint, authstr, unix_cluster_id=ucid)


def get_unix_cluster_groups_ids(ucid, endpoint, authstr):
    unix_cluster_groups = get_unix_cluster_groups(ucid, endpoint, authstr)
    return set(group["CoGroupId"] for group in unix_cluster_groups["UnixClusterGroups"])


def delete_identifier(id_, endpoint, authstr):
    return call_api2(DELETE, "identifiers/%s.json" % id_, endpoint, authstr)


def get_datalist(data, listname):
    return data[listname] if data else []


class LDAP_Server:
    """ Wrapper class for LDAP searches. """
    server: Server = None
    connection: Connection = None

    def __init__(self, ldap_server, ldap_user, ldap_authtok):
        self.server = Server(ldap_server, get_info=ALL)
        self.connection = Connection(self.server, ldap_user, ldap_authtok, client_strategy=SAFE_SYNC, auto_bind=True)

    def search(self, ou, search_base, filter_str, attrs):
        # simple paged search
        # https://github.com/cannatag/ldap3/blob/7991e67d0a2fb2c1f9cbf832d110ad29fc378f9b/docs/manual/source/standard.rst#L4
        # https://ldap3.readthedocs.io/en/latest/tutorial_searches.html#simple-paged-search
        response = self.connection.extend.standard.paged_search(
            f"ou={ou},{search_base}",
            filter_str, 
            attributes=attrs,
            paged_size=500,
            generator=True
        )

        return response

# TODO:
# do_ldap_fallback_search, get_ldap_groups, and get_ldap_active_users_and_groups should be a method of the LDAPSearch class
# script calling this lib should init LDAPSearch, then call the method that asks for the info it wants.
# Be able to feed in either one server's config to the LDAPSearch, or a conffile to parse with a list of >=1 LDAP servers to do fallback searches with.

def do_ldap_fallback_search(search_ou, search_filter, attrs, ldap_config: configparser.ConfigParser):
    response = None

    if ldap_config == None:
        raise EmptyConfiguration(
            "Search Attempted with \"None\" config object."
        )

    for section in ldap_config.sections():
        print(f"Attempting search with server {section}")
        try:
            server_url = ldap_config.get(section, LDAP_CONFIG_KEYS.LDAP_Server_URL)
            search_base = ldap_config.get(section, LDAP_CONFIG_KEYS.LDAP_Search_Base)
            search_user = ldap_config.get(section, LDAP_CONFIG_KEYS.LDAP_User)
            authtok_file = ldap_config.get(section, LDAP_CONFIG_KEYS.LDAP_AuthTok_File)
            authtok = get_ldap_authtok(authtok_file)

            searcher = LDAP_Server(ldap_server=server_url, ldap_user=search_user, ldap_authtok=authtok)
            response = searcher.search(search_ou, search_base, search_filter, attrs)
            
            #If we get a response from one of the servers, we don't need to check the rest 
            if not response is None:
                print(f"Response found for server {section}.")
                break
        # Perm issue reading token file
        except PermissionError as permError:
            print(f"Permission Error when attempting search for {section}: {permError}.")
        # Problem getting LDAP Response
        except LDAPException as ldapError:
            print(f"Exception occurred when attempting search for {section}: {ldapError}.")
            continue

    if response is None:
        raise NoLDAPResponse(
            f"No response found via LDAP servers: {[section for section in ldap_config]}."
        )

    return response

def get_ldap_groups(config=None):
    ldap_group_osggids = set()

    response = do_ldap_fallback_search(
        search_ou="groups",
        search_filter="(cn=*)",
        attrs=["gidNumber"],
        ldap_config=config
    )

    for group in response:
        ldap_group_osggids.add(group["attributes"]["gidNumber"])
    return ldap_group_osggids


def get_ldap_active_users_and_groups(filter_group_name=None, config=None):
    """ Retrieve a dictionary of active users from LDAP, with their group memberships. """
    ldap_active_users = dict()
    filter_str = ("(isMemberOf=CO:members:active)" if filter_group_name is None 
                  else f"(&(isMemberOf={filter_group_name})(isMemberOf=CO:members:active))")

    response = do_ldap_fallback_search(
        search_ou="people",
        search_filter=filter_str,
        attrs=["employeeNumber", "isMemberOf"],
        ldap_config=config
    )

    for person in response:
        ldap_active_users[person["attributes"]["employeeNumber"]] = person["attributes"].get("isMemberOf", [])

    return ldap_active_users


def identifier_from_list(id_list, id_type):
    id_type_list = [id["Type"] for id in id_list]
    try:
        id_index = id_type_list.index(id_type)
        return id_list[id_index]["Identifier"]
    except ValueError:
        return None


def identifier_matches(id_list, id_type, regex_string):
    pattern = re.compile(regex_string)
    value = identifier_from_list(id_list, id_type)
    return (value is not None) and (pattern.match(value) is not None)


def rename_co_group(gid, group, newname, endpoint, authstr):
    # minimal edit CoGroup Request includes Name+CoId+Status+Version
    new_group_info = {
        "Name"    : newname,
        "CoId"    : group["CoId"],
        "Status"  : group["Status"],
        "Version" : group["Version"]
    }
    data = {
        "CoGroups"    : [new_group_info],
        "RequestType" : "CoGroups",
        "Version"     : "1.0"
    }
    return call_api3(PUT, "co_groups/%s.json" % gid, data, endpoint, authstr)


def add_identifier_to_group(gid, type, identifier_value, endpoint, authstr):
    new_identifier_info = {
        "Version": "1.0",
        "Type": type,
        "Identifier": identifier_value,
        "Login": False,
        "Person": {"Type": "Group", "Id": str(gid)},
        "Status": "Active",
    }
    data = {
        "RequestType": "Identifiers",
        "Version": "1.0",
        "Identifiers": [new_identifier_info],
    }
    return call_api3(POST, "identifiers.json", data, endpoint, authstr)


def add_unix_cluster_group(gid, ucid, endpoint, authstr):
    data = {
        "RequestType": "UnixClusterGroups",
        "Version": "1.0",
        "UnixClusterGroups": [{"Version": "1.0", "UnixClusterId": ucid, "CoGroupId": gid}],
    }
    return call_api3(POST, "unix_cluster/unix_cluster_groups.json", data, endpoint, authstr)


def provision_group(gid, provision_target, endpoint, authstr):
    path = f"co_provisioning_targets/provision/{provision_target}/cogroupid:{gid}.json"
    data = {
        "RequestType" : "CoGroupProvisioning",
        "Version"     : "1.0",
        "Synchronous" : True
    }
    return call_api3(POST, path, data, endpoint, authstr)

def provision_group_members(gid, prov_id, endpoint, authstr):
    data = {
        "RequestType" : "CoPersonProvisioning",
        "Version"     : "1.0",
        "Synchronous" : True
    }
    responses = {}
    for member in get_co_group_members(gid, endpoint, authstr)["CoGroupMembers"]:
        if member["Person"]["Type"] == "CO":
            pid = member["Person"]["Id"]
            path = f"co_provisioning_targets/provision/{prov_id}/copersonid:{pid}.json"
            responses[pid] = call_api3(POST, path, data, endpoint, authstr)
    return responses
