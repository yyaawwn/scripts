import ldap
import re
import os
import json
import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-s", "--server",
                help="ldap server config", action="store",
                dest="ldap_server", default="ldap://food.com:389")
parser.add_argument("-d", "--domain-dn",
                help="base dn to serach in", action="store",
                dest="base_dn", default="dc=bar,dc=com")
parser.add_argument("-u", "--user",
                help="user ID for LDAP login", action="store",
                dest="ldap_login", default="foo")
parser.add_argument("-p", "--password",
                help="user ID for LDAP login", action="store",
                dest="ldap_passwd" )
parser.add_argument("-l", "--list",
                help="csv user list for lookup", action="store",
                dest="list",required=True)

args = parser.parse_args()


def is_id_locked(ldap_server,base_dn,ldap_login,ldap_passwd,id,):

    def lockout_time_ldap_query(filter):
        connect = ldap.initialize(ldap_server)
        connect.set_option(ldap.OPT_REFERRALS, 0)  #To search the object and all its descendants
        connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3) #Default is 2
        connect.simple_bind_s(ldap_login, ldap_passwd)
        attributes_to_search = ["samaccountname"]
        r=connect.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attributes_to_search)
        if re.search(id.lower(), str(r).lower()):
            return True

    if lockout_time_ldap_query("(&(objectclass=user)(samaccountname={0}))".format(id)):
        if lockout_time_ldap_query("(&(objectclass=user)(samaccountname={0})(lockouttime>=1))".format(id)):
            status = "locked"
        else:
            status = "active"
    else:
        status = "unknown"

    return {"id": id, "status": status}

if __name__ == "__main__":
    for id in args.list.split(","):
       print(is_id_locked(args.ldap_server, args.base_dn, args.ldap_login, args.ldap_passwd, id))
