import time
import ssl
import os
from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
from rich import print
import readline
import rlcompleter
import atexit
import heapq
import shlex

def samr_set_password(current_session, target_user, newpass):
    from impacket.dcerpc.v5 import samr, transport

    dc_ip = current_session["ip"]
    domain = current_session["domain"]
    sess_user = current_session["username"]
    sess_pass = current_session["password"]
    nthash = current_session.get("nthash", "")

    lmhash = ""
    if nthash:
        lmhash = "aad3b435b51404eeaad3b435b51404ee"
        auth_pass = ""
    else:
        auth_pass = sess_pass

    rpctransport = transport.SMBTransport(dc_ip, filename=r'\samr')
    rpctransport.set_credentials(sess_user, auth_pass, domain, lmhash, nthash)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)

    resp = samr.hSamrConnect(dce)
    server_handle = resp['ServerHandle']

    resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
    domains = resp['Buffer']['Buffer']

    domain_name = None
    for d in domains:
        if d['Name'].lower() != 'builtin':
            domain_name = d['Name']
            break

    if not domain_name:
        print("[-] Could not find domain")
        return False

    resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
    domain_sid = resp['DomainId']

    resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
    domain_handle = resp['DomainHandle']

    resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [target_user])
    user_rid = resp['RelativeIds']['Element'][0]['Data']

    resp = samr.hSamrOpenUser(dce, domain_handle, samr.USER_FORCE_PASSWORD_CHANGE | samr.USER_READ_GENERAL, userId=user_rid)
    user_handle = resp['UserHandle']

    samr.hSamrSetNTInternal1(dce, user_handle, newpass)

    samr.hSamrCloseHandle(dce, user_handle)
    samr.hSamrCloseHandle(dce, domain_handle)
    samr.hSamrCloseHandle(dce, server_handle)
    dce.disconnect()
    return True

