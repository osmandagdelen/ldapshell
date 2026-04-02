import os

with open('ldapshell.py', 'r') as f:
    lines = f.readlines()

def write_f(name, ranges, imports):
    out = []
    out.extend(imports)
    for start, end in ranges:
        out.extend(lines[start-1:end])
    with open(name, 'w') as outf:
        outf.writelines(out)

IMPORTS = [
    "import time\n", "import ssl\n", "import os\n",
    "from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS\n",
    "from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK\n",
    "from rich import print\n", "import readline\n", "import rlcompleter\n",
    "import atexit\n", "import heapq\n", "import shlex\n\n"
]

write_f('src/structs.py', [(62, 308)], IMPORTS)

utils_imports = IMPORTS + [
    "from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST\n"
]
write_f('src/utils.py', [(19, 51), (52, 61), (309, 354), (447, 471), (813, 825), (840, 856)], utils_imports)

queries_imports = IMPORTS + [
    "from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST\n",
    "from src.utils import sid_to_string, resolve_member_name, resolve_sid\n"
]
write_f('src/queries.py', [(355, 446), (472, 540), (800, 812), (826, 839)], queries_imports)

auth_imports = IMPORTS + []
write_f('src/auth.py', [(563, 620)], auth_imports)

add_imports = IMPORTS + [
    "from src.auth import samr_set_password\n",
    "from src.utils import UAC_FLAGS\n"
]
write_f('src/add.py', [(541, 562), (621, 705)], add_imports)

acls_imports = IMPORTS + []
write_f('src/acls.py', [(706, 799)], acls_imports)

new_ldapshell = lines[:18]
new_ldapshell.extend([
    "from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST\n",
    "from src.utils import UAC_FLAGS, COMMANDS, shell_completer, show_menu, infer_netbios, domain_to_dn, check_connection, sid_to_string, save_password, resolve_sid, resolve_member_name\n",
    "from src.queries import batch_lookup, build_category_tree, print_categories, list_groups_bfs, list_users, list_computers, kerberoastable, get_sid\n",
    "from src.add import add_member, add_computer, modify_uac, set_password\n",
    "from src.acls import cmd_setowner, cmd_genericall\n",
    "from src.auth import samr_set_password\n\n",
])
new_ldapshell.extend(lines[856:])

with open('ldapshell.py', 'w') as f:
    f.writelines(new_ldapshell)

print("done")
