from ldap3 import Server, Connection, ALL
from rich import print
def get_domain_info(dc_ip):
    try:
        server = Server(dc_ip, get_info=ALL)
        conn = Connection(server, auto_bind=True)
        
        print(f"\n[bold cyan][*] Enumerating Root DSE for: {dc_ip}[/bold cyan]")
        
        if 'dnsHostName' in server.info.other:
            dns_hostname = server.info.other['dnsHostName'][0]
            print(f"[bold green][+] DNS Hostname: {dns_hostname}[/bold green]")
        else:
            print("[yellow][!] dnsHostName not found in Root DSE info.[/yellow]")
            
        if 'defaultNamingContext' in server.info.other:
            print(f"[bold blue][+] Domain DN: {server.info.other['defaultNamingContext'][0]}[/bold blue]")

        conn.unbind()
    except Exception as e:
        print(f"[bold red][-] Failed to get domain info: {e}[/bold red]")