# KrbRelayEx

![Version](https://img.shields.io/badge/version-1.0-blue)  
Kerberos Relay and Forwarder for (Fake) SMB MiTM Server  
Created by [@decoder_it](https://github.com/decoder-it)

---

## Overview

**KrbRelayEx** is a tool designed for performing Man-in-the-Middle (MitM) attacks by relaying Kerberos AP-REQ tickets. It listens for incoming SMB connections and forwards the AP-REQ to the target host, enabling access to SMB shares or HTTP AD CS (Active Directory Certificate Services) endpoints.  

The tool can span several SMB consoles, and the relaying process is completely transparent to the end user, who will seamlessly access the desired share.  

GitHub Repository: [https://github.com/decoder-it/KrbRelayEx](https://github.com/decoder-it/KrbRelayEx)  
Credits: [cube0x0/KrbRelay](https://github.com/cube0x0/KrbRelay)

---

## Features

- Relay Kerberos AP-REQ tickets to access SMB shares or HTTP ADCS endpoints.
- Interactive or background SMB consoles for managing multiple connections.
- Supports dumping SAM & LSA secrets.
- Transparent relaying process for seamless user access.
- Flexible attack configurations with support for SSL and port redirection.

---

## Usage

```bash
KrbRelayEx.exe -spn <SPN> [OPTIONS] [ATTACK]
