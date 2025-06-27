---
title: Hack the System - Bug Bounty CTF Playground
date: 2025-06-27
tags: [htb, bugbounty, ctf, playground, jwt client side, bypass email verification]
categories: [CTF Writeups, Bug Bounty, HTB Writeups]
author: 2Fa0n
img_path: /assets/img/hack-the-system-bug-bounty-ctf-playground
image: /assets/img/hack-the-system-bug-bounty-ctf-playground/hack-the-system-bug-bounty-ctf-playground_banner.png
---

# Web
## Criticalops
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
Criticalops is a web application designed to monitor several critical infrastructure of XYZ region. Users usualy use this website to report for unusual behavioral, or we also called it ticket. They've asked you to hunt for any potential security issues in their application and retrieve the flag stored in their site. <br>
**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [JWT client-side](https://hackerone.com/reports/638635)

### Solution
Click on spawn the docker and have a look at the website.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops.png)

So this platform is about monitoring and control the critical infrastructure. Let's register a new account.

```bash
username: test123
password: test123
```

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_register.png)

Let's login with the account we just created.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_login.png)

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_dashboard.png)

The dashboard looks pretty cool. There is a ticket section. Let's create a new ticket.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_ticket.png)

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_ticket_create.png)

When checking back the incident, we can see that the ticket is created.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_ticket_created.png)

Then I also check these request through burp suite, and there is a JWT token in the request. After reading the *Bug Report #1*, we need to impersonate maybe **admin** user to view all the tickets.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_jwt.png)

I use the tool which is **JWT Editor** to edit the JWT token. You can install it from BApp Store in burp suite.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_jwt_editor.png)

But if only we change the **role** to **admin**, it will not work, we need to find the `JWT_SECRET` in order to sign the JWT token. <br>
&rarr;We can get it from the source code.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_jwt_secret.png)

Now we can impersonate the **admin** user with this `JWT_SECRET`:`SecretKey-CriticalOps-2025`.

**Steps:** <br>
- Go the **JWT Editor** and click the **New Symmetric Key** button.
- Select **Specific Key** and paste `SecretKey-CriticalOps-2025`.
- For **ID** field, paste the **userId** from the JWT token.

&rarr; Then click **Generate** button.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_jwt_generate.png)

We can now change the **role** to **admin** and click the **Sign** button and sign with the one we just generated.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_jwt_sign.png)

Send the request.

![criticalops](/assets/img/hack-the-system-bug-bounty-ctf-playground/criticalops_jwt_admin.png)

Now we are **admin** and can view all the tickets. <br>
&rarr; Grab the flag.

**Flag:** `HTB{Wh0_Put_JWT_1n_Cl13nt_S1d3_lm4o}`

## NovaEnergy
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
NovaEnergy is a internal web application used for file sharing system. This site can only be accessed by employee of NovaEnergy company. You're tasked to hunt for any vulnerabilities that led to any breaches in their site. <br>
**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [Bypass Email verification](https://hackerone.com/reports/2712583) <br>
*Bug Report #2* - [Bypass Email verification in Mozilla](https://0d-amr.medium.com/bypass-email-verification-in-mozilla-2ab45ac36c42)

### Solution
Click on spawn the docker and have a look at the website.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy.png)

So this platform is about sharing files with other employees. Let's register a new account.

```bash
email address: test123@novaenergy.com
password: test123
```

> Can not use `test123@gmail.com` because this platform only allow the email address from `novaenergy.com` domain.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_register.png)

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_verify_email.png)

Need to verify the email address but we do not control this email address. So we need to bypass the email verification. <br>
&rarr; After reading two bug reports, we can must find a leak verification token from `novaenergy.com` domain.

Let's [dirsearch](https://github.com/maurosoria/dirsearch) to finding more endpoints.

```bash
➜  ~ dirsearch -u http://94.237.121.185:55405/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /Users/benasin/reports/http_94.237.121.185_55405/__25-06-27_21-45-22.txt

Target: http://94.237.121.185:55405/

[21:45:22] Starting:
[21:46:05] 404 -   22B  - /api/
[21:46:05] 404 -   22B  - /api/2/issue/createmeta
[21:46:05] 404 -   22B  - /api/2/explore/
[21:46:05] 404 -   22B  - /api/_swagger_/
[21:46:05] 404 -   22B  - /api/__swagger__/
[21:46:05] 404 -   22B  - /api/api
[21:46:05] 404 -   22B  - /api/api-docs
[21:46:05] 404 -   22B  - /api/apidocs
[21:46:05] 404 -   22B  - /api/cask/graphql
[21:46:05] 404 -   22B  - /api/config
[21:46:05] 200 -  963B  - /api/docs
[21:46:05] 307 -    0B  - /api/docs/  ->  http://94.237.121.185/api/docs
[21:46:05] 404 -   22B  - /api/jsonws
[21:46:05] 404 -   22B  - /api/login.json
[21:46:05] 404 -   22B  - /api/package_search/v4/documentation
[21:46:05] 404 -   22B  - /api/proxy
[21:46:05] 404 -   22B  - /api/spec/swagger.json
[21:46:05] 404 -   22B  - /api/swagger-ui.html
[21:46:05] 404 -   22B  - /api/snapshots
[21:46:05] 404 -   22B  - /api/swagger.json
[21:46:05] 404 -   22B  - /api/swagger
[21:46:05] 404 -   22B  - /api/swagger.yaml
[21:46:05] 404 -   22B  - /api/swagger.yml
[21:46:05] 301 -  169B  - /api  ->  http://94.237.121.185/api/
[21:46:05] 404 -   22B  - /api/timelion/run
[21:46:05] 404 -   22B  - /api/v1
[21:46:05] 404 -   22B  - /api/v1/swagger.json
[21:46:06] 404 -   22B  - /api/batch
[21:46:06] 404 -   22B  - /api/v2/
[21:46:06] 404 -   22B  - /api/v2
[21:46:06] 404 -   22B  - /api/application.wadl
[21:46:06] 404 -   22B  - /api/v2/swagger.json
[21:46:06] 404 -   22B  - /api/v3
[21:46:06] 404 -   22B  - /api/v2/swagger.yaml
[21:46:06] 404 -   22B  - /api/v2/helpdesk/discover
[21:46:06] 404 -   22B  - /api/v4
[21:46:06] 404 -   22B  - /api/error_log
[21:46:06] 404 -   22B  - /api/index.html
[21:46:06] 404 -   22B  - /api/vendor/phpunit/phpunit/phpunit
[21:46:06] 404 -   22B  - /api/version
[21:46:06] 404 -   22B  - /api/jsonws/invoke
[21:46:06] 404 -   22B  - /api/whoami
[21:46:06] 404 -   22B  - /api/profile
[21:46:06] 404 -   22B  - /api/swagger/static/index.html
[21:46:06] 404 -   22B  - /api/swagger/index.html
[21:46:06] 404 -   22B  - /api/swagger/swagger
[21:46:06] 404 -   22B  - /api/swagger/ui/index
[21:46:06] 404 -   22B  - /api/v1/
[21:46:06] 404 -   22B  - /api/apidocs/swagger.json
[21:46:06] 404 -   22B  - /api/v1/swagger.yaml
[21:46:26] 302 -  199B  - /dashboard  ->  /login
[21:46:54] 200 -    3KB - /login
[21:46:55] 200 -    1KB - /logout
[21:47:15] 200 -    3KB - /register
[21:47:25] 301 -  169B  - /static  ->  http://94.237.121.185/static/
[21:47:34] 302 -  199B  - /upload  ->  /login

Task Completed
```

Found out `/api/docs` endpoint. Let's check it out.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_api_docs.png)

Look at it, just familiar with [swagger](https://swagger.io/) where we can see the API documentation and make some request to the API.

Let's try the `POST /userDetails` to view our user details.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_api_user_details.png)

See that we get details of our user and also the **verifyToken** in the response. <br>
We can also see the `POST /email-verify` endpoint which require **email** and **token**. <br>
&rarr; Can leverage this to bypass the email verification.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_api_email_verify.png)

See the response that `Email verified successfully`. <br>
&rarr; Now we can able to login with the email address we just created.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_login_success.png)

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_dashboard.png)

Got into the dashboard ans saw the `flag.txt` file. <br>
&rarr; Nail the flag.

![novaenergy](/assets/img/hack-the-system-bug-bounty-ctf-playground/novaenergy_flag.png)

**Flag:** `HTB{g00d_j0b_r3g1str4ti0n_byp4s5_add84cf14172259f0a31355373926deb}`

*From these two challenges, we can see that these challenges based on the real world bug bounty reports. And we know that if we understand the approach of the application, we can figure out the vulnerability and exploit it.*

This is just a CTF playground, let's go for the real event [Hack the System - Bug Bounty CTF](https://ctf.hackthebox.com/event/2508).