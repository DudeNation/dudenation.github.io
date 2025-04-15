---
title: Texsaw CTF 2025 - WEB, OSINT
date: 2025-04-15
tags: [ctf, web, osint]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/texsaw-ctf_2025
image: /assets/img/texsaw-ctf_2025/texsaw_banner.png
---

# Osint
## pottermania_part1
**Solvers:** *** <br>
**Author:** texsaw

### Description
Analyze the image and find where it is used. (P.S. word.paragraph) <br>
**Hint:** numbers are considered as words <br>
![pottermania_part1](/assets/img/texsaw-ctf_2025/pottermania_part1.png)

### Solution
This challenge gives us a image and what us to find something. Let's try google image search see what we can find. <br>
After searching, we can this [website](https://www.life.com/arts-entertainment/harry-potter-the-story-that-changed-the-world/) and I am not really a fan or watch any movie or even read about Harry Potter so I skip this part. <br>
Let use some popular command line when doing osint which is `exiftool` to see if we can find anything. <br>
```bash
➜  pottermania_part1 exiftool harrypotter.jpg | cat
ExifTool Version Number         : 12.76
File Name                       : harrypotter.jpg
Directory                       : .
File Size                       : 106 kB
File Modification Date/Time     : 2025:04:13 10:57:38+07:00
File Access Date/Time           : 2025:04:13 11:13:39+07:00
File Inode Change Date/Time     : 2025:04:13 11:13:36+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Copyright                       : Caesar Cipher [shift=11]
XMP Toolkit                     : Image::ExifTool 13.19
Title                           : texsaw{Copyright(12.4)Copyright(35.7)Copyright(37.7)}
Author                          : Gina McIntyre
Image Width                     : 753
Image Height                    : 1024
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 753x1024
Megapixels                      : 0.771
```

I am really curious about the `Copyright` field and the `Title` field. <br>
```
Copyright                       : Caesar Cipher [shift=11]
Title                           : texsaw{Copyright(12.4)Copyright(35.7)Copyright(37.7)}
```

Look back the hint, it says that numbers are considered as words. And also the P.S says that word.paragraph. <br>
Maybe it could be like this:
```
word.paragraph
12      4
35      7
37      7
```

Luckly, we have found a website above. Let's find these words in the website. <br>
For the word at position 12 in paragraph 4, it is `Harry`. <br>
![harry](/assets/img/texsaw-ctf_2025/harry124.png)

And the rest of the words are:
- `Ron` at position 35 in paragraph 7 <br>
- `Hermione` at position 37 in paragraph 7 <br>

I quickly submit the flag `texsaw{HarryRonHermione}` and it failed =)). I suddenly realize that the Copyright field is Caesar Cipher with shift 11. So it means that we need to shift to 11 characters and I found this website [caesar-cipher-solver](https://cryptii.com/pipes/caesar-cipher). <br>
![caesar](/assets/img/texsaw-ctf_2025/caesar.png)

So the final result is:
- `Harry` -> `Slccj`
- `Ron` -> `Czy`
- `Hermione` -> `Spcxtzyp`

So let's correct the format `SlccjCzySpcxtzyp` and we successfully submit correctly. <br>

**Flag:** `texsaw{SlccjCzySpcxtzyp}`

# Web
## Deprecated Site
**Solvers:** *** <br>
**Author:** texsaw

### Description
CSG's left an old webpage up on accident. It's old and deprecated, maybe you should do us a favor and get rid of it? <br>

### Solution
This challenge is really simple. The hint is `deprecated` and `get rid of it` so just simply delete this page. <br>
I will use `curl` to delete the page. <br>
```bash
➜  ~ curl -X DELETE http://74.207.229.59:20201/
Why would you delete my website :( here's a sad flag texsaw{why_d0_i_del3t3ed}
```

Super easy right? =))

**Flag:** `texsaw{why_d0_i_del3t3ed}`

## PotterMania pt.2
**Solvers:** *** <br>
**Author:** texsaw

### Description
Can you direct(ory) Harry to go down the right path to defeat You-Know-Who? P.S. You might want to check out pottermaina_part1, it's key. <br>

### Solution
When go through the website, we just found another endpoint `/magic` which reveal `JWT Token`. <br>
```js
fetch('/magic', {
    method: 'GET',
    credentials: "include",
    headers: {
        'X-Magic-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRlIjoiMjAyMy0wMTQwLWZzoyMToyNy42MTAiNzcrMDAgMDAlMDAiLCJzGVsbCI6IkpybjIiYmF0dGxlIiwibG9jYXRpb24iIGIG9mIGhvZ3Z3cnRzIn0.bBdbvETm-Aml15_asxsgiEMcMBTiiFTgXpXycDCgY8'
    }
})
```

I will use `jwt.is` to decode the JWT Token. <br>
![jwt](/assets/img/texsaw-ctf_2025/jwt.png)

But is missing the signature part. So from the hint we get from description, the key for this secret is from challenge `pottermania_part1` which is `SlccjCzySpcxtzyp`. <br>
So let's sign the JWT Token. <br>
![jwt](/assets/img/texsaw-ctf_2025/jwt_signed.png)

The signature has been verified. So what next? <br>
After reading again the hint from the description `Can you direct(ory) Harry to go down the right path to defeat You-Know-Who?`, I think we need to find the right path. <br>

From the payload data we get from the JWT Token, we can see that the `location` is `hogwarts`. <br>
```json
{
    "date": "2025-04-13T03:21:27.310577+00:00",
    "spell": "Protego Maxima",
    "loc": "battle of hogwarts",
}
```

If we search about `battle of hogwarts date` we will the exact date. <br>
![battle](/assets/img/texsaw-ctf_2025/battle.png)

Is `May 2, 1998` when Harry Potter defeated Voldemort so we need to find the correct spell to defeat Voldemort. <br>
After searching, I found this [website](https://harrypotter.fandom.com/wiki/Battle_of_Hogwarts) and I found the correct spell is `Expelliarmus` which is his Disarming Charm. <br>
![expelliarmus](/assets/img/texsaw-ctf_2025/expelliarmus.png)

But I was not able to find the flag but I have found all the information I need and here is the script to get the flag. <br>
```python
import jwt
import requests

SECRET_KEY = 'SlccjCzySpcxtzyp'

SESSION_COOKIE = "tk3kXkymEaa0uE7g_P274TPkEgsX-TX9DrFL_ghzIwI.i2NS5OQ0qHpagdx7eh2HMWE9KV0"

MAGIC_URL = "http://74.207.229.59:20202/magic"

BATTLE_DATE = "1998-05-02T09:45:00.000000+00:00"

LOCATION = "battle of hogwarts"

spells = [
    "Expelliarmus", "Stupefy", "Protego", "Protego Maxima", "Petrificus Totalus", "Reducto",
    "Confringo", "Bombarda", "Diffindo", "Impedimenta", "Rictusempra", "Levicorpus",
    "Incarcerous", "Relashio", "Oppugno", "Finite Incantatem", "Lumos Maxima",
    "Homenum Revelio", "Salvio Hexia", "Cave Inimicum", "Muffliato", "Glisseo",
    "Everte Statum", "Expecto Patronum", "Langlock"
]

print(f"[*] Starting PotterMania Solver...")
print(f"[*] Using secret key: {SECRET_KEY}")
print(f"[*] Using battle date: {BATTLE_DATE}")
print(f"[*] Using location: {LOCATION}")
print(f"[*] Testing {len(spells)} different spells...")

for spell in spells:
    payload = {
        "date": BATTLE_DATE,
        "loc": LOCATION,
        "spell": spell
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    
    headers = {
        "X-Magic-Token": token
    }
    cookies = {
        "session": SESSION_COOKIE
    }
    
    print(f"\n[*] Trying spell: {spell}")
    response = requests.get(MAGIC_URL, headers=headers, cookies=cookies)
    
    if "are u ready to help harry win the war of hogwarts" not in response.text:
        print(f"[+] FOUND INTERESTING RESPONSE with spell: {spell}")
        print(f"[+] Status code: {response.status_code}")
        
        if "texsaw{" in response.text.lower():
            import re
            flag_match = re.search(r'texsaw\{[^}]+\}', response.text, re.IGNORECASE)
            if flag_match:
                print(f"\n[!] FLAG FOUND: {flag_match.group(0)}")
                with open(f"flag_found_{spell}.html", "w") as f:
                    f.write(response.text)
                break
        
        print(f"[+] First 200 chars of response: {response.text[:200]}")
        with open(f"response_{spell}.html", "w") as f:
            f.write(response.text)
    else:
        print(f"[-] No special response with {spell}")

print("\n[*] Script execution completed.")
```

And this technique is about `JWT manipulation` but sadly I can not find the flag because I need to read some information about `Harry Potter` which I have never watched or even read it before. <br>
But thankfully this challenge is getting me to read something about `Harry Potter` =)) <br>

**Flag:** `texsaw{XXX}`