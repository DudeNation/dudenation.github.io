---
title: Punk Security DevSecOps birthday CTF
date: 2025-05-05
tags: [ctf, web, ai, password cracking]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/punksecurity-ctf_2025
image: /assets/img/punksecurity-ctf_2025/punksecurity-ctf_banner.png
---

# AI Guardrails!
## Just ask for the flag - Intro
**Solvers:** 390 <br>
**Author:** punksecurity

### Description
The Ai knows the flag, you just need to ask it.

### Solution
Knows the flag, just ask for it =)). <br>

![ai_flag](/assets/img/punksecurity-ctf_2025/ai_flag.png)

**Flag:** `punk_{QART45N5NNDRQZGL}`

# Web
## Zorses awareness
**Solvers:** 271 <br>
**Author:** punksecurity

### Description
Zorses are awesome, we think you'll love them too!
![zorses](/assets/img/punksecurity-ctf_2025/zorses.png)

### Solution
After go through the website, I just found a admin login panel. <br>

![admin_login](/assets/img/punksecurity-ctf_2025/admin_login.png)

So I tried some default credentials like `admin:admin` or `admin:password` but not working. <br>

![not_working](/assets/img/punksecurity-ctf_2025/not_working.png)

Then I tried some basic SQLi.
```bash
admin' or '1'='1
```

Still not working either. Hmm, let's inspect the page and see if any clues. <br>

![inspect](/assets/img/punksecurity-ctf_2025/inspect.png)

I found the `password` is `zorses4ever` and successfully login and grab the flag. <br>

![flag](/assets/img/punksecurity-ctf_2025/flag.png)

**Flag:** `punk_{5BC0T04N242NI8CX}`

## Financial data breach!
**Solvers:** 166 <br>
**Author:** punksecurity

### Description
BritPipe shares the quarterly financial reports every 3 months, but their January report leaked early. <br>
This is not good at all, and their share value has plummeted. <br>
Can you figure out how it happened? <br>
![britpipe](/assets/img/punksecurity-ctf_2025/britpipe.png)

### Solution
After reading the first post, I found this sentence really interesting. <br>

![sentence](/assets/img/punksecurity-ctf_2025/sentence.png)

When I check, there is no report about Q4 2024. <br>

![no_report](/assets/img/punksecurity-ctf_2025/no_report.png)

Then I click on the Q3 2024 and I see a link to pdf file. <br>

![q3_2024](/assets/img/punksecurity-ctf_2025/q3_2024.png)
![pdf](/assets/img/punksecurity-ctf_2025/pdf.png)

What if I change the `report_Q3_2024.pdf` to `report_Q4_2024.pdf`? <br>

![q4_2024](/assets/img/punksecurity-ctf_2025/q4_2024.png)

I got the flag. <br>

**Flag:** `punk_{Y08L9196ZSMB48MQ}`

# Password Cracking!
## Password Cracking - 1
**Solvers:** 134 <br>
**Author:** punksecurity

### Description
The flag is the password for this vault.

### Solution
```bash
┌──(kali㉿kali)-[~]
└─$ cat vault         
$ANSIBLE_VAULT;1.1;AES256
61643339343131623937633938363634353838633532643166353162343034353764623238313134
3664373637333039343265613130643661303132376537620a353362643664353463636338653830
65366434356566643865326635643533373736346535343433666462643634383137346334363737
3735393963326566360a653463616465653934393365663535393361356337376438633864376431
36646333356330363139653830346261326239313363636431666139353939376364
```

I search on google for `ansible value crack` and found this [article](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/). <br>

![article](/assets/img/punksecurity-ctf_2025/article.png)

They use `ansible2john` tool to convert the vault file to hash. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ ansible2john vault > vault.hash

┌──(kali㉿kali)-[~]
└─$ cat vault.hash 
vault:$ansible$0*0*ad39411b97c98664588c52d1f51b40457db281146d76730942ea10d6a0127e7b*e4cadee9493ef5593a5c77d8c8d7d16dc35c0619e804ba2b913ccd1fa95997cd*53bd6d54ccc8e80e6d45efd8e2f5d537764e5443fdbd648174c46777599c2ef6
```

Let's use `john` to crack the hash. <br>

```bash
└─$ john vault.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
zebracakes       (vault)     
1g 0:00:01:12 DONE (2025-05-04 22:23) 0.01375g/s 6245p/s 6245c/s 6245C/s zenab..zalasar
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Successfully cracked and got the password. <br>

**Flag:** `zebracakes`

## Password Cracking - 2
**Solvers:** 150 <br>
**Author:** punksecurity

### Description
The flag is the password for this vault.

### Solution
We got `Passwords.kdb` file. Search and found [github](https://github.com/patecm/cracking_keepass) repo. <br>
Let's jump in and try to crack it. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ keepass2john Passwords.kdb > Passwords.hash

┌──(kali㉿kali)-[~]
└─$ cat Passwords.hash
Passwords.kdb:$keepass$*1*6000*0*de0caa8989332003fb19f2bbb9d231fc*12483160763d1c55664327d50bc438d8b7140475314dcd6e57a5461d6a88b88b*5a39e1cdf4775de9edd74dbbbf314e06*475d12aee0d194acb7ad27c5c34c734595ff7fadda1cbea7abc503b6aa983a66*1*1024*45eb969afa089b0a8d20ecb4207db5cfec3985b59f1d6a2dfcb4dcfb4b4d687d21acf7b4bcc934bd87e879812f013818d72ad3443062ecfc9d90d907748dcc8ba37a77978332f01bcaf1bf06f9c0b66e3187e85dca79898b53cc614eb91f3bdd77ee497645f964066add2b278d7974a9832f2700f9ea0e43fc937da4d377959ca1d2fcbc1fd155d5aefb34a9337cc1aff2c11ea88cae0d9958fd8b10e153888cbd86ab295868b1ddf2384dfa34120e74b727ba556d0365746b3ab66729c0646ede49de0029d9244454b561adec55fa98d2188e01658b38a07b60ecd456225a1b7a90afd85a5362bc8a436f1f071448a04931772b41b4538a2d76f18cda5fbff7261b195b673a38f5b8d7ed9ad59d75fd776b2916aaedd961f9ae94bdca140b5da089386d90c9e97d228f4ff6a25e68ab1832f33d043d6c5cd3334b71f70d880a040c9e9eac30ff5cf3b8fd75034404a78ccdfd370fbd85b8fde3166843cc6ab93b0847d37b7b7e05b9a9e67ea151bc8a224730dff4ec5048b725a7db8c653cb1a20afd77811f5c1c323206e05d877838e79b0fa8fce4277ded08fd9ca888af54beacf1a1618700a13761d4602cfa6aa80026d7e12e186f9dae2a25813d339fe2f5d9fc4f00dfb76ace0f4896c15a966d636f6dfca314db1c4b09f11231e04941dd2266f6ca64dfbace86abe1f5e70c3fa01fbe70377cd43391b2ee995a6825346c987c8c7e3068da7b30be79a9292893ba0ecf12619b5d43aa2372385fb9a5234c344212f7d4c498e2a0954813d94a4be112fa64caf8c020997b98f52d5b25c9801cf1c6e53ff6b6bbfb2a0acf2dba515068100454db102b70198a38cc01c7413c0d6e8058168166da9c413e7307f5295a53318ff09e79acaec1b828aced6546789b490c2bf9f21f411a7f2574b6c6eba7bcbb5d1ee19eb29ee2c7639c20ba2a1a3a7c72a484755fdc1a20e6f14835a8196fb97e994f72df06a9f9857675d17503323d3c8953d028c223f71418172a5b5efdac8dc5242fe5f6f7e1f16fcef9f7f5c93834699b616e2188746b7282724db0b15657c8c9cac4b171ae8a7ed371b23ef8b89b9adf55353a8972e86843d656650f1d021d15fe565faf196468acb0d1740f848f32fe9318a1125e4323200c17a62995aa510fca6e101da8748035a5501db3ba70c6614ef680303f3c9066802e5aa5001cd517a64d9e7d77a0e92d5e11cda62fa5d656ed56bb6ca35d3bd72a2e77aab0122f429ee3a0515c30786ce386105829b52889f43f9a004e06235bdba23e9885f20fcce487385586e30c873de4e2c1d894b7799a76854e660517ab8de65fac147807b29c7466d8c09fa6edd267064179d2632ba7d9c8c3feb7abd28145ff11e5577b80414c81cad0aa967c226aba80d25da6ea288cb289398ff84603e169536c58ca6f79ca5171535166b315a7
```

When read the `README.md` of the repo, I found that we need to remove the first prefix `Passwords.kdb` so that we can able to use `hashcat` to crack it. <br>

![remove_prefix](/assets/img/punksecurity-ctf_2025/remove_prefix.png)

```bash
┌──(kali㉿kali)-[~]
└─$ keepass2john Passwords.kdb | grep -o "$keepass$.*" > Passwords.hash
Inlining Passwords.kdb

┌──(kali㉿kali)-[~]
└─$ cat Passwords.hash
$keepass$*1*6000*0*de0caa8989332003fb19f2bbb9d231fc*12483160763d1c55664327d50bc438d8b7140475314dcd6e57a5461d6a88b88b*5a39e1cdf4775de9edd74dbbbf314e06*475d12aee0d194acb7ad27c5c34c734595ff7fadda1cbea7abc503b6aa983a66*1*1024*45eb969afa089b0a8d20ecb4207db5cfec3985b59f1d6a2dfcb4dcfb4b4d687d21acf7b4bcc934bd87e879812f013818d72ad3443062ecfc9d90d907748dcc8ba37a77978332f01bcaf1bf06f9c0b66e3187e85dca79898b53cc614eb91f3bdd77ee497645f964066add2b278d7974a9832f2700f9ea0e43fc937da4d377959ca1d2fcbc1fd155d5aefb34a9337cc1aff2c11ea88cae0d9958fd8b10e153888cbd86ab295868b1ddf2384dfa34120e74b727ba556d0365746b3ab66729c0646ede49de0029d9244454b561adec55fa98d2188e01658b38a07b60ecd456225a1b7a90afd85a5362bc8a436f1f071448a04931772b41b4538a2d76f18cda5fbff7261b195b673a38f5b8d7ed9ad59d75fd776b2916aaedd961f9ae94bdca140b5da089386d90c9e97d228f4ff6a25e68ab1832f33d043d6c5cd3334b71f70d880a040c9e9eac30ff5cf3b8fd75034404a78ccdfd370fbd85b8fde3166843cc6ab93b0847d37b7b7e05b9a9e67ea151bc8a224730dff4ec5048b725a7db8c653cb1a20afd77811f5c1c323206e05d877838e79b0fa8fce4277ded08fd9ca888af54beacf1a1618700a13761d4602cfa6aa80026d7e12e186f9dae2a25813d339fe2f5d9fc4f00dfb76ace0f4896c15a966d636f6dfca314db1c4b09f11231e04941dd2266f6ca64dfbace86abe1f5e70c3fa01fbe70377cd43391b2ee995a6825346c987c8c7e3068da7b30be79a9292893ba0ecf12619b5d43aa2372385fb9a5234c344212f7d4c498e2a0954813d94a4be112fa64caf8c020997b98f52d5b25c9801cf1c6e53ff6b6bbfb2a0acf2dba515068100454db102b70198a38cc01c7413c0d6e8058168166da9c413e7307f5295a53318ff09e79acaec1b828aced6546789b490c2bf9f21f411a7f2574b6c6eba7bcbb5d1ee19eb29ee2c7639c20ba2a1a3a7c72a484755fdc1a20e6f14835a8196fb97e994f72df06a9f9857675d17503323d3c8953d028c223f71418172a5b5efdac8dc5242fe5f6f7e1f16fcef9f7f5c93834699b616e2188746b7282724db0b15657c8c9cac4b171ae8a7ed371b23ef8b89b9adf55353a8972e86843d656650f1d021d15fe565faf196468acb0d1740f848f32fe9318a1125e4323200c17a62995aa510fca6e101da8748035a5501db3ba70c6614ef680303f3c9066802e5aa5001cd517a64d9e7d77a0e92d5e11cda62fa5d656ed56bb6ca35d3bd72a2e77aab0122f429ee3a0515c30786ce386105829b52889f43f9a004e06235bdba23e9885f20fcce487385586e30c873de4e2c1d894b7799a76854e660517ab8de65fac147807b29c7466d8c09fa6edd267064179d2632ba7d9c8c3feb7abd28145ff11e5577b80414c81cad0aa967c226aba80d25da6ea288cb289398ff84603e169536c58ca6f79ca5171535166b315a7
```

From the repo, we saw that to crack with `hashcat`, we need to use `-m 13400`. Let's try it out. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -a 0 -m 13400 -o Passwords.txt --outfile-format 2 Passwords.hash /usr/share/wordlists/rockyou.txt
```

Successfully cracked and got the password. <br>

**Flag:** `zebralicious`

## Password Cracking - 3
**Solvers:** 48 <br>
**Author:** punksecurity

### Description
`d8e5d901a23c7d3023eedf501b626bfdc4a3b243635491e6d2abd39c0ec7cf9dff0c677383a7558e066d1417b08a3311d0ebcdc5f8b9f219477839dcb0ebfbfe` <br>
Salt: `PunkCTF2025` <br>
The flag is the password.

### Solution
Do not know what hash is that so let's use [hash-identifier](https://www.kali.org/tools/hash-identifier/) to identify it. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hash-identifier                                                                                          
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: d8e5d901a23c7d3023eedf501b626bfdc4a3b243635491e6d2abd39c0ec7cf9dff0c677383a7558e066d1417b08a3311d0ebcdc5f8b9f219477839dcb0ebfbfe

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
```

It could be `SHA-512` or `Whirlpool`. Let's search in `hashcat` to see what type of mode do we need to use, and remember there is a salt which is `PunkCTF2025`. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -h | grep -i sha512 | grep salt 
   1710 | sha512($pass.$salt)                                        | Raw Hash salted and/or iterated
   1720 | sha512($salt.$pass)                                        | Raw Hash salted and/or iterated
   1740 | sha512($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
   1730 | sha512(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
   1760 | HMAC-SHA512 (key = $salt)                                  | Raw Hash authenticated

┌──(kali㉿kali)-[~]
└─$ hashcat -h | grep -i whirlpool | grep salt
```

So we found that there is `HMAC-SHA512` mode. Let's try it out. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -a 0 -m 1760 "d8e5d901a23c7d3023eedf501b626bfdc4a3b243635491e6d2abd39c0ec7cf9dff0c677383a7558e066d1417b08a3311d0ebcdc5f8b9f219477839dcb0ebfbfe:PunkCTF2025" /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================

<SNIP>

d8e5d901a23c7d3023eedf501b626bfdc4a3b243635491e6d2abd39c0ec7cf9dff0c677383a7558e066d1417b08a3311d0ebcdc5f8b9f219477839dcb0ebfbfe:PunkCTF2025:zanyzebra9
                                                          
<SNIP>
```

Successfully cracked and got the password. <br>

**Flag:** `zanyzebra9`

## Password Cracking - 4
**Solvers:** 160 <br>
**Author:** punksecurity

### Description
`$6$Q9/shQzQf6xlQyKr$bfHWQDlkwfvrJTBU0itN6kJeyEwQKfvviQ3buIDDNG1S/77a52unKnEssSw340AOMoGzUiyQ.l60wfho28Ay41` <br>
The flag is the password corresponding with this hash.

### Solution
Use `hash-identifier` to identify the hash. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hash-identifier                                                                                                                                                                                     
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: $6$Q9/shQzQf6xlQyKr$bfHWQDlkwfvrJTBU0itN6kJeyEwQKfvviQ3buIDDNG1S/77a52unKnEssSw340AOMoGzUiyQ.l60wfho28Ay41

 Not Found.
```

`Not Found.` Hmm, let's use the online hash identifier in case of our `hash-identifier` is not up-to-date yet. <br>

![online_hash_identifier](/assets/img/punksecurity-ctf_2025/online_hash_identifier.png)

We use this website [hash_identifier](https://hashes.com/en/tools/hash_identifier) and we got `sha512crypt` hash. <br>
Let's search for the mode of `sha512crypt` in `hashcat`. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -h | grep -i sha512crypt
   1800 | sha512crypt $6$, SHA512 (Unix)                             | Operating System
```

So we found that the mode is `1800`. Let's try to crack it with `hashcat`. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -a 0 -m 1800 "$6$Q9/shQzQf6xlQyKr$bfHWQDlkwfvrJTBU0itN6kJeyEwQKfvviQ3buIDDNG1S/77a52unKnEssSw340AOMoGzUiyQ.l60wfho28Ay41" /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-skylake-avx512-Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz, 1424/2912 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hash '/shQzQf6xlQyKr/77a52unKnEssSw340AOMoGzUiyQ.l60wfho28Ay41': Separator unmatched
No hashes loaded.

Started: Sun May  4 23:07:12 2025
Stopped: Sun May  4 23:07:12 2025
```

Due to some syntax that make `hashcat` hard to crack so we put in a `file` to crack it. <br>

```bash
┌──(kali㉿kali)-[~]
└─$ echo '$6$Q9/shQzQf6xlQyKr$bfHWQDlkwfvrJTBU0itN6kJeyEwQKfvviQ3buIDDNG1S/77a52unKnEssSw340AOMoGzUiyQ.l60wfho28Ay41' > password4.hash

┌──(kali㉿kali)-[~]
└─$ hashcat -a 0 -m 1800 password4.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================

<SNIP>

$6$Q9/shQzQf6xlQyKr$bfHWQDlkwfvrJTBU0itN6kJeyEwQKfvviQ3buIDDNG1S/77a52unKnEssSw340AOMoGzUiyQ.l60wfho28Ay41:pinkzebra
                                                          
<SNIP>
```

Got the password. <br>

**Flag:** `pinkzebra`

## Password Cracking - 5
**Solvers:** 197 <br>
**Author:** punksecurity

### Description
`92d7dcb3b27551277307d46856325798` <br>
The flag is the password corresponding with this hash.

### Solution
Use [crackstation](https://crackstation.net/) to crack the hash. <br>

![crackstation](/assets/img/punksecurity-ctf_2025/crackstation.png)

**Flag:** `3greenzebras`