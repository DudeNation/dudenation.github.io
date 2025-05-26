---
title: NahamCon CTF 2025 - OSINT
date: 2025-05-26
tags: [ctf, osint]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/nahamcon-ctf_2025
image: /assets/img/nahamcon-ctf_2025/nahamcon-ctf_banner.png
---

# OSINT
## Taken to School
**Solvers:** 214 <br>
**Author:** @Jstith

### Description
"I was reading the news this week, and I saw that a student tried to hack a school's computer system!" a worried professor remarked to an IT employee during lunch. "I'm glad we've got people like you keeping our network safe." While Bob the IT admin appreciated the warm comment, his stomach dropped. "Dang it.. I haven't checked that firewall since we set it up months ago!".

IT has pulled a log file of potentially anomalous events detected by the new (albeit poorly tuned) network security software for your school. Based on open-sourced intelligence (OSINT), identify the anomalous entry in the file.

Each log entry contains a single line, including an MD5 hash titled <span style="color:hotpink">eventHash</span>.

The challenge flag is <span style="color:hotpink">flag{MD5HASH}</span> containing the <span style="color:hotpink">eventHash</span> of the anomalous entry.

### Solution
They give us a `network-log.cef` file and see out that there are lot of log entries from **2024**. <br>

![network-log](/assets/img/nahamcon-ctf_2025/network-log.png)

Our goal is to find the correct hash that is anomalous. <br>

Read through the discription, it's topic generaly about `Hack school`. So I search for `hack school few month ago` on google. <br>

![google_search](/assets/img/nahamcon-ctf_2025/google_search.png)

Found this article [Powerschool Hack: Data Breach Protect Student, School, Teacher Safe](https://www.nbcnews.com/tech/security/powerschool-hack-data-breach-protect-student-school-teacher-safe-rcna189029) <br>

The target is `Powerschool`. Search for `Powerschool hack` on google. <br>

![powerschool_hack](/assets/img/nahamcon-ctf_2025/powerschool_hack.png)

Notice this [Powerschool Security Incident](https://www.powerschool.com/security/sis-incident/) <br>

Go though and found section `CrowdStrike Incident Report` submitted `incident report`.

![powerschool_incident](/assets/img/nahamcon-ctf_2025/powerschool_incident.png)

Check it out and found this section `Appendix A: Indicators of Compromise`. <br>

![indicators_of_compromise](/assets/img/nahamcon-ctf_2025/indicators_of_compromise.png)

Show list of IOC. Find out this one `91.218.50[.]11` in the log file. <br>

![iocs](/assets/img/nahamcon-ctf_2025/iocs.png)

```bash
2024-12-22T15:07:40 CEF:0|PaloAltoNetworks|PAN-OS|8.3|44985|Trojan Signature Match|9|src=91.218.50.11 dst=192.168.113.2 spt=27660 dpt=443 proto=HTTPS act=allowed fileName=chemistry_notes.pdf eventHash=5b16c7044a22ed3845a0ff408da8afa9 cs1Label=threatType cs1=trojan
```

Got the eventHash `5b16c7044a22ed3845a0ff408da8afa9` <br>

**Flag:** `flag{5b16c7044a22ed3845a0ff408da8afa9}`

For this challenge, I do not have enough time so just solve one challenge only. The rest of the challenge really interesting, definitely will try it later 🔥. 

![certificate](/assets/img/nahamcon-ctf_2025/certificate.png)