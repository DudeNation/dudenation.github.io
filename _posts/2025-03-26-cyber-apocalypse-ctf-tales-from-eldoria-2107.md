---
title: Cyber Apocalypse CTF - Tales from Eldoria 2107
date: 2025-03-26
tags: [ctf, osint]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/cyber-apocalypse-ctf-tales-from-eldoria-2107
image: /assets/img/cyber-apocalypse-ctf-tales-from-eldoria-2107/cyber_apocalypse_banner.png
---

# Osint
## The Ancient Citadel
**Solvers:** xxx <br>
**Author:** Joaquin Iglesias

### Description
Deep in her sanctum beneath Eldoria's streets, Nyla arranges seven crystalline orbs in a perfect circle. Each contains a different vision of stone battlements and weathered walls—possible matches for the mysterious fortress the Queen seeks in the southern kingdoms of Chile. The image in her central crystal pulses with ancient power, showing a majestic citadel hidden among the distant Chilean mountains. Her fingers dance across each comparison crystal, her enchanted sight noting subtle architectural differences between the visions. The runes along her sleeves glow more intensely with each elimination until only one crystal remains illuminated. As she focuses her magical threads on this final vision, precise location runes appear in glowing script around the orb. Nyla smiles in satisfaction as the fortress reveals not just its position, but its true name and history. A more challenging mystery solved by Eldoria's premier information seeker, who knows that even the most distant fortifications cannot hide their secrets from one who compares the patterns of stone and shadow.

![ancient_citadel](/assets/img/cyber-apocalypse-ctf-tales-from-eldoria-2107/ancient_citadel.png)

### Solution
Upload image to Google reverse image search and we identify the name of the castle. <br>

![castle](/assets/img/cyber-apocalypse-ctf-tales-from-eldoria-2107/castle.png)

It show the name of the castle is `Castillo Brunet`, when click on that name, it gives more information about the address of the castle. <br>

![castle_info](/assets/img/cyber-apocalypse-ctf-tales-from-eldoria-2107/castle_info.png)

There we go, look at the flag format `HTB{street number,postal code city, region}`.

**Flag:** `HTB{Iberia_104_2571409_Viña_del_Mar_Valparaíso}`

## The Poisoned Scroll
**Solvers:** xxx <br>
**Author:** Joaquin Iglesias

### Description
In her crystal-lit sanctum, Nyla examines reports of a series of magical attacks against the ruling council of Germinia, Eldoria's eastern ally. The attacks all bear the signature of the Shadow Ravens, a notorious cabal of dark mages known for their espionage across the realms. Her fingers trace connections between affected scrolls and contaminated artifacts, seeking the specific enchantment weapon deployed against the Germinian leaders. The runes along her sleeves pulse rhythmically as she sifts through intercepted messages and magical residue analyses from the attack sites. Her network of information crystals glows brighter as patterns emerge in the magical attacks—each victim touched by the same corrupting spell, though disguised under different manifestations. Finally, the name of the specific dark enchantment materializes in glowing script above her central crystal. Another dangerous threat identified by Eldoria's master information seeker, who knows that even the most sophisticated magical weapons leave distinctive traces for those who know how to read the patterns of corruption.

### Solution
After reading the description, these are some keywords to identify for our research:
- `Germinia` -> Germany
- `against the Germinian leaders` -> maybe against the politics of Germany
- `Her network of information crystals glows brighter as patterns emerge in the magical attacks—each victim touched by the same corrupting spell, though disguised under different manifestations.` -> could be a popular malware

Gather these information which leads to `malware target german politics`, let's google it out to find that malware. <br>

![malware](/assets/img/cyber-apocalypse-ctf-tales-from-eldoria-2107/malware.png)

From the result, we could see that the malware is `WINELOADER` which is used by APT29 in these attacks. <br>

**Flag:** `HTB{WINELOADER}`