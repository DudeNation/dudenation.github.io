---
title: Hack'OSINT CTF 2025
date: 2025-05-26
tags: [ctf, osint]
categories: [CTF Writeups]
author: 2Fa0n
img_path: /assets/img/hack-osint-ctf_2025
image: /assets/img/hack-osint-ctf_2025/hack-osint-ctf_banner.png
---

# OSINT
## Interview
**Solvers:** xxx <br>
**Author:** hack-osint

### Description
The previous document suggests that the interview given by Charlottle is a good starting point. <br>
Can you find out when this interview conducted? <br>
> Flag format: JJ/MM/AAAA

### Solution
When doing this challenge, they provide a document file for us to read and had some information related to the entire challenge. <br>
Start reading and I found a twitter account [@CN_CumSpe](https://x.com/cn_cumspe) <br>

![twitter_account](/assets/img/hack-osint-ctf_2025/twitter_account.png)

Look around the post and found this one: <br>

![twitter_post](/assets/img/hack-osint-ctf_2025/twitter_post.png)

This post is posted on `Feb 2, 2025` <br>

**Flag:** `02/02/2025`

## Qui es-tu?
**Solvers:** xxx <br>
**Author:** hack-osint

### Description
In the interview, Charlotte mentions the name of a person who behaved suspiciously towards her. <br>
Would you be able to identify this person for us? <br>
> Flag format: Henri le Montclair

### Solution
When I look at this post: <br>

![twitter_post](/assets/img/hack-osint-ctf_2025/twitter_post2.png)

I thought **A** is the first letter of the person she trying to mention. <br>
Look back the document and found this: <br>

![document](/assets/img/hack-osint-ctf_2025/document.png)
![document](/assets/img/hack-osint-ctf_2025/document2.png)

Thinking that `Alpha` and `Ainoa Fernandez` is the right answer, result is wrong. <br>
Then I found this [charlotte.nectoux](https://medium.com/@charlotte.nectoux/following) Medium page <br>

Found the profile of the guy that interviewed her: <br>

![medium_profile](/assets/img/hack-osint-ctf_2025/medium_profile.png)

His profile [Marc Steiner](https://medium.com/@marcsteinerdailynews) <br>

Go around and found this conversation: <br>

![medium_conversation](/assets/img/hack-osint-ctf_2025/medium_conversation.png)

So the person she trying to mention is **Nicolas de Richelieu** <br>

**Flag:** `Nicolas de Richelieu`

## Pseudonyme
**Solvers:** xxx <br>
**Author:** hack-osint

### Description
This Nicolas seems very active on social media. Can you find out what username he goes by? <br>
> Flag format: xhacker

### Solution
I search for his page facebook and found this: <br>

![facebook_page](/assets/img/hack-osint-ctf_2025/facebook_page.png)

Check for his reel and found this one really interesting: <br>

![facebook_reel](/assets/img/hack-osint-ctf_2025/facebook_reel.png)

Quite blur, zoom it out. <br>

![facebook_reel_zoom](/assets/img/hack-osint-ctf_2025/facebook_reel_zoom.png)

Yes, got his username. <br>

**Flag:** `Xnicolasht`

## Première approche
**Solvers:** xxx <br>
**Author:** hack-osint

### Description
While investigating this pseudonym, you uncover a place filled with secrets that was meant to remain confidential. <br>
Can you determine exactly when Nicolas <mark>began communication</mark> (a former member of APT-509 arrested in 2024)? <br>
> Flag format: JJ/MM/AAAA

### Solution
I use his username to search and found this `Bluesky` account: <br>

![bluesky_account](/assets/img/hack-osint-ctf_2025/bluesky_account.png)

His profile [xnicolasht.bsky.social](https://bsky.app/profile/xnicolasht.bsky.social) <br>
Found a post that contains a drive link: <br>

![bluesky_post](/assets/img/hack-osint-ctf_2025/bluesky_post.png)

But when zoom it out, there is a missing part. <br>

![bluesky_post_zoom](/assets/img/hack-osint-ctf_2025/bluesky_post_zoom.png)

Use this [image to text](https://www.imagetotext.info/) to convert the image to text. <br>

![image_to_text](/assets/img/hack-osint-ctf_2025/image_to_text.png)

Need to figure out that first part of `.fr/drive/#/2/drive/view/f3YGBpPsdLVDxwpvH+PfWsHBS2nNHpOglwGr-VP9cHI/` <br>

I try to find and the result is that I can not find it and so on the challenge ended =((. <br>

**Flag:** `JJ/MM/AAAA`

After all, this CTF challenge is pretty cool with nice OSINT flow. Definitely gonna try this challenge next year. <br>

Got the badge, awesome! <br>

![badge](/assets/img/hack-osint-ctf_2025/badge.png)

![badge](/assets/img/hack-osint-ctf_2025/badge2.png#center)