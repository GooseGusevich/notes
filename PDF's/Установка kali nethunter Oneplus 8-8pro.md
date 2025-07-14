Инструкция только для Oneplus 8/8t/8pro
Подготавливаем почву:
1. Узнать страну изготовителя модели телефона:
- **IN - Индия**
- **CN - Китай**
- **EU - Европейский рынок**
- **NA - Северная Америка**
1. Переходим на сайт скачиваем откат для своего телефона 
Oneplus 8 https://onepluscommunityserver.com/list/Unbrick_Tools/OnePlus_8/
Oneplus 8t https://onepluscommunityserver.com/list/Unbrick_Tools/OnePlus_8T/
Oneplus 8pro https://onepluscommunityserver.com/list/Unbrick_Tools/OnePlus_8_Pro/
2. Скачиваем TWRP:
Oneplus 8,8t,8pro: https://drive.google.com/file/d/1rP7HjWim9oADLQ2vVmP3B5LaDuKG1nvV/view?usp=sharing
3. Скачиваем еще одну прошивку под вашу модель телефона и страну производителя fw_Oneplus****_*OOS13_F64.zip:
Oneplus 8 https://mega.nz/folder/W7JhwTAT#Yu6cxqvJcAC28cy0m_kkQA/folder/Tv41nBwJ
Oneplus 8t https://mega.nz/folder/W7JhwTAT#Yu6cxqvJcAC28cy0m_kkQA/folder/arpUDS5T
Oneplus 8pro https://mega.nz/folder/W7JhwTAT#Yu6cxqvJcAC28cy0m_kkQA/folder/SzwzkZbY
4. Скачиваем Cdroid Версия 9.9 так же на свой телефон:
Oneplus 8 https://sourceforge.net/projects/crdroid/files/instantnoodle/9.x/
Oneplus 8t https://sourceforge.net/projects/crdroid/files/kebab/9.x/
Oneplus 8pro https://sourceforge.net/projects/crdroid/files/instantnoodlep/9.x/
5. Для своего телефона[vbmeta] ,[recovery] :
Oneplus 8: t.me/crDroidAndroid
Oneplus 8t: t.me/crDroidAndroid
Oneplus 8pro:  https://drive.google.com/file/d/15RT4ql-hvu6UDBx-3Xte6fJXN65V953w/view?usp=sharing
https://drive.google.com/file/d/1y0Ow0yUbkm_Ffc_-jX3TPalbBpeQjh0k/view?usp=sharing

________________________________________________________________________
Oneplus USB Driver: https://oneplususbdrivers.com/oneplus-8-pro-usb-drivers-download/
________________________________________________________________________
Драйвер EDL: https://qcomdriver.com/
________________________________________________________________________
Драйвер Андроид (adb): https://xdaforums.com/attachments/qdloader-hs-usb-driver_32_64bit_setup-zip.5475023/?hash=a2246ade1de8a4670e50229daf27342d
________________________________________________________________________
platform tools:https://developer.android.com/tools/releases/platform-tools
________________________________________________________________________
Google apps (по желанию[Желательно])
https://sourceforge.net/projects/nikgapps/files/Releases/Android-13/18-Jul-2024/NikGapps-core-arm64-13-20240718-signed.zip/download
https://drive.google.com/file/d/17nAGOLiKqg0bxpcqqbDIYe6WnEcQw39I/view?usp=sharing

________________________________________________________________________
Magisk 27.0:https://magisksu.ru/
https://drive.google.com/file/d/1LgImNbL-6kknpcKXWSIOXRvsTcBtnqjK/view?usp=sharing
https://drive.google.com/file/d/1FSYMUOcFAm7k7VmBUvnTfRT2Iqo9O7GL/view?usp=sharing

________________________________________________________________________
Termux:https://f-droid.org/repo/com.termux_1020.apk
https://drive.google.com/file/d/1chMhL-z4_ceCm0XqJDcQmqP0QfBqqQsX/view?usp=sharing
________________________________________________________________________
RO2RW:https://sourceforge.net/projects/multi-function-patch/files/RO2RW/RO2RW-StableBeta.v3.7.2.1.zip/download
https://drive.google.com/file/d/1HoFAPiriaL6MbyKr2O72wO5euEbhwa3s/view?usp=sharing
________________________________________________________________________
Kernel manager: https://f-droid.org/repo/com.smartpack.kernelmanager_177.apk
https://drive.google.com/file/d/1YZNWFSyd2WTEXkL5A8GoiQmeGFrF1_Ap/view?usp=sharing
________________________________________________________________________
Kali nethunter:http://old.kali.org/nethunter-images/kali-2024.1/nethunter-2024.1-oneplus8-all-twelve-kalifs-full.zip

________________________________________________________________________
kernel nethunter:
https://xdaforums.com/attachments/neternel_modules_opkona-zip.5859487/
https://drive.google.com/file/d/11Qyv1iXHubRiPkV785xvdIMq-nKLVAlf/view?usp=sharing
https://xdaforums.com/attachments/neternel_v1_opkona-zip.5859489/
https://drive.google.com/file/d/1d1nXXJD7hdoFc1dfv8NjJO9q64-bU7gY/view?usp=sharing
________________________________________________________________________

Проверяем страну производителя телефона у меня это Индия. Для каждой подели выше предоставлены ссылки на загрузку прошивок, драйверов, приложений.
Запускаем MSM Tool, выключаем телефон и подключаем к ПК, переходим в режим EDL(зажимаем все кнопки), в диспетчере устройств должен выставится неопознанное устройство, Устанавливаем драйвера и запускаем откат на стоковую прошивку)

После того как все откатилось вам нужно будет поднять свою версию  Oxygen 13 (НЕ БОЛЬШЕ) через локальное обновления (ну или каждый раз, постепенно загружать и устанавливать новую версию Oxygen )
Включаем режим разработчика и разрешаем отладку по usb и разблокировка загрузчика.
В диспетчере устройств опять появится неопознанное устройство устанавливаем еще одни драйвер)
после установки заходим в platform tools и перезагружаемся в bootloder
```
adb reboot bootloader
```

И конечно же разблокируем загрузчик
```
fastboot oem unlock
```

Жмем ЗВУК - и соглашаемся 
После перезагрузки снова включаем режим разработчика и тыкаем на отладку по USB 
опять же перезагружаемся в bootloder 

```
adb reboot bootloader
```

И шьем TWRP в boot (временно)
```
fastboot boot TWRP.img
```

БЕЗ ЭТОЙ МАНИПУЛЯЦИИ МОЗМОЖНО НЕ БУДУТ РАБОТАТЬ СИМ КАРТЫ НА Cdroid.
Закидываю fw_Oneplus8pro_IN_OOS13_F64 (в моем случае) на телефон и устанавливаю в TWRP и перезагружаюсь в bootlader.

и записываем туда уже для своей модели телефона свои файл vbmeta
```
fastboot flash vbmeta vbmeta.img
```

и записываем туда уже для своей модели телефона свои файл recovery 
```
fastboot flash recovery recovery.img
```
Заходим в Recovery и через sideload заливаем прошивку

```
adb sideload cdroid.zip
```

После установки не выходим из recovery
Если не нужны google apps то просто перезапускаемся в систему
Если нужны отходим до главного меню и перезапускаемся в recovery

Там уже с такими же действиями через sideload загружаем google apps

```
adb sideload NikGapps-core-arm64-13-20240718-signed.zip
```

После установки перезагружаемся
По пути нас попросят формоваться мы соглашаемся 

После того как установили все необходимое нужно включить режим разработчика и включить отладку по USB
После этого перезагружаемся в RECOVERY и через ADB sideload устанавливаем Magisk 27.0(APK файл заверните в архив)
```
adb sideload Magisk27.0.zip
```

После установки перезагружаемся в систему и устанавливаем Magisk27.0.apk
после установки он предложит перезагрузится, перезагружаемся и обратно заходим в Magisk и уже автоматически пропатчим boot образ, опять же после перезагрузки рут права на месте)
В Magisk через модули устанавливаем RO2RW и перезагружаемся
Устанавливаем Termux заходим в него и прописываем 

```
apt updade && apt upgrade -y
```

после установки и обновлений получаем рут права в termux 
```
su
```
И пишем 
```
ro2rw
```

ответы на вопросы)
```
«1» (установить), «1» (макс. расширение 1), «1» (продолжить), «2» (ДА для DFE), «любой ключ», «2» (НЕТ УДАЛИТЬ), «2» (НЕТ BACKUP), «1» (быстрая загрузка/разреженная), «1» (принудительное отключение)
```

Выходим из TERMUX и копируем себе на комп rw  super img 

перезагружаемся в bootloader
```
adb reboot bootloader
```
и прошиваем его)
```
fastboot flash super super-rw-sparse*.img
```

Процесс долгий может показаться что все встало не не спешите)
После установки загружаемся в RECOVERY и сформатируемся )
Получаем разработчика и включаем отладку
Как вошли в систему установите Magisk еще раз только APK и модуль RORW

Устанавливаем через Magisk Kali nethunter

После установки nethunter заходим в само приложение nethunter разрешая ему все!
Далее заходим в терминал и вводим туда эти команды 
Лично я подключался подключался по SSH 
```
sudo nano /etc/apt/apt.conf.d/10sandbox
```
и закидываем через nano вот это 
енеее
```
echo 'APT::Sandbox::User "root";
```

```
sudo apt clean 
```

```
sudo apt update && sudo apt full-upgrade -y 
```

```
sudo apt --fix-broken install -y
```

```
apt install kali-linux-everything -y 
```

```
apt autoremove
```

после того как все зависимости ,пакеты, и.т.д. установилось, устанавливаем kernel manager 
После установки закидываем в smart paсk neternel_v1_opkona-zip
Перезагружаемся и после закидываем уже в Magisk модуль neternel_modules_opkona-zip
опять перезагружаемся 
Заходим в kernel manager > скрипты и создаем скрипт под названием external_wifi_driver_load

и туда закидываем и сохраняем 
```
insmod /system/lib/modules/rtl_drivers/88XXau.ko 
insmod /system/lib/modules/rtl_drivers/8188eu.ko 
insmod /system/lib/modules/rtl_drivers/8192eu.ko 
insmod /system/lib/modules/rtl_drivers/8192fu.ko 
insmod /system/lib/modules/rtl_drivers/8814au.ko
```
на против скрипта в меню ставим галочку при загрузке
перезагружаемся и радуемся)

Источники:
```http
https://www.youtube.com/watch?v=JeRzpvqr1kM&t=1209s
https://xdaforums.com/t/rom-unofficial-nethunter-oneplus-8t-android-11-12-26-08-21.4324555/page-20#post-88269379
```