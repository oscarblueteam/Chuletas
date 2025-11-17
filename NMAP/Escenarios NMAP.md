
**Qué comandos introducir, en qué situación y simulación.**

-Escanear una IP en sus primeros 1024 puertos TCP

nmap 192.168.0.X1

-Escanear una simple red /24 con los primeros 1024 puertos.

nmap 192.168.X.X/24

-Escanear una simple red/24 pero para saber que IPs están vivas (no realiza escaneo de puertos)

nmap -sn192.168.X.X/24