--EN DESARROLLO--

from netmiko import ConnectHandler
import getpass
import sys

# ----------------------------------------------------------
# 1 - Mensaje de advertencia
# ----------------------------------------------------------
print("\n*** ADVERTENCIA ***")
print("Está accediendo a un equipamiento controlado y restringido.")
print("El uso no autorizado puede ser sancionado.\n")

# ----------------------------------------------------------
# 2 - Preguntar protocolo SSH o Telnet
# ----------------------------------------------------------
protocolo = input("¿Desea conectarse por SSH o Telnet? (ssh/telnet): ").strip().lower()

if protocolo not in ["ssh", "telnet"]:
    print("Protocolo no válido. Saliendo.")
    sys.exit()

# ----------------------------------------------------------
# 3 - Preguntar dirección IP
# ----------------------------------------------------------
ip = input("Introduzca la dirección IP del switch: ").strip()

# ----------------------------------------------------------
# 4 - Credenciales modo EXEC
# ----------------------------------------------------------
usuario = input("Usuario (modo EXEC): ")
password = getpass.getpass("Password (modo EXEC): ")

# ----------------------------------------------------------
# 5 - Credenciales modo privilegiado
# ----------------------------------------------------------
enable_pass = getpass.getpass("Password modo privilegiado (enable): ")

# ----------------------------------------------------------
# Definir conexión
# ----------------------------------------------------------
device = {
    "device_type": "cisco_ios_telnet" if protocolo == "telnet" else "cisco_ios",
    "ip": ip,
    "username": usuario,
    "password": password,
    "secret": enable_pass,
}

# ----------------------------------------------------------
# Conexión al dispositivo
# ----------------------------------------------------------
print("\nConectando al switch...\n")

try:
    conexion = ConnectHandler(**device)
    conexion.enable()
except Exception as e:
    print(f"Error al conectar: {e}")
    sys.exit()

# ----------------------------------------------------------
# Ejecutar comandos
# ----------------------------------------------------------
comandos = [
    "show version",
    "show running-config",
    "show interface status",
    "show log"
]

salida_total = ""

for cmd in comandos:
    print(f"Ejecutando: {cmd}")
    salida = conexion.send_command(cmd)
    salida_total += f"\n\n===== {cmd} =====\n{salida}"

# Obtener hostname del switch
hostname = conexion.find_prompt().replace("#", "").strip()

# ----------------------------------------------------------
# Guardar resultados
# ----------------------------------------------------------
archivo = f"{hostname}.txt"

with open(archivo, "w") as f:
    f.write(salida_total)

print(f"\nResultados guardados en: {archivo}\n")

conexion.disconnect()
