# Informe Técnico de Respuesta a Incidentes

**Organización:** 4Geeks Academy
**Sistema afectado:** `4geeks-server` — Ubuntu 20.04.6 LTS (kernel 5.4.0-216) · VirtualBox · IP 192.168.1.127
**Tipo de respuesta:** Live Incident Response (sistema activo, no se apaga)
**Analista:** _[tu nombre]_ · **Fecha del análisis:** 13 jun 2026

---

## 1. Resumen ejecutivo

El servidor `4geeks-server` fue **comprometido mediante acceso SSH con credenciales válidas de la cuenta `sysadmin`** desde la IP `192.168.1.50` (21 jun 2025). El atacante estableció persistencia y desplegó un mecanismo de **exfiltración de datos activo**: un *script* programado (`backup2.sh`) que cada 15 minutos empaqueta `/etc/passwd` y lo envía a un servidor externo (`192.168.1.100:8080`). Se identificaron además **dos cuentas de usuario no autorizadas** (`hacker`, `reports`) y **borrado de huellas** (historiales de shell vacíos). Un proceso que en un inicio parecía sospechoso (binario borrado) fue investigado y **descartado** como componente legítimo del kernel (`bpfilter_umh`).

La causa raíz es una **configuración SSH permisiva** (autenticación por contraseña habilitada) combinada con **credenciales débiles/comprometidas** sobre un **sistema fuera de soporte y sin parches**. El incidente fue contenido, erradicado y el sistema fortalecido siguiendo el ciclo NIST SP 800-61. **Las credenciales de `sysadmin` se consideran comprometidas y deben rotarse de inmediato.**

---

## 2. Alcance y metodología

El análisis se realizó sobre el sistema en producción (Live IR), priorizando la disponibilidad del servicio. Se siguió el marco **NIST SP 800-61 / SANS PICERL**: recolección de evidencia en orden de volatilidad, contención, erradicación, recuperación y fortalecimiento. Herramientas utilizadas: utilidades nativas del sistema (`ps`, `ss`, `last`/`lastb`, `auth.log`, `find`, `crontab`, `systemctl`) y verificadores de integridad recomendados (`rkhunter`, `chkrootkit`, `lynis`).

---

## 3. Cronología del incidente

| Fecha / hora (UTC) | Evento | Evidencia |
|---|---|---|
| Sáb 21 jun 2025 19:36 | Intentos fallidos de `root` por SSH desde 192.168.1.50 | `lastb` |
| **Sáb 21 jun 2025 19:38:47** | **Acceso EXITOSO: `Accepted password` de `sysadmin` desde 192.168.1.50** | `auth.log` |
| Lun 23 jun 2025 ~14:07 | Sesión de la cuenta `reports` por consola (`tty1`) | `lastlog` |
| Lun 23 jun 2025 15:24–15:29 | Fuerza bruta SSH desde 192.168.1.103 (test/admin/hacker/root) — fallida | `auth.log`, `lastb` |
| (post-acceso) | Persistencia desplegada: cuentas rogue (`hacker`, `reports`) y cron de exfiltración (`backup2.sh`) | sistema |
| Vie 13 jun 2026 03:45 | `/tmp/secrets.tgz` regenerado por `backup2.sh` (exfiltración activa) | `ls -la /tmp` |

---

## 4. Hallazgos y vulnerabilidades

### 4.1 Indicadores de compromiso (IOCs)

| # | Tipo | Indicador | Estado |
|---|---|---|---|
| 1 | Acceso inicial | Credenciales de `sysadmin` comprometidas (login desde **192.168.1.50**) | Confirmado |
| 2 | Exfiltración | `/usr/local/bin/backup2.sh` → `curl POST` de `/etc/passwd` a **192.168.1.100:8080** cada 15 min | Confirmado |
| 3 | Artefacto | `/tmp/secrets.tgz` (contiene `etc/passwd`) — *staging* de exfiltración | Confirmado |
| 4 | Cuenta rogue | `hacker` (UID 1002, `/bin/bash`) | Confirmado |
| 5 | Cuenta rogue | `reports` (UID 1001, `/bin/bash`) | Confirmado |
| 6 | IP fuerza bruta | 192.168.1.103 (intentos fallidos, 23 jun) | Confirmado |
| 7 | Anti-forense | `.bash_history` vacíos en todas las cuentas | Confirmado |

### 4.2 Vulnerabilidades de configuración (causa raíz)

- **SSH con autenticación por contraseña habilitada** y sin restricción de `root` → permitió el acceso por credenciales.
- **Credenciales débiles/comprometidas** de `sysadmin`.
- **Sistema operativo fuera de soporte y sin parches** (Ubuntu 20.04 EOL, release 22.04 disponible sin aplicar).
- **Sin filtrado de salida (egress)**: el sistema pudo enviar datos a `192.168.1.100:8080` sin restricción.
- **Servicios expuestos** innecesarios: `vsftpd` (21/tcp) y `apache2` (80/tcp).

### 4.3 Vectores verificados y descartados

Para demostrar exhaustividad, se confirmó que los siguientes vectores **están limpios**: solo `root` con UID 0; solo `sysadmin` en el grupo `sudo`; sin servicios ni *timers* systemd maliciosos; `/etc/ld.so.preload` vacío; sin binarios SUID anómalos; sin módulos de kernel sospechosos; `resolv.conf`/`hosts` íntegros; **sin** persistencia por claves SSH (`authorized_keys` vacíos). Se investigó `/opt/scripts/logrotate.sh` y se determinó **benigno** (solo ejecuta `logrotate /etc/logrotate.conf`); no requiere erradicación.

**Falso positivo notable — proceso con binario borrado:** durante el reconocimiento se observó un proceso ejecutándose desde un binario borrado (`/proc/<pid>/exe -> / (deleted)`), cuyo PID cambiaba en cada arranque (389 → 392), patrón que inicialmente sugería malware *fileless* persistente. La interrogación del proceso lo descartó como amenaza: su padre es el **PID 2 (`kthreadd`)**, lo que prueba que es un **hilo lanzado por el kernel** (un proceso de usuario no puede ser hijo de `kthreadd`); su `cmdline` es **`bpfilter_umh`**, el *user-mode helper* legítimo del subsistema **bpfilter** del kernel de Linux; su `cgroup` está en la raíz y se comunica con el kernel vía `/dev/kmsg`. El binario "(deleted)" es la firma normal de un UMH (el kernel ejecuta un binario embebido en memoria). **Conclusión: componente legítimo del kernel, no requiere acción.**

---

## 5. Acciones de contención, erradicación y recuperación

> **Orden aplicado:** contener → eliminar persistencia → erradicar proceso/artefactos → recuperar → verificar. Cada acción se justifica y se verifica.

### 5.1 Contención
| Acción | Comando | Justificación |
|---|---|---|
| Cortar exfiltración y acceso del atacante | `sudo ufw deny out to 192.168.1.100` ; `sudo ufw deny from 192.168.1.103` | Detiene el envío de datos al C2 y bloquea la fuente de fuerza bruta sin tumbar el servicio. |
| Bloquear cuentas rogue | `sudo passwd -l hacker reports` ; `sudo usermod -s /usr/sbin/nologin hacker reports` | Impide nuevos accesos mientras se erradica. |

### 5.2 Erradicación
| Acción | Comando | Justificación |
|---|---|---|
| Eliminar el cron de exfiltración | retirar la línea `backup2.sh` de `/etc/cron.d/…` y `sudo rm /usr/local/bin/backup2.sh` | Quita la persistencia ANTES de detener el proceso, para que no se regenere. |
| Borrar el artefacto de *staging* | `sudo rm -f /tmp/secrets.tgz` | Elimina los datos ya empaquetados para exfiltración. |
| (Falso positivo investigado) | Proceso de binario borrado (PID 389/392): `cat /proc/<pid>/status`, `cgroup`, `lsof` — **no se elimina** | Identificado como `bpfilter_umh`, *user-mode helper* legítimo del kernel (PPid 2 = `kthreadd`). No es malware; eliminarlo sería un error. |
| Eliminar cuentas no autorizadas | `sudo userdel -r hacker` ; `sudo userdel -r reports` | Cierra el acceso de las cuentas creadas por el atacante. |
| (Distractor benigno) | `/opt/scripts/logrotate.sh` — **no se elimina**; opcionalmente se retira su entrada de cron redundante | Es legítimo; eliminarlo sería un error de remediación. |

### 5.3 Recuperación
| Acción | Comando | Justificación |
|---|---|---|
| **Rotar credenciales de `sysadmin`** | `sudo passwd sysadmin` | La cuenta fue el vector de acceso; su contraseña está comprometida. |
| Verificar integridad del sistema | `sudo rkhunter --check --sk` ; `sudo chkrootkit` | Confirma que no quedan rootkits ni binarios alterados (0 hallazgos). |
| Verificar ausencia de la exfiltración | `ls -la /tmp` ; `sudo ss -tnp` ; `sudo crontab -l` y `cat /etc/cron.d/*` | Confirma que `secrets.tgz` no reaparece y no hay conexión a `.100`. |

---

## 6. Fortalecimiento (Hardening) y recomendaciones

| Frente | Medida | Objetivo |
|---|---|---|
| SSH | `PermitRootLogin no`, `PasswordAuthentication no` (solo claves), `AllowUsers sysadmin`, `MaxAuthTries 3` + **Fail2ban** | Cerrar la causa raíz: eliminar login por contraseña y fuerza bruta. |
| Firewall | **UFW** con *default deny* (entrada y salida); permitir solo puertos del servicio | Impedir exfiltración y reducir superficie de ataque (filtrado de egress). |
| Parches | `apt full-upgrade` + `unattended-upgrades`; planificar migración desde 20.04 EOL | Eliminar vulnerabilidades conocidas. |
| Servicios | Deshabilitar `vsftpd` y `apache2` si no son necesarios | Reducir la superficie expuesta. |
| Auditoría | `auditd` con reglas + línea base con **AIDE** | Detectar futuros cambios no autorizados. |
| Monitorización | Aprovechar el **Wazuh** ya instalado para alertar sobre logins y cambios | Detección temprana de reincidencias. |
| Métrica | Verificación de configuración antes/después: `sshd -T`, `ufw status verbose`, `systemctl is-enabled` | Evidencia concreta del endurecimiento aplicado. |

> **Recomendación de madurez:** dado que el host estuvo comprometido con acceso de root del atacante y exfiltración de datos activa, la práctica de oro sería **reconstruir el servidor desde una imagen confiable** y restaurar datos validados, además de realizar un **análisis de causa raíz**. La remediación en vivo se aplicó por la prioridad de disponibilidad del laboratorio.

---

## 7. Conclusión

El incidente correspondió a un acceso no autorizado por credenciales SSH comprometidas, con persistencia mediante cuentas rogue y un mecanismo de exfiltración activo hacia un servidor externo. La respuesta contuvo la amenaza (corte de exfiltración y bloqueo del atacante), erradicó la persistencia (cron de exfiltración, cuentas rogue y artefactos) y recuperó la integridad del sistema, cerrando la causa raíz mediante el endurecimiento de SSH, firewall con filtrado de salida y aplicación de parches. La lección principal: una sola credencial débil sobre un servicio expuesto y sin filtrado de egress fue suficiente para comprometer y exfiltrar datos del sistema.

---

## 8. Anexos — Evidencia

Las capturas que respaldan cada hallazgo se encuentran en `evidencias/`. Referencias clave:

- Identidad del sistema y fechas — `uname`, `hostnamectl`, `date`
- Acceso exitoso del atacante — `grep "Accepted" /var/log/auth.log`
- Fuerza bruta — `lastb`, `auth.log`
- Cuentas rogue — `/etc/passwd`, `lastlog`
- Exfiltración — `cat /usr/local/bin/backup2.sh`, `tar tzf /tmp/secrets.tgz`
- Proceso con binario borrado — `ls -l /proc/*/exe | grep deleted`
- Persistencia (cron) — `cat /etc/cron.d/*`
- Vectores descartados — `ld.so.preload`, SUID, `authorized_keys`, systemd
