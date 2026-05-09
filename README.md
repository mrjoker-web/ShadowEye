# 👁️ ShadowEye — Network Device Monitor

> Part of **Shadow Suite** by [Mr Joker](https://github.com/mrjoker-web) | For educational purposes and authorized networks only.

```
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗    ███████╗██╗   ██╗███████╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║    ██╔════╝╚██╗ ██╔╝██╔════╝
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║    █████╗   ╚████╔╝ █████╗
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║    ██╔══╝    ╚██╔╝  ██╔══╝
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝    ███████╗   ██║   ███████╗
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚══════╝   ╚═╝   ╚══════╝
                    Network Monitor v1.0 — Shadow Suite
```

---

## 🔍 O que faz

ShadowEye descobre e monitoriza todos os dispositivos conectados à tua rede local. Ideal para verificar quem está na tua rede, detetar intrusos e fazer recon local antes de um pentest autorizado.

---

## ⚡ Features

| Feature | Descrição |
|---|---|
| 🔎 ARP Scan | Descobre hosts ativos via ARP (rápido e fiável) |
| 🏭 Vendor Lookup | Identifica fabricante pelo MAC address (offline) |
| 🖥️ OS Guess | Estimativa de OS via TTL (Linux/Android, Windows, Network Device) |
| 🌐 Hostname | Resolução reversa de DNS por dispositivo |
| ⏱️ Latency | Latência via ping por dispositivo |
| 🔌 Port Scan | Scan rápido das portas mais comuns (opcional, flag `-p`) |
| 👁️ Watch Mode | Monitorização contínua com alerta de novos dispositivos (`-w`) |
| 📄 Export | Exporta resultados para JSON ou TXT (`-e`) |

---

## 📦 Instalação

```bash
# Clonar
git clone https://github.com/mrjoker-web/ShadowEye
cd ShadowEye

# Dependências
pip install scapy rich

# Termux
pkg install python root-repo
pip install scapy rich
```

---

## 🚀 Uso

```bash
# Scan básico (auto-deteta rede)
sudo python3 shadoweye.py

# Rede específica
sudo python3 shadoweye.py -n 192.168.1.0/24

# Com scan de portas
sudo python3 shadoweye.py -p

# Watch mode — alerta quando entra dispositivo novo
sudo python3 shadoweye.py -w

# Watch mode com intervalo personalizado (15 segundos)
sudo python3 shadoweye.py -w -i 15

# Exportar para JSON
sudo python3 shadoweye.py -e report.json

# Exportar para TXT
sudo python3 shadoweye.py -e report.txt

# Combinado
sudo python3 shadoweye.py -n 192.168.0.0/24 -p -e report.json
```

---

## 📊 Output exemplo

```
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  #   IP Address       MAC Address         Vendor        Hostname     OS Guess
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  1   192.168.1.1      00:1A:11:AA:BB:CC   TP-Link       router       Network Device
  2   192.168.1.10     B8:27:EB:11:22:33   Raspberry Pi  raspberrypi  Linux/Android
  3   192.168.1.15     3C:22:FB:44:55:66   Apple         iPhone       Linux/Android
  4   192.168.1.20     A0:21:B7:77:88:99   Netgear       —            Windows
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
```

---

## 🔗 Shadow Suite Pipeline

```
ShadowSub   →  encontra subdomínios
     ↓
ShadowProbe →  verifica quais estão ativos
     ↓
ShadowScan  →  analisa portas e serviços
     ↓
ShadowEye   →  monitoriza dispositivos na rede local  ← aqui
```

---

## ⚠️ Disclaimer

> Ferramenta desenvolvida para **fins educacionais e testes em redes autorizadas**.
> O autor não se responsabiliza pelo uso indevido.
> Usa **apenas em redes que tens autorização** para testar.

---

## 📫 Contacto

[![Telegram](https://img.shields.io/badge/-Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/mr_joker78)
[![GitHub](https://img.shields.io/badge/-GitHub-000?style=for-the-badge&logo=github)](https://github.com/mrjoker-web)
