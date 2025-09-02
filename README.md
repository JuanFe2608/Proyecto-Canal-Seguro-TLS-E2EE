#  Chat Seguro con TLS y E2EE sobre ngrok

## Descripción
Este proyecto implementa un **chat multi-cliente** en Python con las siguientes características:

- **Canal seguro TLS**: todo el tráfico viaja cifrado extremo a extremo entre cliente y servidor.  
- **Soporte de túneles con ngrok (TCP)**: permite exponer el servidor local a internet.  
- **E2EE (End-to-End Encryption) entre clientes**:  
  - Mensajes cliente→cliente se cifran con **X25519 + HKDF + AES-GCM**.  
  - El servidor solo reenvía `nonce + cipher` y **no puede leer el contenido**.  
- **Chat con servidor**: los clientes también pueden enviar mensajes directos al servidor (el servidor sí los puede leer).  

---

## ⚙️ Requisitos
- Python 3.9+  
- Librerías:
  ```bash
  pip install cryptography
