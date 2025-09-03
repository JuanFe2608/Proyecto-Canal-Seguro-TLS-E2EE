# 🔐 Chat Seguro con TLS + E2EE sobre ngrok
## 🎯 Resumen 

Transporte cifrado (TLS): todo lo que va entre cliente ↔ servidor viaja dentro de un túnel TLS; ngrok y la red solo ven bytes opacos.

Capa de aplicación cifrada (E2EE): los mensajes cliente ↔ cliente van además cifrados con X25519 + HKDF + AES-GCM; el servidor no puede leerlos (solo los reenvía).

## Comandos:
/list usuarios, /fp <user> huella, /to <user> <texto> E2EE, /server <texto> hablar con el servidor.

🏗️ Arquitectura (capas y roles)
[ Cliente A ]  <--TLS-->  [ Servidor ]  <--TLS-->  [ Cliente B ]
      \_______________________ ngrok TCP ______________________/

- TLS: Capa de transporte segura (cliente-servidor). ngrok NO descifra.
- E2EE (aplicación): Mensajes A↔B cifrados extremo a extremo. Servidor reenvía sin leer.
- Mensajes al servidor (/server ...): el servidor sí los ve (tras descifrar TLS).

##Objetivos de seguridad

Confidencialidad en tránsito frente a ISP, campus WiFi, ngrok, etc. (gracias a TLS).

Confidencialidad extremo a extremo entre clientes (gracias a E2EE).

Integridad (detección de manipulación) y autenticidad del servidor (pinning de server.crt).


## 🔑 Criptografía usada (y por qué)
1) TLS (transporte)

Qué es: protocolo híbrido estándar. Durante el handshake se negocia una clave simétrica efímera y, desde ahí, todo va cifrado y autenticado.

En este proyecto:

El servidor carga server.key (privada) + server.crt (pública).

El cliente fija confianza (pinning) en server.crt (verify_mode=CERT_REQUIRED).

Usamos check_hostname=False porque el CN no coincide con *.ngrok.io; la seguridad depende del pinning.

Mínimo TLS 1.2 (ideal 1.3 por defecto en Python moderno).

Resultado: ngrok no puede leer el contenido; solo reenvía TCP.

2) E2EE (aplicación) cliente ↔ cliente

Intercambio de claves: X25519 (ECDH) → ambas partes calculan el mismo secreto compartido.

Derivación: HKDF-SHA256 estira el secreto a una clave simétrica de 32 bytes.

Cifrado autenticado: AES-GCM con nonce de 12 bytes aleatorio por mensaje.

Formato: el cliente envía {nonce, cipher} en Base64 al servidor para que lo reenvíe. El servidor nunca ve el texto.

Propiedad clave: solo el verdadero destinatario (con su privada X25519) puede derivar la misma clave y descifrar.

💡 Recomendación: comparar huellas (fingerprints) de las claves públicas por un canal alterno (voz/WhatsApp) para detectar suplantación.

📨 Protocolo de mensajes (JSON por líneas)

Los mensajes son objetos JSON terminados en \n (framing por líneas). Campos binarios (claves públicas, nonce, cipher) van en Base64.

hello (primer mensaje del cliente)
Cliente → Servidor:

{"type":"hello","user":"alice","pub":"<b64(pub_x25519))>"}


Servidor → Cliente:

{"type":"welcome","users":{"alice":"<b64(pub)>","bob":"<b64(pub)>", "..."}}


list (listar usuarios)
Cliente → Servidor: {"type":"list"}
Servidor → Cliente: {"type":"users","users":{...}}

chat (hablar con el servidor)
Cliente → Servidor: {"type":"chat","text":"hola server"}
Servidor → Cliente: {"type":"server","text":"echo: hola server"}

relay (E2EE A → B, el servidor NO lee)
Cliente A → Servidor:

{"type":"relay","to":"Juan","from":"Felipe","alg":"X25519+AESGCM",
 "nonce":"<b64>", "cipher":"<b64>"}


Servidor → Cliente B: reenvía tal cual.

## 🧠 Flujo detallado
a) Arranque del servidor

Crea contexto TLS (SSLContext(PROTOCOL_TLS_SERVER)).

Carga server.crt + server.key.

bind(0.0.0.0:5000), listen() y acepta conexiones.

Por cada conexión: wrap_socket(..., server_side=True) → TLS activo.

b) Conexión del cliente

Crea contexto TLS de cliente y pinning con server.crt.

create_connection + wrap_socket: TLS activo.

Envía hello con su clave pública X25519.

Recibe welcome/users con el directorio de claves.

c) Mensaje E2EE (cliente ↔ cliente)

A elige a B y toma su pub_B del directorio.

Calcula key = HKDF( X25519(sk_A, pub_B) ).

Cifra plaintext con AESGCM(key) → obtiene nonce + cipher.

Manda relay al servidor; el servidor solo reenvía.

B, al recibir, calcula key = HKDF( X25519(sk_B, pub_A) ) y descifra.

## 🧪 Cómo ejecutar (local y remoto)
### 1) Requisitos
python --version   # >= 3.9
pip install cryptography

### 2) Generar certificado del servidor (demo)
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=servidor-local"


Comparte server.crt con todos los clientes.

Nunca compartas server.key.

### 3) Prueba local (sin ngrok)

Terminal A (servidor):

python server_tls_chat.py


Terminal B y C (clientes):

python client_tls_e2ee.py Juan 127.0.0.1 5000
python client_tls_e2ee.py Felipe  127.0.0.1 5000

### 4) Prueba remota (con ngrok TCP)

En el servidor:

python server_tls_chat.py
ngrok tcp 5000
# ejemplo: Forwarding  tcp://0.tcp.ngrok.io:14309 -> localhost:5000


### Compartir con otros amigos(Otros Clientes): host 0.tcp.ngrok.io, puerto 14309 y el server.crt.

En los clientes remotos:

python client_tls_e2ee.py Amigo 0.tcp.ngrok.io 14309

## 🕹️ Uso desde el cliente
/list                      # ver usuarios y claves públicas
/fp <user>                 # ver huella de la clave pública de <user>
/to <user> <texto>         # enviar mensaje E2EE a <user>
/server <texto>            # hablar con el servidor (el server sí lo ve)

### 🔍 ¿Cómo sé que de verdad va cifrado?

#### Con Wireshark (nivel red)

Filtro: tcp.port == <puerto_ngrok>

Se vera TLSv1.3 Application Data (o TLS 1.2), nunca texto en claro.

“Follow TCP stream” mostrará bytes aleatorios/hex.

En el servidor (nivel aplicación)

Mensajes /server ... → aparecerán legibles en la consola del servidor.

Mensajes /to ... → el servidor solo verá JSON con nonce y cipher en Base64 (no el texto).

En los clientes

Solo el destinatario podrá descifrar y leer el texto del otro.

Si la clave/nonce no coinciden, falla con aviso (integridad de GCM).

## 🧯 Troubleshooting rápido

CERTIFICATE_VERIFY_FAILED → el cliente no tiene el server.crt correcto o en esa ruta.

Timeouts / desconexiones → después del handshake, el cliente hace self.tls.settimeout(None); opcional: añade heartbeats ping/pong.

“mensaje de X pero no tengo su pubkey” → ejecuta /list (o implementa broadcast de usuarios al conectar/desconectar).

No conecta por ngrok → deja ngrok abierto, usa host/puerto exactos, prueba otra red (a veces campus/empresa bloquea puertos arbitrarios).

🛡️ Propiedades de seguridad (qué sí / qué no)
Garantizado por diseño

Confidencialidad en tránsito (TLS): ngrok/ISP/red no leen.

Integridad y autenticidad del servidor: pinning a server.crt.

Confidencialidad cliente↔cliente (E2EE): el servidor no puede leer contenido.

No garantizado (pero puedes extender)

Autenticidad del cliente (quién es “Alice” de verdad): añade mTLS o un sistema de login/firma de mensajes.

Verificación contra MITM del servidor en intercambio de claves E2EE: compara huellas por canal alterno (SAS) o usa verificación persistente (estilo “safety numbers”).

Persistencia de claves y re-keying periódico: opcional pero recomendable para PFS a nivel aplicación.