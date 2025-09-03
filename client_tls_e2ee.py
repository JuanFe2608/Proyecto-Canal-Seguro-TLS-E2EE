# client_tls_e2ee.py
# -------------------------------------------------------------
# Cliente de chat seguro:
#  - Capa de transporte protegida con TLS (pinning de server.crt)
#  - Capa de aplicación con E2EE (cliente <-> cliente) usando:
#       X25519 (intercambio de claves) + HKDF (derivación) + AES-GCM (cifrado autenticado)
#  - Protocolo de mensajes JSON delimitados por '\n'
#  - Comandos: /list, /fp, /to <user> <texto>, /server <texto>
# -------------------------------------------------------------

import socket, ssl, threading, json, base64, os, sys
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------- Utilidades E2EE ----------
# Pequeñas funciones auxiliares para codificar/decodificar y operar la cripto de aplicación.

def b64e(b): 
    # Codifica bytes a Base64 (string ASCII) para meter binarios en JSON
    return base64.b64encode(b).decode("ascii")

def b64d(s): 
    # Decodifica de Base64 (string) a bytes
    return base64.b64decode(s.encode("ascii"))

def derive_key(my_sk: X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    """
    Deriva una clave simétrica de 32 bytes (para AES-256/ChaCha20) 
    a partir de ECDH con X25519 + HKDF-SHA256.
    - my_sk: clave privada local X25519
    - peer_pub_bytes: clave pública del par en bytes (cruda)
    """
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = my_sk.exchange(peer_pub)  # secreto compartido de 32 bytes (ECDH)
    # HKDF: estira/deriva el secreto compartido a una clave fuerte de 32 bytes
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"chat-e2ee")
    return hkdf.derive(shared)

def encrypt_msg(key: bytes, plaintext: bytes):
    """
    Cifra 'plaintext' con AES-GCM (cifrado autenticado).
    - Genera 'nonce' aleatorio de 96 bits (12 bytes) UNA VEZ por mensaje.
    - Devuelve (nonce, cipher). 'cipher' ya incluye el tag de autenticación.
    """
    nonce = os.urandom(12)             # ¡no repetir nonces con la misma clave!
    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, cipher

def decrypt_msg(key: bytes, nonce: bytes, cipher: bytes):
    """
    Descifra con AES-GCM y verifica integridad. 
    Lanza excepción si el tag no cuadra (mensaje alterado o clave/nonce incorrectos).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cipher, None)

def fingerprint(pub_bytes: bytes) -> str:
    """
    Genera una 'huella' corta de la clave pública (hash SHA-256 abreviado).
    Útil para que usuarios verifiquen por un canal alterno (anti-MITM).
    """
    h = sha256(pub_bytes).hexdigest()
    return f"{h[:8]}-{h[8:16]}"

# --------- Cliente Chat ----------
class Client:
    """
    Representa un cliente de chat:
      - Mantiene su par X25519 (sk/pk) para E2EE.
      - Abre un canal TLS al servidor (pinning de server.crt).
      - Envía/recibe mensajes JSON por líneas.
      - Mantiene un mapa de usuarios -> claves públicas (para cifrar a destinatarios).
    """
    def __init__(self, user, host, port):
        self.user = user
        self.host = host
        self.port = port

        # Par X25519 generado al iniciar el cliente (puedes rotarlo por sesión si quieres PFS a nivel app)
        self.sk = X25519PrivateKey.generate()
        self.pk = self.sk.public_key().public_bytes_raw()

        # Tabla de usuarios conectados: nombre -> clave pública (bytes)
        self.users = {}

        # Sockets (raw y TLS). 'sock' no se usa directamente en esta versión, nos quedamos con self.tls
        self.sock = None
        self.tls = None

        # Lock para evitar cruces si varios hilos envían al mismo tiempo
        self.lock = threading.Lock()

    def send_json(self, obj):
        """
        Serializa un dict a JSON + '\n' y lo envía por el socket TLS.
        El '\n' delimita mensajes para que el receptor pueda hacer framing por líneas.
        """
        data = (json.dumps(obj) + "\n").encode("utf-8")
        with self.lock:
            self.tls.sendall(data)

    def reader(self):
        """
        Hilo lector: 
         - Recibe datos del TLS, acumula en buffer y procesa línea por línea (separador '\n').
         - Por cada línea JSON, llama a handle_msg().
         - Si el servidor cierra, sale del proceso (os._exit para simplificar demo).
        """
        buf = b""
        try:
            while True:
                chunk = self.tls.recv(4096)
                if not chunk:
                    print("[CLI] conexión cerrada por el servidor")
                    os._exit(0)
                buf += chunk
                # Procesa todas las líneas completas disponibles en el buffer
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self.handle_msg(json.loads(line.decode("utf-8","ignore")))
        except Exception as e:
            # Si hay un error (p. ej., timeout si hubieras puesto settimeout), se termina la app
            print("[CLI] Error en lectura:", e)
            os._exit(1)

    def handle_msg(self, msg):
        """
        Router de mensajes entrantes (desde el servidor):
          - 'welcome'/'users': actualiza lista de usuarios y muestra huellas.
          - 'server': mensaje de texto proveniente del servidor (legible por él).
          - 'error': mensaje de error del servidor.
          - 'relay': mensaje E2EE de otro cliente (descifrar con X25519+HKDF+AES-GCM).
        """
        t = msg.get("type")

        if t == "welcome" or t == "users":
            # Actualiza mapa de usuarios con las claves públicas (vienen en Base64)
            self.users = {u: b64d(p) for u,p in msg.get("users",{}).items()}
            print("[SYS] usuarios disponibles:", ", ".join(sorted(self.users)))
            # Imprime huellas para que los usuarios comparen fuera de banda (anti MITM de servidor)
            for u, pb in self.users.items():
                print(f"   - {u} fp={fingerprint(pb)}")

        elif t == "server":
            # Texto enviado por el servidor (el servidor tiene acceso a este contenido)
            print(f"[SERVER] {msg.get('text','')}")

        elif t == "error":
            # Mensaje de error genérico
            print(f"[ERROR] {msg.get('text','')}")

        elif t == "relay":
            # Mensaje E2EE reenviado por el servidor (NO lo entiende)
            frm = msg.get("from")
            nonce = b64d(msg["nonce"])
            cipher = b64d(msg["cipher"])

            # Si aún no tenemos la clave pública del remitente, no podemos descifrar
            if frm not in self.users:
                print(f"[WARN] mensaje de {frm} pero no tengo su pubkey.")
                return

            # Deriva la clave simétrica con ECDH (X25519) + HKDF
            key = derive_key(self.sk, self.users[frm])

            try:
                # Descifra y valida integridad con AES-GCM
                pt = decrypt_msg(key, nonce, cipher).decode("utf-8","ignore")
                print(f"[{frm}] {pt}")
            except Exception:
                # Si falla, puede ser nonce repetido/alterado, clave incorrecta, o mensaje corrupto
                print(f"[WARN] no se pudo descifrar mensaje de {frm} (nonce/clave incorrecta?)")
        else:
            # Cualquier tipo desconocido, lo mostramos tal cual
            print("[SYS] msg:", msg)

    def connect(self):
        """
        Establece el canal TLS con pinning del 'server.crt' y lanza el hilo lector.
        Luego envía el 'hello' inicial con (user, pubkey) para que el servidor registre.
        """
        # 1) Contexto TLS del cliente con pinning:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations("server.crt")  # confía en ESTE cert (pinning)
        ctx.check_hostname = False               # no validamos nombre contra CN/SAN (usamos pinning)
        ctx.verify_mode = ssl.CERT_REQUIRED      # exige verificación del cert del servidor

        # 2) Conexión TCP y envoltura TLS
        raw = socket.create_connection((self.host, self.port), timeout=8)
        self.tls = ctx.wrap_socket(raw, server_hostname="servidor-local")

        # 3) Evita timeouts de lectura por inactividad (modo bloqueante)
        self.tls.settimeout(None)

        # 4) Handshake de aplicación: anuncia usuario y su clave pública
        self.send_json({"type":"hello","user":self.user,"pub": b64e(self.pk)})

        # 5) Lanza el hilo que atiende mensajes entrantes
        threading.Thread(target=self.reader, daemon=True).start()

    # Comandos de usuario (enviados al servidor en JSON):

    def cmd_list(self):
        # Pide al servidor el listado de usuarios y sus claves públicas
        self.send_json({"type":"list"})

    def cmd_server(self, text):
        # Envía mensaje al servidor (el servidor lo puede leer y responder)
        self.send_json({"type":"chat","text": text})

    def cmd_to(self, dest, text):
        """
        Envía mensaje E2EE a otro usuario:
          1) Verifica que tengamos su public key.
          2) Deriva clave simétrica compartida con X25519+HKDF.
          3) Cifra con AES-GCM usando nonce aleatorio.
          4) Envía JSON 'relay' con (nonce, cipher) en Base64.
        """
        if dest not in self.users:
            print("[SYS] destino no disponible (usa /list)")
            return
        key = derive_key(self.sk, self.users[dest])
        nonce, cipher = encrypt_msg(key, text.encode("utf-8"))
        self.send_json({
            "type":"relay","to":dest,"from":self.user,
            "alg":"X25519+AESGCM","nonce": b64e(nonce),"cipher": b64e(cipher)
        })

def main():
    """
    CLI del cliente:
      Uso: python client_tls_e2ee.py <usuario> <host> <port>
      Ej.: python client_tls_e2ee.py alice 127.0.0.1 5000
      Luego puedes escribir comandos:
        /list
        /server <texto>
        /to <user> <texto>
        /fp <user>
    """
    if len(sys.argv) < 4:
        print("Uso: python client_tls_e2ee.py <usuario> <host> <port>")
        print("Ej:  python client_tls_e2ee.py alice 127.0.0.1 5000")
        return

    user, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

    # Construye cliente y establece conexión TLS + hello
    c = Client(user, host, port)
    c.connect()

    # Muestra ayuda de comandos
    print("[SYS] comandos:")
    print("  /list                -> pedir usuarios")
    print("  /server <texto>      -> chatear con el servidor")
    print("  /to <user> <texto>   -> enviar E2EE al usuario")
    print("  /fp <user>           -> ver huella de la clave pública del user")

    # Bucle de lectura de comandos del usuario (stdin)
    while True:
        try:
            line = input().strip()
        except EOFError:
            break

        if not line: 
            continue

        if line == "/list":
            c.cmd_list()

        elif line.startswith("/server "):
            c.cmd_server(line[len("/server "):])

        elif line.startswith("/to "):
            # Formato: /to <usuario> <texto con espacios>
            try:
                _, usr, txt = line.split(" ", 2)
                c.cmd_to(usr, txt)
            except ValueError:
                print("Uso: /to <user> <texto>")

        elif line.startswith("/fp "):
            # Muestra huella de la pubkey del usuario, si está en el mapa
            _, usr = line.split(" ", 1)
            if usr in c.users:
                print(f"[SYS] {usr} fp={fingerprint(c.users[usr])}")
            else:
                print("[SYS] usuario no conocido (usa /list)")

        else:
            print("[SYS] comando no reconocido")
        
if __name__ == "__main__":
    main()
