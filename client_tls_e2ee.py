# client_tls_e2ee.py
import socket, ssl, threading, json, base64, os, sys
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------- Utilidades E2EE ----------
def b64e(b): return base64.b64encode(b).decode("ascii")
def b64d(s): return base64.b64decode(s.encode("ascii"))

def derive_key(my_sk: X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = my_sk.exchange(peer_pub)  # 32 bytes
    # HKDF-SHA256 para derivar clave simétrica de 32 bytes (AES256/ChaCha20)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"chat-e2ee")
    return hkdf.derive(shared)

def encrypt_msg(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)             # 96-bit nonce único por mensaje
    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, cipher

def decrypt_msg(key: bytes, nonce: bytes, cipher: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cipher, None)

def fingerprint(pub_bytes: bytes) -> str:
    # Código corto para verificar identidad por canal alterno (anti-MITM)
    h = sha256(pub_bytes).hexdigest()
    return f"{h[:8]}-{h[8:16]}"

# --------- Cliente Chat ----------
class Client:
    def __init__(self, user, host, port):
        self.user = user
        self.host = host
        self.port = port
        # Par X25519 (estático para la sesión; puedes rotarlo por sesión si quieres)
        self.sk = X25519PrivateKey.generate()
        self.pk = self.sk.public_key().public_bytes_raw()
        self.users = {}   # user -> peer_pub_bytes
        self.sock = None
        self.tls = None
        self.lock = threading.Lock()

    def send_json(self, obj):
        data = (json.dumps(obj) + "\n").encode("utf-8")
        with self.lock:
            self.tls.sendall(data)

    def reader(self):
        buf = b""
        try:
            while True:
                chunk = self.tls.recv(4096)
                if not chunk:
                    print("[CLI] conexión cerrada por el servidor")
                    os._exit(0)
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self.handle_msg(json.loads(line.decode("utf-8","ignore")))
        except Exception as e:
            print("[CLI] Error en lectura:", e)
            os._exit(1)

    def handle_msg(self, msg):
        t = msg.get("type")
        if t == "welcome" or t == "users":
            self.users = {u: b64d(p) for u,p in msg.get("users",{}).items()}
            print("[SYS] usuarios disponibles:", ", ".join(sorted(self.users)))
            # Muestra huellas para verificación fuera de banda
            for u, pb in self.users.items():
                print(f"   - {u} fp={fingerprint(pb)}")
        elif t == "server":
            print(f"[SERVER] {msg.get('text','')}")
        elif t == "error":
            print(f"[ERROR] {msg.get('text','')}")
        elif t == "relay":
            frm = msg.get("from")
            nonce = b64d(msg["nonce"])
            cipher = b64d(msg["cipher"])
            if frm not in self.users:
                print(f"[WARN] mensaje de {frm} pero no tengo su pubkey.")
                return
            key = derive_key(self.sk, self.users[frm])
            try:
                pt = decrypt_msg(key, nonce, cipher).decode("utf-8","ignore")
                print(f"[{frm}] {pt}")
            except Exception:
                print(f"[WARN] no se pudo descifrar mensaje de {frm} (nonce/clave incorrecta?)")
        else:
            print("[SYS] msg:", msg)

    def connect(self):
        # TLS cliente con pinning del server.crt
        ctx = ssl.create_default_context()
        ctx.load_verify_locations("server.crt")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        raw = socket.create_connection((self.host, self.port), timeout=8)
        self.tls = ctx.wrap_socket(raw, server_hostname="servidor-local")
        
        self.tls.settimeout(None)   # vuelve a modo bloqueante (sin límite)

        # HELLO con usuario y clave pública
        self.send_json({"type":"hello","user":self.user,"pub": b64e(self.pk)})
        threading.Thread(target=self.reader, daemon=True).start()

    # Comandos de usuario:
    def cmd_list(self):
        self.send_json({"type":"list"})

    def cmd_server(self, text):
        self.send_json({"type":"chat","text": text})

    def cmd_to(self, dest, text):
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
    if len(sys.argv) < 4:
        print("Uso: python client_tls_e2ee.py <usuario> <host> <port>")
        print("Ej:  python client_tls_e2ee.py alice 127.0.0.1 5000")
        return
    user, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    c = Client(user, host, port)
    c.connect()
    print("[SYS] comandos:")
    print("  /list                -> pedir usuarios")
    print("  /server <texto>      -> chatear con el servidor")
    print("  /to <user> <texto>   -> enviar E2EE al usuario")
    print("  /fp <user>           -> ver huella de la clave pública del user")
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
            try:
                _, usr, txt = line.split(" ", 2)
                c.cmd_to(usr, txt)
            except ValueError:
                print("Uso: /to <user> <texto>")
        elif line.startswith("/fp "):
            _, usr = line.split(" ", 1)
            if usr in c.users:
                print(f"[SYS] {usr} fp={fingerprint(c.users[usr])}")
            else:
                print("[SYS] usuario no conocido (usa /list)")
        else:
            print("[SYS] comando no reconocido")
        
if __name__ == "__main__":
    main()
