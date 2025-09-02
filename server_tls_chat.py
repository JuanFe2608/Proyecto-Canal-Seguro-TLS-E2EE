# server_tls_chat.py
import socket, ssl, threading, json, base64, traceback

HOST, PORT = "0.0.0.0", 5000

# Estado en memoria
clients = {}   # user -> tls_socket
pubkeys = {}   # user -> bytes (X25519 public key)

def send_json(tls_sock, obj):
    data = (json.dumps(obj) + "\n").encode("utf-8")
    tls_sock.sendall(data)

def recv_line(tls_sock, buf):
    # lee hasta '\n'
    while b"\n" not in buf:
        chunk = tls_sock.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
    line, buf = buf.split(b"\n", 1)
    return line.decode("utf-8", "ignore"), buf

def handle_client(tls_sock):
    buf = b""
    user = None
    try:
        # 1) Espera HELLO
        line, buf = recv_line(tls_sock, buf)
        if not line:
            return
        msg = json.loads(line)
        if msg.get("type") != "hello" or "user" not in msg or "pub" not in msg:
            send_json(tls_sock, {"type":"error","text":"first message must be hello"})
            return
        user = msg["user"]
        pub_b = base64.b64decode(msg["pub"])
        # registra
        clients[user] = tls_sock
        pubkeys[user] = pub_b
        # envía bienvenida y la tabla de usuarios/pubs
        users_map = {u: base64.b64encode(k).decode("ascii") for u,k in pubkeys.items()}
        send_json(tls_sock, {"type":"welcome","users": users_map})
        print(f"[SRV] {user} conectado")

        # 2) Loop de mensajes
        while True:
            line, buf = recv_line(tls_sock, buf)
            if line is None:
                break
            if not line.strip():
                continue
            msg = json.loads(line)
            t = msg.get("type")

            if t == "list":
                users_map = {u: base64.b64encode(k).decode("ascii") for u,k in pubkeys.items()}
                send_json(tls_sock, {"type":"users","users": users_map})

            elif t == "chat":
                # chat con el servidor (server sí ve el texto)
                text = msg.get("text","")
                print(f"[SRV] {user} dice al server: {text}")
                send_json(tls_sock, {"type":"server","text": f"echo: {text}"})

            elif t == "relay":
                # Mensaje E2EE cliente->cliente (server no descifra)
                to = msg.get("to")
                if not to or to not in clients:
                    send_json(tls_sock, {"type":"error","text":"destino no conectado"})
                    continue
                # Reenvía tal cual (sin abrir cipher)
                send_json(clients[to], msg)

            else:
                send_json(tls_sock, {"type":"error","text":"tipo no soportado"})

    except Exception as e:
        print("[SRV] Error:", e)
        traceback.print_exc()
    finally:
        try:
            tls_sock.close()
        except:
            pass
        if user:
            clients.pop(user, None)
            pubkeys.pop(user, None)
            print(f"[SRV] {user} desconectado")

def main():
    # TLS server context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(10)
        print(f"[SRV] TLS escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = srv.accept()
            tls = ctx.wrap_socket(conn, server_side=True)
            threading.Thread(target=handle_client, args=(tls,), daemon=True).start()

if __name__ == "__main__":
    main()
