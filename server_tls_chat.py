# server_tls_chat.py
# -------------------------------------------------------------
# Servidor de chat seguro:
#  - Capa de transporte protegida con TLS (el servidor presenta server.crt/server.key)
#  - Mantiene usuarios conectados y sus claves públicas X25519 (para E2EE cliente<->cliente)
#  - Reenvía mensajes "relay" sin descifrarlos (el servidor NO ve el contenido E2EE)
#  - Acepta mensajes de chat dirigidos al servidor (que sí puede leer)
#  - Protocolo: mensajes JSON terminados en '\n' (delimitación por líneas)
# -------------------------------------------------------------

import socket, ssl, threading, json, base64, traceback

HOST, PORT = "0.0.0.0", 5000  # Escucha en todas las interfaces (loopback, WiFi, Ethernet) en el puerto 5000

# Estado en memoria del servidor
clients = {}   # Mapa: user -> tls_socket (socket TLS del cliente conectado con ese nombre de usuario)
pubkeys = {}   # Mapa: user -> bytes (clave pública X25519 del cliente en binario crudo)

def send_json(tls_sock, obj):
    """
    Envía un objeto Python como JSON y lo delimita con '\n'.
    Esto permite que el receptor haga 'framing' por líneas (leer mensaje a mensaje).
    """
    data = (json.dumps(obj) + "\n").encode("utf-8")
    tls_sock.sendall(data)

def recv_line(tls_sock, buf):
    """
    Lee del socket TLS hasta encontrar un '\n'.
    - 'buf' acumula bytes que pudieron quedar de lecturas anteriores.
    - Devuelve (linea_str, buf_restante). Si el peer cierra, retorna (None, buf).
    """
    while b"\n" not in buf:
        chunk = tls_sock.recv(4096)  # bloquea hasta recibir algo o que se cierre
        if not chunk:
            return None, buf         # conexión cerrada por el cliente
        buf += chunk
    line, buf = buf.split(b"\n", 1)  # separa la primera línea completa del resto
    return line.decode("utf-8", "ignore"), buf

def handle_client(tls_sock):
    """
    Atiende a UN cliente:
      1) Espera el mensaje 'hello' inicial con (user, pub)
      2) Registra su socket y su clave pública
      3) Entra en un bucle leyendo mensajes y respondiendo según 'type'
      4) Al salir, limpia estado y cierra
    """
    buf = b""
    user = None  # guardará el nombre de usuario una vez que llegue el 'hello'
    try:
        # 1) Handshake de aplicación: el primer mensaje debe ser 'hello'
        line, buf = recv_line(tls_sock, buf)
        if not line:
            return  # conexión cerrada sin enviar nada
        msg = json.loads(line)
        if msg.get("type") != "hello" or "user" not in msg or "pub" not in msg:
            # Primer mensaje inválido: devolvemos error y cortamos
            send_json(tls_sock, {"type":"error","text":"first message must be hello"})
            return

        # Extrae nombre y clave pública del cliente
        user = msg["user"]
        pub_b = base64.b64decode(msg["pub"])  # pub venía en Base64 en el 'hello'

        # 2) Registrar al cliente y su clave pública en los mapas globales
        clients[user] = tls_sock
        pubkeys[user] = pub_b

        # 3) Enviar bienvenida con la tabla de usuarios actuales (nombre -> pubkey en Base64)
        users_map = {u: base64.b64encode(k).decode("ascii") for u,k in pubkeys.items()}
        send_json(tls_sock, {"type":"welcome","users": users_map})
        print(f"[SRV] {user} conectado")

        # 4) Bucle principal de mensajes desde este cliente
        while True:
            line, buf = recv_line(tls_sock, buf)
            if line is None:          # el cliente cerró la conexión
                break
            if not line.strip():      # línea vacía (p. ej., "\n"), la ignoramos
                continue

            msg = json.loads(line)    # parsea JSON
            t = msg.get("type")       # tipo de mensaje

            if t == "list":
                # El cliente solicita el listado actualizado de usuarios y pubkeys
                users_map = {u: base64.b64encode(k).decode("ascii") for u,k in pubkeys.items()}
                send_json(tls_sock, {"type":"users","users": users_map})

            elif t == "chat":
                # Chat dirigido al servidor (el servidor SÍ ve el texto en claro)
                text = msg.get("text","")
                print(f"[SRV] {user} dice al server: {text}")
                # En esta demo respondemos un eco simple
                send_json(tls_sock, {"type":"server","text": f"echo: {text}"})

            elif t == "relay":
                """
                Relay E2EE cliente->cliente:
                  - El servidor NO descifra el contenido (cipher).
                  - Valida que el destino 'to' exista y esté conectado.
                  - Reenvía el mensaje tal cual al destinatario.
                """
                to = msg.get("to")
                if not to or to not in clients:
                    send_json(tls_sock, {"type":"error","text":"destino no conectado"})
                    continue
                # Reenvío directo (sin tocar 'cipher' ni 'nonce')
                send_json(clients[to], msg)

            else:
                # Tipos no soportados -> error genérico
                send_json(tls_sock, {"type":"error","text":"tipo no soportado"})

    except Exception as e:
        # Cualquier error en la atención del cliente se loguea (stacktrace incluido)
        print("[SRV] Error:", e)
        traceback.print_exc()
    finally:
        # Limpieza: cerrar socket TLS y eliminar al usuario de los mapas si estaba registrado
        try:
            tls_sock.close()
        except:
            pass
        if user:
            clients.pop(user, None)
            pubkeys.pop(user, None)
            print(f"[SRV] {user} desconectado")

def main():
    """
    Punto de entrada del servidor:
      - Crea contexto TLS de servidor y carga cert/clave
      - Abre socket TCP en 0.0.0.0:5000
      - Acepta conexiones, las envuelve en TLS y delega a 'handle_client' en un hilo por cliente
    """
    # 1) Contexto TLS del lado servidor (presenta el certificado a los clientes)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")  # identidad del servidor
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2                     # fuerza como mínimo TLS 1.2

    # 2) Socket TCP de escucha
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # reusar puerto sin esperar TIME_WAIT
        srv.bind((HOST, PORT))
        srv.listen(10)                                               # backlog de 10 conexiones pendientes
        print(f"[SRV] TLS escuchando en {HOST}:{PORT}")

        # 3) Bucle de accept: por cada cliente que llega, envolver en TLS y despachar a un hilo
        while True:
            conn, addr = srv.accept()                                # conexión TCP entrante
            tls = ctx.wrap_socket(conn, server_side=True)            # handshake TLS (server-side)
            threading.Thread(target=handle_client, args=(tls,), daemon=True).start()

if __name__ == "__main__":
    main()
