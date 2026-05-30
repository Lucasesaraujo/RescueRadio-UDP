import getpass
import socket
import sys
import threading
import time
from datetime import datetime

from protocol import MAX_DATAGRAM_BYTES, build_packet, decode_packet, encode_packet, sanitize_text


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345

DEFAULT_HEARTBEAT_SECONDS = 5
AUTH_RESPONSE_TIMEOUT_SECONDS = 8
RECV_TIMEOUT_SECONDS = 1
SERVER_SILENCE_WARNING_SECONDS = 15


def clear_line() -> None:
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()


def print_line(text: str) -> None:
    clear_line()
    print(text, flush=True)


def local_log(level: str, message: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print_line(f"[{now}] [{level}] {message}")


class RescueRadioUDPClient:
    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.send_lock = threading.Lock()

        self.connected = False
        self.stop_event = threading.Event()

        self.session_id = ""
        self.callsign = ""
        self.channel = ""
        self.heartbeat_interval = DEFAULT_HEARTBEAT_SECONDS
        self.last_server_packet = 0.0
        self.last_silence_warning = 0.0

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(AUTH_RESPONSE_TIMEOUT_SECONDS)
            self.connected = True
            self.last_server_packet = time.time()
            return True
        except OSError as exc:
            local_log("ERRO", f"Falha ao abrir socket UDP: {exc}")
            return False

    def disconnect(self) -> None:
        self.stop_event.set()
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_packet(self, payload: dict) -> bool:
        if not self.sock or not self.connected:
            return False
        try:
            raw = encode_packet(payload)
            if len(raw) > MAX_DATAGRAM_BYTES:
                local_log("ERRO", "Pacote excede limite de datagrama UDP.")
                return False
            with self.send_lock:
                self.sock.send(raw)
            return True
        except OSError as exc:
            local_log("ERRO", f"Erro de envio UDP: {exc}")
            self.stop_event.set()
            return False

    def recv_packet(self) -> tuple[dict | None, str | None]:
        if not self.sock:
            return None, "SOCKET_CLOSED"

        try:
            raw = self.sock.recv(MAX_DATAGRAM_BYTES)
        except socket.timeout:
            return None, "TIMEOUT"
        except OSError:
            return None, "SOCKET_ERROR"

        self.last_server_packet = time.time()
        return decode_packet(raw)

    def auth_flow(self) -> bool:
        print("\n=== AUTENTICACAO OPERACIONAL ===")
        print("Credenciais do operador cadastrado no admin.py\n")

        while True:
            try:
                username = input("  Usuario: ").strip()
                password = getpass.getpass("  Senha: ")
                callsign = input("  Callsign (apelido de radio): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return False

            callsign = callsign or username
            payload = build_packet(
                "auth",
                username=username,
                password=password,
                callsign=callsign,
            )
            if not self.send_packet(payload):
                return False

            packet, err = self.recv_packet()
            if err == "TIMEOUT":
                local_log("AVISO", "Sem resposta do servidor no login. Tentando novamente...")
                continue
            if err:
                local_log("ERRO", f"Falha ao receber resposta de auth: {err}")
                return False
            if packet is None:
                continue

            packet_type = packet.get("type")
            if packet_type == "auth_ok":
                self.session_id = sanitize_text(packet.get("session_id"), 64)
                self.callsign = sanitize_text(packet.get("callsign"), 32) or callsign
                self.channel = sanitize_text(packet.get("channel"), 32)
                hb = packet.get("heartbeat_interval_seconds", DEFAULT_HEARTBEAT_SECONDS)
                if isinstance(hb, int) and hb > 0:
                    self.heartbeat_interval = hb
                print("\n\033[1;32m[ACESSO AUTORIZADO]\033[0m")
                print(f"Callsign: {self.callsign} | Canal inicial: {self.channel}\n")
                return True

            if packet_type == "auth_fail":
                message = sanitize_text(packet.get("message"), 120) or "Credenciais invalidas."
                remaining = packet.get("remaining_attempts", "?")
                print(f"\033[1;31m{message} Tentativas restantes: {remaining}\033[0m\n")
                continue

            if packet_type == "auth_ban":
                message = sanitize_text(packet.get("message"), 120)
                retry_after = packet.get("retry_after_seconds", 0)
                print(f"\033[1;31m{message}\033[0m")
                print(f"Tente novamente em {retry_after} segundo(s).")
                return False

            if packet_type == "error":
                code = sanitize_text(packet.get("code"), 60)
                message = sanitize_text(packet.get("message"), 120)
                local_log("ERRO", f"{code}: {message}")
                continue

    def send_authed(self, packet_type: str, **fields) -> bool:
        if not self.session_id:
            return False
        payload = build_packet(packet_type, session_id=self.session_id, **fields)
        return self.send_packet(payload)

    def heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            self.send_authed("heartbeat")
            time.sleep(self.heartbeat_interval)

    def receiver_loop(self) -> None:
        if self.sock:
            self.sock.settimeout(RECV_TIMEOUT_SECONDS)

        while not self.stop_event.is_set():
            packet, err = self.recv_packet()
            if err == "TIMEOUT":
                self.handle_server_silence()
                continue
            if err in {"SOCKET_CLOSED", "SOCKET_ERROR"}:
                if not self.stop_event.is_set():
                    local_log("ERRO", "Canal UDP interrompido.")
                    self.stop_event.set()
                return
            if err:
                continue
            if packet is None:
                continue

            self.handle_packet(packet)

    def handle_server_silence(self) -> None:
        now = time.time()
        silent_for = now - self.last_server_packet
        if silent_for >= SERVER_SILENCE_WARNING_SECONDS:
            if (now - self.last_silence_warning) >= SERVER_SILENCE_WARNING_SECONDS:
                local_log("AVISO", f"Sem pacotes do servidor ha {int(silent_for)}s.")
                self.last_silence_warning = now

    def handle_packet(self, packet: dict) -> None:
        packet_type = packet.get("type")

        if packet_type == "heartbeat_ack":
            return

        if packet_type == "system":
            channel = sanitize_text(packet.get("channel"), 32)
            text = sanitize_text(packet.get("text"), 180)
            stamp = sanitize_text(packet.get("server_time"), 16)
            print_line(f"[{stamp}] [SISTEMA:{channel}] {text}")
            return

        if packet_type == "briefing":
            channel = sanitize_text(packet.get("channel"), 32)
            entries = packet.get("entries", [])
            print_line(f"--- BRIEFING ({channel}) ---")
            if not isinstance(entries, list) or not entries:
                print_line("  (sem historico recente)")
            else:
                for item in entries:
                    if not isinstance(item, dict):
                        continue
                    t = sanitize_text(item.get("server_time"), 16)
                    c = sanitize_text(item.get("callsign"), 32)
                    p = sanitize_text(item.get("priority"), 12).upper()
                    tx = sanitize_text(item.get("text"), 280)
                    print_line(f"  [{t}] [{p}] {c}: {tx}")
            print_line("--------------------------")
            return

        if packet_type == "radio":
            stamp = sanitize_text(packet.get("server_time"), 16)
            channel = sanitize_text(packet.get("channel"), 32)
            callsign = sanitize_text(packet.get("callsign"), 32)
            priority = sanitize_text(packet.get("priority"), 12).upper() or "ROUTINE"
            text = sanitize_text(packet.get("text"), 320)
            print_line(f"[{stamp}] [{channel}] [{priority}] {callsign}: {text}")

            require_ack = bool(packet.get("require_ack"))
            ack_id = sanitize_text(packet.get("ack_id"), 64)
            if require_ack and ack_id:
                self.send_authed("ack", ack_id=ack_id)
            return

        if packet_type == "command_result":
            command = sanitize_text(packet.get("command"), 32)
            if command == "members":
                members = packet.get("members", [])
                channel = sanitize_text(packet.get("channel"), 32)
                print_line(f"--- MEMBROS ({channel}) ---")
                if isinstance(members, list) and members:
                    for m in members:
                        print_line(f"  - {sanitize_text(m, 32)}")
                else:
                    print_line("  (nenhum membro)")
                print_line("--------------------------")
                return

            if command == "status":
                channel = sanitize_text(packet.get("channel"), 32)
                online_total = packet.get("online_total", "?")
                online_channel = packet.get("online_channel", "?")
                pending_critical = packet.get("pending_critical", "?")
                print_line(
                    f"[STATUS] canal={channel} online_total={online_total} "
                    f"online_canal={online_channel} pendencias_criticas={pending_critical}"
                )
                return

            if command == "help":
                print_line("--- AJUDA REMOTA ---")
                lines = packet.get("lines", [])
                if isinstance(lines, list):
                    for line in lines:
                        print_line(f"  {sanitize_text(line, 120)}")
                print_line("--------------------")
                return

            if command == "switch_channel":
                message = sanitize_text(packet.get("message"), 120)
                channel = sanitize_text(packet.get("channel"), 32)
                self.channel = channel or self.channel
                print_line(f"[CANAL] {message}")
                return

            return

        if packet_type == "critical_update":
            msg_id = sanitize_text(packet.get("msg_id"), 32)
            expected = packet.get("expected", 0)
            acked = packet.get("acked", 0)
            failed = packet.get("failed", 0)
            done = bool(packet.get("done"))
            tail = " (concluido)" if done else ""
            print_line(
                f"[CRITICO] msg={msg_id} ack={acked}/{expected} falhas={failed}{tail}"
            )
            return

        if packet_type == "logout_ack":
            message = sanitize_text(packet.get("message"), 120)
            print_line(message)
            self.stop_event.set()
            return

        if packet_type == "error":
            code = sanitize_text(packet.get("code"), 60)
            message = sanitize_text(packet.get("message"), 200)
            print_line(f"[ERRO] {code}: {message}")
            return

    def print_help(self) -> None:
        print_line("--- COMANDOS LOCAIS ---")
        print_line("  /membros       lista membros no canal atual")
        print_line("  /status        estado operacional")
        print_line("  /ajuda         ajuda do servidor")
        print_line("  /canal <nome>  troca de canal")
        print_line("  /urg <texto>   envio urgente")
        print_line("  /crit <texto>  envio critico (ack/reenvio)")
        print_line("  /sair          encerra sessao")
        print_line("  /help          mostra esta ajuda")
        print_line("-----------------------")

    def input_loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    raw = input().strip()
                except EOFError:
                    break

                if not raw:
                    continue

                lowered = raw.lower()

                if lowered == "/help":
                    self.print_help()
                    continue

                if lowered == "/membros":
                    self.send_authed("command", command="members")
                    continue

                if lowered == "/status":
                    self.send_authed("command", command="status")
                    continue

                if lowered == "/ajuda":
                    self.send_authed("command", command="help")
                    continue

                if lowered.startswith("/canal "):
                    new_channel = sanitize_text(raw[7:], 32)
                    self.send_authed("command", command="switch_channel", channel=new_channel)
                    continue

                if lowered.startswith("/urg "):
                    text = sanitize_text(raw[5:], 300)
                    if text:
                        self.send_authed("radio", priority="urgent", text=text)
                    continue

                if lowered.startswith("/crit "):
                    text = sanitize_text(raw[6:], 300)
                    if text:
                        self.send_authed("radio", priority="critical", text=text)
                    continue

                if lowered == "/sair":
                    self.send_authed("logout")
                    self.stop_event.set()
                    break

                self.send_authed("radio", priority="routine", text=raw)

        except KeyboardInterrupt:
            print()
            local_log("INFO", "Encerrando por Ctrl+C...")
            self.send_authed("logout")
            self.stop_event.set()

    def run(self) -> None:
        print("\033[1;36m")
        print("===============================================")
        print("   RESCUERADIO UDP | CENTRAL DE RESGATE")
        print("   Baixa latencia, canal tatico por datagrama")
        print("===============================================")
        print(f"\033[0mDestino: {self.host}:{self.port}")

        if not self.connect():
            sys.exit(1)

        if not self.auth_flow():
            self.disconnect()
            sys.exit(1)

        local_log("INFO", "Canal ativo. Digite /help para comandos.")

        recv_thread = threading.Thread(target=self.receiver_loop, daemon=True)
        hb_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        recv_thread.start()
        hb_thread.start()

        self.input_loop()

        recv_thread.join(timeout=2)
        hb_thread.join(timeout=2)
        self.disconnect()
        print("\n\033[1;33mSessao finalizada. Retorne em seguranca.\033[0m\n")


def parse_args() -> tuple[str, int]:
    host = sys.argv[1] if len(sys.argv) > 1 else SERVER_HOST
    try:
        port = int(sys.argv[2]) if len(sys.argv) > 2 else SERVER_PORT
    except ValueError:
        print(f"Porta invalida '{sys.argv[2]}'. Usando padrao {SERVER_PORT}.")
        port = SERVER_PORT
    return host, port


if __name__ == "__main__":
    h, p = parse_args()
    RescueRadioUDPClient(host=h, port=p).run()
