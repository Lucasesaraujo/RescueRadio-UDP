import secrets
import socket
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from auth import AuthManager
from protocol import MAX_DATAGRAM_BYTES, build_packet, decode_packet, encode_packet, sanitize_text


Address = tuple[str, int]

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 12345
DEFAULT_CHANNEL = "resgate-principal"

MAX_AUTH_ATTEMPTS = 3
AUTH_WINDOW_SECONDS = 90
SESSION_TIMEOUT_SECONDS = 35
HEARTBEAT_GRACE_SECONDS = 15

HISTORY_SIZE = 30
MAX_MESSAGE_LEN = 280
MAX_CALLSIGN_LEN = 24
MAX_USERNAME_LEN = 32
MAX_CHANNEL_LEN = 24

SOCKET_TIMEOUT_SECONDS = 0.25
CRITICAL_RETRY_INTERVAL = 1.5
CRITICAL_MAX_RETRIES = 3


@dataclass
class Session:
    addr: Address
    session_id: str
    username: str
    callsign: str
    channel: str
    last_seen: float
    last_heartbeat: float


@dataclass
class AuthWindow:
    attempts: int
    last_attempt: float


@dataclass
class PendingDelivery:
    ack_id: str
    msg_id: str
    sender_addr: Address
    recipient_addr: Address
    payload: dict
    next_retry_at: float
    retries_left: int


@dataclass
class CriticalStatus:
    sender_addr: Address
    expected: int
    acked: int = 0
    failed: int = 0


class RescueRadioUDPServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.auth = AuthManager()
        self.sessions: dict[Address, Session] = {}
        self.auth_windows: dict[Address, AuthWindow] = {}
        self.history_by_channel: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=HISTORY_SIZE)
        )
        self.pending_critical: dict[str, PendingDelivery] = {}
        self.critical_status: dict[str, CriticalStatus] = {}

        if self.auth.count() == 0:
            self.log("AVISO", "Nenhum operador cadastrado. Execute admin.py antes de conectar clientes.")

    def log(self, level: str, message: str) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] [{level}] {message}")

    def send_packet(self, addr: Address, payload: dict) -> None:
        raw = encode_packet(payload)
        if len(raw) > MAX_DATAGRAM_BYTES:
            self.log("AVISO", f"Drop de pacote para {addr}: payload acima do limite UDP.")
            return
        try:
            self.sock.sendto(raw, addr)
        except OSError as exc:
            self.log("ERRO", f"Falha ao enviar para {addr}: {exc}")

    def send_error(self, addr: Address, code: str, message: str) -> None:
        safe_code = sanitize_text(code, 40) or "ERROR"
        safe_message = sanitize_text(message, 180) or "Erro de protocolo."
        self.send_packet(addr, build_packet("error", code=safe_code, message=safe_message))

    def start(self) -> None:
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        self.log("INFO", f"RescueRadio UDP online em {self.host}:{self.port}")

        while True:
            now = time.time()
            try:
                raw, addr = self.sock.recvfrom(MAX_DATAGRAM_BYTES)
            except socket.timeout:
                self.run_maintenance(now)
                continue
            except OSError as exc:
                self.log("ERRO", f"Erro no socket: {exc}")
                self.run_maintenance(now)
                continue

            payload, err = decode_packet(raw)
            if err:
                self.send_error(addr, err, "Pacote invalido para o protocolo do canal.")
                self.run_maintenance(now)
                continue

            self.handle_packet(addr, payload, now)
            self.run_maintenance(now)

    def handle_packet(self, addr: Address, payload: dict, now: float) -> None:
        packet_type = payload["type"]

        if packet_type == "auth":
            self.handle_auth(addr, payload, now)
            return

        session = self.validate_session(addr, payload, now)
        if session is None:
            return

        if packet_type == "heartbeat":
            session.last_heartbeat = now
            self.send_packet(
                addr,
                build_packet(
                    "heartbeat_ack",
                    online_total=len(self.sessions),
                    online_channel=self.online_in_channel(session.channel),
                ),
            )
            return

        if packet_type == "radio":
            self.handle_radio(session, payload, now)
            return

        if packet_type == "command":
            self.handle_command(session, payload, now)
            return

        if packet_type == "ack":
            self.handle_ack(session, payload)
            return

        if packet_type == "logout":
            self.remove_session(addr, reason="desconectou", announce=True)
            self.send_packet(addr, build_packet("logout_ack", message="Sessao encerrada."))
            return

        self.send_error(addr, "UNKNOWN_PACKET_TYPE", f"Tipo de pacote nao suportado: {packet_type}")

    def validate_session(self, addr: Address, payload: dict, now: float) -> Session | None:
        session = self.sessions.get(addr)
        if session is None:
            self.send_error(addr, "NOT_AUTHENTICATED", "Autentique antes de usar o canal.")
            return None

        packet_session_id = sanitize_text(payload.get("session_id"), 64)
        if packet_session_id != session.session_id:
            self.send_error(addr, "SESSION_INVALID", "Sessao invalida para este remetente.")
            return None

        session.last_seen = now
        return session

    def handle_auth(self, addr: Address, payload: dict, now: float) -> None:
        if self.is_banned(addr, now):
            remaining = int(AUTH_WINDOW_SECONDS - (now - self.auth_windows[addr].last_attempt))
            self.send_packet(
                addr,
                build_packet(
                    "auth_ban",
                    message="Acesso temporariamente bloqueado por excesso de tentativas.",
                    retry_after_seconds=max(1, remaining),
                ),
            )
            return

        username = sanitize_text(payload.get("username"), MAX_USERNAME_LEN)
        password = payload.get("password")
        callsign = sanitize_text(payload.get("callsign"), MAX_CALLSIGN_LEN) or username

        if not username or not isinstance(password, str) or not password:
            self.register_auth_failure(addr, now)
            return

        if not self.auth.verify(username, password):
            self.register_auth_failure(addr, now)
            self.log("AVISO", f"Auth FAIL para '{username}' de {addr}")
            return

        self.drop_existing_username(username, current_addr=addr)

        session = Session(
            addr=addr,
            session_id=secrets.token_hex(16),
            username=username,
            callsign=callsign,
            channel=DEFAULT_CHANNEL,
            last_seen=now,
            last_heartbeat=now,
        )
        self.sessions[addr] = session
        self.auth_windows.pop(addr, None)

        self.log("INFO", f"Auth OK: {session.callsign} ({session.username}) de {addr}")

        self.send_packet(
            addr,
            build_packet(
                "auth_ok",
                session_id=session.session_id,
                callsign=session.callsign,
                channel=session.channel,
                heartbeat_interval_seconds=5,
                session_timeout_seconds=SESSION_TIMEOUT_SECONDS,
            ),
        )
        self.send_briefing(addr, session.channel)
        self.broadcast_system(session.channel, f"{session.callsign} entrou no canal.", exclude=addr)

    def register_auth_failure(self, addr: Address, now: float) -> None:
        window = self.auth_windows.get(addr)
        if window is None or (now - window.last_attempt) > AUTH_WINDOW_SECONDS:
            window = AuthWindow(attempts=0, last_attempt=now)

        window.attempts += 1
        window.last_attempt = now
        self.auth_windows[addr] = window

        if window.attempts >= MAX_AUTH_ATTEMPTS:
            self.send_packet(
                addr,
                build_packet(
                    "auth_ban",
                    message="Acesso temporariamente bloqueado por excesso de tentativas.",
                    retry_after_seconds=AUTH_WINDOW_SECONDS,
                ),
            )
        else:
            remaining = MAX_AUTH_ATTEMPTS - window.attempts
            self.send_packet(
                addr,
                build_packet(
                    "auth_fail",
                    message="Credenciais invalidas.",
                    remaining_attempts=remaining,
                ),
            )

    def is_banned(self, addr: Address, now: float) -> bool:
        window = self.auth_windows.get(addr)
        if window is None:
            return False

        if (now - window.last_attempt) > AUTH_WINDOW_SECONDS:
            self.auth_windows.pop(addr, None)
            return False

        return window.attempts >= MAX_AUTH_ATTEMPTS

    def drop_existing_username(self, username: str, current_addr: Address) -> None:
        for addr, session in list(self.sessions.items()):
            if addr != current_addr and session.username == username:
                self.remove_session(addr, reason="sessao substituida", announce=True)

    def handle_radio(self, session: Session, payload: dict, now: float) -> None:
        text = sanitize_text(payload.get("text"), MAX_MESSAGE_LEN)
        priority = sanitize_text(payload.get("priority"), 12).lower() or "routine"
        if priority not in {"routine", "urgent", "critical"}:
            priority = "routine"

        if not text:
            self.send_error(session.addr, "MESSAGE_EMPTY", "Mensagem vazia nao pode ser enviada.")
            return

        msg_id = secrets.token_hex(8)
        event = build_packet(
            "radio",
            msg_id=msg_id,
            channel=session.channel,
            callsign=session.callsign,
            priority=priority,
            text=text,
            server_time=datetime.now().strftime("%H:%M:%S"),
        )

        self.append_history(session.channel, event)
        recipients = self.channel_recipients(session.channel)

        expected_acks = 0
        for recipient in recipients:
            outbound = dict(event)
            if priority == "critical" and recipient != session.addr:
                ack_id = secrets.token_hex(10)
                outbound["require_ack"] = True
                outbound["ack_id"] = ack_id
                self.pending_critical[ack_id] = PendingDelivery(
                    ack_id=ack_id,
                    msg_id=msg_id,
                    sender_addr=session.addr,
                    recipient_addr=recipient,
                    payload=outbound,
                    next_retry_at=now + CRITICAL_RETRY_INTERVAL,
                    retries_left=CRITICAL_MAX_RETRIES,
                )
                expected_acks += 1
            else:
                outbound["require_ack"] = False

            self.send_packet(recipient, outbound)

        if priority == "critical":
            self.critical_status[msg_id] = CriticalStatus(
                sender_addr=session.addr,
                expected=expected_acks,
            )
            self.send_packet(
                session.addr,
                build_packet(
                    "critical_update",
                    msg_id=msg_id,
                    expected=expected_acks,
                    acked=0,
                    failed=0,
                    done=(expected_acks == 0),
                ),
            )

    def handle_ack(self, session: Session, payload: dict) -> None:
        ack_id = sanitize_text(payload.get("ack_id"), 64)
        if not ack_id:
            return

        pending = self.pending_critical.get(ack_id)
        if pending is None:
            return

        if pending.recipient_addr != session.addr:
            return

        del self.pending_critical[ack_id]
        status = self.critical_status.get(pending.msg_id)
        if status is None:
            return

        status.acked += 1
        self.push_critical_update(pending.msg_id, status)

    def push_critical_update(self, msg_id: str, status: CriticalStatus) -> None:
        sender = self.sessions.get(status.sender_addr)
        done = (status.acked + status.failed) >= status.expected
        payload = build_packet(
            "critical_update",
            msg_id=msg_id,
            expected=status.expected,
            acked=status.acked,
            failed=status.failed,
            done=done,
        )

        if sender:
            self.send_packet(sender.addr, payload)

        if done:
            self.critical_status.pop(msg_id, None)

    def handle_command(self, session: Session, payload: dict, now: float) -> None:
        command = sanitize_text(payload.get("command"), 32).lower()

        if command == "members":
            members = [
                s.callsign
                for s in self.sessions.values()
                if s.channel == session.channel
            ]
            self.send_packet(
                session.addr,
                build_packet(
                    "command_result",
                    command="members",
                    channel=session.channel,
                    members=sorted(members),
                ),
            )
            return

        if command == "status":
            self.send_packet(
                session.addr,
                build_packet(
                    "command_result",
                    command="status",
                    channel=session.channel,
                    online_total=len(self.sessions),
                    online_channel=self.online_in_channel(session.channel),
                    pending_critical=len(self.pending_critical),
                ),
            )
            return

        if command == "help":
            self.send_packet(
                session.addr,
                build_packet(
                    "command_result",
                    command="help",
                    lines=[
                        "/membros -> lista membros no canal atual",
                        "/status  -> status operacional",
                        "/canal X -> troca de canal",
                        "/urg TXT -> mensagem urgente",
                        "/crit TXT -> mensagem critica com reenvio/ack",
                        "/sair    -> encerra sessao",
                    ],
                ),
            )
            return

        if command == "switch_channel":
            raw_channel = sanitize_text(payload.get("channel"), MAX_CHANNEL_LEN)
            new_channel = self.normalize_channel(raw_channel)
            if not new_channel:
                self.send_error(session.addr, "CHANNEL_INVALID", "Nome de canal invalido.")
                return

            if new_channel == session.channel:
                self.send_packet(
                    session.addr,
                    build_packet(
                        "command_result",
                        command="switch_channel",
                        channel=session.channel,
                        message="Voce ja esta neste canal.",
                    ),
                )
                return

            old_channel = session.channel
            session.channel = new_channel
            session.last_seen = now

            self.broadcast_system(old_channel, f"{session.callsign} saiu para {new_channel}.", exclude=session.addr)
            self.broadcast_system(new_channel, f"{session.callsign} entrou no canal.", exclude=session.addr)
            self.send_packet(
                session.addr,
                build_packet(
                    "command_result",
                    command="switch_channel",
                    channel=session.channel,
                    message=f"Canal alterado para {session.channel}.",
                ),
            )
            self.send_briefing(session.addr, session.channel)
            return

        self.send_error(session.addr, "COMMAND_UNKNOWN", f"Comando desconhecido: {command}")

    def run_maintenance(self, now: float) -> None:
        for addr, session in list(self.sessions.items()):
            idle_for = now - max(session.last_seen, session.last_heartbeat)
            if idle_for > (SESSION_TIMEOUT_SECONDS + HEARTBEAT_GRACE_SECONDS):
                self.remove_session(addr, reason="inatividade", announce=True)

        for ack_id, pending in list(self.pending_critical.items()):
            if now < pending.next_retry_at:
                continue

            if pending.retries_left <= 0:
                self.pending_critical.pop(ack_id, None)
                status = self.critical_status.get(pending.msg_id)
                if status is not None:
                    status.failed += 1
                    self.push_critical_update(pending.msg_id, status)
                continue

            pending.retries_left -= 1
            pending.next_retry_at = now + CRITICAL_RETRY_INTERVAL
            self.send_packet(pending.recipient_addr, pending.payload)

    def remove_session(self, addr: Address, reason: str, announce: bool) -> None:
        session = self.sessions.pop(addr, None)
        if session is None:
            return

        self.log("INFO", f"Sessao encerrada: {session.callsign} ({reason})")
        if announce:
            self.broadcast_system(session.channel, f"{session.callsign} saiu do canal ({reason}).", exclude=addr)

        for ack_id, pending in list(self.pending_critical.items()):
            if pending.recipient_addr == addr:
                self.pending_critical.pop(ack_id, None)
                status = self.critical_status.get(pending.msg_id)
                if status is not None:
                    status.failed += 1
                    self.push_critical_update(pending.msg_id, status)

    def online_in_channel(self, channel: str) -> int:
        return sum(1 for s in self.sessions.values() if s.channel == channel)

    def channel_recipients(self, channel: str) -> list[Address]:
        return [s.addr for s in self.sessions.values() if s.channel == channel]

    def append_history(self, channel: str, event: dict) -> None:
        item = {
            "server_time": event.get("server_time", ""),
            "callsign": event.get("callsign", ""),
            "priority": event.get("priority", "routine"),
            "text": event.get("text", ""),
        }
        self.history_by_channel[channel].append(item)

    def send_briefing(self, addr: Address, channel: str) -> None:
        entries = list(self.history_by_channel[channel])
        self.send_packet(
            addr,
            build_packet("briefing", channel=channel, entries=entries),
        )

    def broadcast_system(self, channel: str, text: str, exclude: Address | None = None) -> None:
        packet = build_packet(
            "system",
            channel=channel,
            text=text,
            server_time=datetime.now().strftime("%H:%M:%S"),
        )
        for recipient in self.channel_recipients(channel):
            if exclude is not None and recipient == exclude:
                continue
            self.send_packet(recipient, packet)

    def normalize_channel(self, raw: str) -> str:
        lowered = raw.lower().replace(" ", "-")
        allowed = "".join(ch for ch in lowered if ch.isalnum() or ch in {"-", "_"})
        return allowed[:MAX_CHANNEL_LEN]


if __name__ == "__main__":
    RescueRadioUDPServer().start()
