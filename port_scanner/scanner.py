import random
import socket
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from queue import Queue


class Scanner:
    def __init__(self, host: str, port_start: int, port_end: int,
                 max_workers=2, timeout=1):
        self.host = host
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout

        self.ports_queue = Queue()
        self.print_lock = Lock()
        self.max_workers = max_workers
        self.executor: ThreadPoolExecutor = None
        self.end = False

    def start(self, tcp_only: bool, udp_only: bool):
        if self.executor is None:
            raise ValueError("You need run this method in contextmanager")
        futures = []
        for port in range(self.port_start, self.port_end + 1):
            if tcp_only:
                futures.append(self.executor.submit(self.scan_tcp_port, port))
            if udp_only:
                futures.append(self.executor.submit(self.scan_udp_port, port))

    def scan_udp_port(self, port: int):
        if self.end:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as client:
                    client.sendto("ping".encode('utf_8'), (self.host, port))
                    sock.settimeout(self.timeout)
                    sock.recvfrom(1024)
        except socket.timeout:
            data = sock.recv(1024)
            print(data)
            protocol = self.get_protocol(port, 'udp')
            if protocol:
                print(f'UDP {port} {protocol}')
        except PermissionError:
            with self.print_lock:
                print(f'UDP {port}: Not enough rights')

    def scan_tcp_port(self, port: int):
        if self.end:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.host, port))
                try:
                    sock.send(b'a'*250 + b'\r\n\r\n')
                    data = sock.recv(1024)
                except socket.timeout:
                    data = b""
            protocol = self.get_protocol(port, 'tcp', data)
            with self.print_lock:
                print(f'TCP {port} {protocol}')
        except (socket.timeout, ConnectionRefusedError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(port: int, transport: str, data: bytes
                     ) -> str:
        if len(data) > 4 and b'HTTP' in data:
            return 'HTTP'

        if b'SMTP' in data or b'EHLO' in data:
            return 'SMTP'

        if b'POP3' in data or data.startswith(b'+OK') or data.startswith(b'+'):
            return 'POP3'

        if b'IMAP' in data:
            return 'IMAP'

        try:
            return socket.getservbyport(port, transport).upper()
        except OSError:
            return ''

    def __enter__(self):
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.executor.shutdown()

    def cancel(self):
        self.end = True
