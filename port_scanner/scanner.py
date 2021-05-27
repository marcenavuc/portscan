import random
import socket
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from queue import Queue


random_time = random.randint(2 ** 16, 2 ** 64 - 1).to_bytes(8, 'big')
udp_to_send = b'\x13' + b'\0' * 39 + random_time


class Scanner:
    def __init__(self, host: str, port_start: int, port_end: int,
                 max_workers=2):
        self.host = host
        self.port_start = port_start
        self.port_end = port_end

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

    def scan_udp_port(self, port: int, timeout=1):
        if self.end:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as client:
                    client.sendto("ping".encode('utf_8'), (self.host, port))
                    sock.settimeout(timeout)
                    sock.recvfrom(1024)
        except socket.timeout:
            protocol = self.get_protocol(port, 'udp')
            if protocol:
                print(f'UDP {port} {protocol}')
        except PermissionError:
            with self.print_lock:
                print(f'UDP {port}: Not enough rights')

    def scan_tcp_port(self, port: int, timeout=0.5):
        if self.end:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((self.host, port))
            protocol = self.get_protocol(port, 'tcp')
            with self.print_lock:
                print(f'TCP {port} {protocol}')
        except (socket.timeout, OSError, ConnectionRefusedError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(port: int, transport: str) -> str:
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
