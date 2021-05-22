from port_scanner import Scanner
from port_scanner.parse import parse_args


args = parse_args()
with Scanner(args.host, args.ports[0], args.ports[1], args.jobs) as scanner:
    scanner.start(args.tcp_only, args.udp_only)
