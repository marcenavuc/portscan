from port_scanner import Scanner
from port_scanner.parse import parse_args


args = parse_args()
with Scanner(args.host, args.ports[0], args.ports[1], args.jobs,
             args.timeout) as scanner:
    try:
        scanner.start(args.tcp_only, args.udp_only)
    except KeyboardInterrupt:
        scanner.cancel()
