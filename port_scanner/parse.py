from argparse import ArgumentParser


def parse_args():
    parser = ArgumentParser(description='TCP and UDP port scanner')
    parser.add_argument('-t', '--tcp_only',
                        help='Scan only TCP ports',
                        action='store_true')
    parser.add_argument('-u', '--udp_only',
                        help='Scan only UDP ports',
                        action='store_true')
    parser.add_argument('-p', '--ports', nargs=2,
                        default=[1, 65535], type=int,
                        metavar='PORT', help='Port range')
    parser.add_argument("-j", "--jobs", default=2,
                        help="max threads", type=int)
    parser.add_argument('host', help='hostname in network')
    return parser.parse_args()
