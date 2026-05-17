import argparse

from modules.scanner.port_scanner import scan_ports
from modules.web.dir_bruteforce import dir_scan


def run():

    parser = argparse.ArgumentParser(description="My VAPT Tool")

    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan ports")
    scan_parser.add_argument("target")
    scan_parser.add_argument("-p", "--ports", default="1-100")

    # Directory brute force command
    dir_parser = subparsers.add_parser("dir", help="Directory brute force")
    dir_parser.add_argument("url")
    dir_parser.add_argument("-w", "--wordlist", required=True)

    args = parser.parse_args()

    if args.command == "scan":
        scan_ports(args.target, args.ports)

    elif args.command == "dir":
        dir_scan(args.url, args.wordlist)

    else:
        parser.print_help()
