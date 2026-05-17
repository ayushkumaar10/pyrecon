import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


common_ports = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}


possible_vulns = {
    "FTP": [
        "Anonymous login enabled",
        "Weak credentials",
        "Outdated FTP server"
    ],

    "SSH": [
        "Weak passwords",
        "Outdated OpenSSH version",
        "Password authentication enabled"
    ],

    "Telnet": [
        "Unencrypted communication",
        "Default credentials"
    ],

    "HTTP": [
        "Directory listing",
        "Missing security headers",
        "Outdated web server"
    ],

    "HTTP-Alt": [
        "Directory listing",
        "Missing security headers",
        "Outdated web server"
    ],

    "HTTPS": [
        "Weak SSL/TLS configuration",
        "Expired certificate"
    ],

    "SMB": [
        "SMBv1 enabled",
        "EternalBlue exposure",
        "Null sessions"
    ],

    "MySQL": [
        "Weak database credentials",
        "Remote root login"
    ],

    "RDP": [
        "BlueKeep exposure",
        "Weak passwords",
        "NLA disabled"
    ],

    "Redis": [
        "Unauthenticated access",
        "Remote code execution risks"
    ],

    "MongoDB": [
        "Unauthenticated database access"
    ],

    "PostgreSQL": [
        "Weak credentials",
        "Exposed database service"
    ],

    "VNC": [
        "Weak authentication",
        "No encryption"
    ],

    "WinRM": [
        "Weak credentials",
        "Remote management exposure"
    ]
}


def identify_service(port, banner):

    if port in common_ports:
        return common_ports[port]

    if "HTTP" in banner:
        return "HTTP"

    if "SSH" in banner:
        return "SSH"

    if "FTP" in banner:
        return "FTP"

    return "Unknown"

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((target, port))

        if result == 0:
            banner = ""

            try:
                # Try HTTP probe
                s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                pass

            if not banner:
                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except:
                    pass

            if not banner:
                banner = "Unknown Service"

            s.close()
            return (port, banner)

        s.close()

    except:
        return None

def scan_ports(target, port_range):
    print(f"[+] Scanning {target} on ports {port_range}")

    start, end = map(int, port_range.split("-"))

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(scan_port, target, port)
            for port in range(start, end + 1)
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                service = identify_service(port, banner)

                print(f"[OPEN] Port {port} → {service}")

                if service in possible_vulns:
                    print("  Possible Issues:")

                    for vuln in possible_vulns[service]:
                        print(f"   - {vuln}")
	
 
