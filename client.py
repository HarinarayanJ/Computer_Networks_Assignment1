import dpkt
from datetime import datetime
import socket
import textwrap

HOST = ''
PORT = 50007              # The same port as used by the server

filePath = input("File path: ")
dnsQueries = []

with open(filePath, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)

    for i,(timestamp, buf) in enumerate(pcap):
        try:
            # Parse Ethernet frame
            eth = dpkt.ethernet.Ethernet(buf)

            # Make sure the packet contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data

            # Check for UDP packets (DNS usually runs over UDP port 53)
            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data

                # Filter packets where source or destination port is 53 (DNS)
                if udp.sport == 53 or udp.dport == 53:
                    try:
                        dns = dpkt.dns.DNS(udp.data)

                        # We want only DNS queries (qr == 0)
                        if dns.qr == dpkt.dns.DNS_Q:
                            for question in dns.qd:
                                # question.name is a bytes object, decode it to string
                                print(f'Found DNS Query (len {len(buf)}): {question.name}')
                                dnsQueries.append(buf)
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        # Ignore packets that can't be parsed as DNS
                        continue
        except Exception as e:
            # General exception catch for malformed packets or unexpected errors
            print("Error:",str(e))
            continue

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    for i, buf in enumerate(dnsQueries):
        dt = datetime.now().strftime("%H%M%S")
        custom_header = f"{dt}{str(i).rjust(2, '0')}"
        query = custom_header.encode() + buf
        s.sendto(query, (HOST, PORT))
        print('\n'+'-'*50)
        print("Custom Header: ", custom_header)
        print("\nQuery (UTF-8):")
        print(query.decode('utf-8', errors="replace"))
        print("\nQuery (hex):")
        print("\n".join(textwrap.wrap(query.hex(), 32)))

        data = s.recv(16)
        print("\nReceived response (hex):", data.hex())
        print("Parsed IP address: ", data.decode())
        print()
