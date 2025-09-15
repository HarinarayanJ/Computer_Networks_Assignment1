IP_POOL = [
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]


import socket


HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50007              # Arbitrary non-privileged port


def ipBasedOnHour(hour, queryID):
    if 4 <= hour < 12:
        return IP_POOL[queryID%5]
    if 12 <= hour <18:
        return IP_POOL[5 + queryID%5]
    if 18 <= hour <= 24 or 0 <= hour < 4:
        return IP_POOL[10 + queryID%5]


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))
    while True:
        data, addr = s.recvfrom(512)
        if(data):
            timestamp, queryID, pkt = data[:6].decode(), int(data[6:8]), data[8:]
            hour = int(timestamp[:2])
            ip = ipBasedOnHour(hour, queryID)
            s.sendto(ip.encode(), addr)