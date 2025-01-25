import socket
import threading
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from dnslib import DNSRecord, QTYPE, RR, A

def parse_arguments():
    parser = argparse.ArgumentParser(description='Simple DNS and HTTP Server')
    parser.add_argument('--http-ip', type=str, required=True, help='IP адрес HTTP сервера')
    parser.add_argument('--forward-dns', type=str, default='8.8.8.8', help='IP форвард DNS сервера')
    return parser.parse_args()

def dns_response(data, addr, sock, http_server_ip, forward_dns):
    request = DNSRecord.parse(data)
    qname = request.q.qname
    qtype = request.q.qtype

    print(f"Received DNS request for {qname} (Type: {QTYPE[qtype]}) from {addr}")

    if any(qname.matchSuffix(domain) for domain in ALLOWED_DOMAINS) and qtype in [QTYPE.A, QTYPE.ANY]:
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(http_server_ip)))
        sock.sendto(reply.pack(), addr)
        print(f"Responded to {qname} with local IP {http_server_ip}")
    else:
        print(f"Forwarding DNS request for {qname} to {forward_dns}")
        forward_and_respond(data, addr, sock, forward_dns)

def forward_and_respond(data, addr, sock, forward_dns):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_socket:
        forward_socket.settimeout(5)
        forward_socket.sendto(data, (forward_dns, DNS_PORT))
        try:
            response_data, _ = forward_socket.recvfrom(512)
            sock.sendto(response_data, addr)
            print(f"Received and forwarded response for forwarded query")
        except socket.timeout:
            print(f"Timeout waiting for response from forward DNS {forward_dns}")

def run_dns_server(http_server_ip, forward_dns):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', DNS_PORT))
        print(f"DNS server listening on port {DNS_PORT}")

        while True:
            try:
                data, addr = sock.recvfrom(512)
                dns_response(data, addr, sock, http_server_ip, forward_dns)
            except Exception as e:
                print(f"Error during DNS response: {e}")
    except Exception as main_exception:
        print(f"Main DNS server error: {main_exception}")
    finally:
        sock.close()

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Обработка запросов
        if self.path.startswith(NETWORK_CHECK_PATH) or self.path.startswith("/generate_204_"):
            self.send_response(204)
            self.end_headers()
        elif self.path == "/hotspot-detect.html":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Success")
        elif self.path == "/ncsi.txt":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Microsoft NCSI")
        elif self.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Success")
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        if self.path.startswith(NETWORK_CHECK_PATH) or self.path.startswith("/generate_204_"):
            self.send_response(204)
        elif self.path in ("/hotspot-detect.html", "/ncsi.txt", "/"):
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

def run_http_server():
    server_address = ('', HTTP_PORT)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"HTTP server running on port {HTTP_PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    args = parse_arguments()

    ALLOWED_DOMAINS = [
        "connectivitycheck.gstatic.com", 
        "clients3.google.com", 
        "www.apple.com", 
        "www.msftncsi.com",
        "connectivitycheck.platform.hicloud.com",
        "captive.apple.com"
    ]
    NETWORK_CHECK_PATH = "/generate_204"
    DNS_PORT = 53
    HTTP_PORT = 80

    dns_thread = threading.Thread(target=run_dns_server, args=(args.http_ip, args.forward_dns))
    http_thread = threading.Thread(target=run_http_server)

    dns_thread.start()
    http_thread.start()

    dns_thread.join()
    http_thread.join()