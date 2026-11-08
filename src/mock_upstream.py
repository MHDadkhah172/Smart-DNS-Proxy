import socket
import sys
from config import load_config


def build_mock_response(query_data, fake_ip="93.184.216.34"):
    """Build a minimal DNS A-record response."""
    if len(query_data) < 12:
        return b""

    # Header: ID, standard response flags, and record counts (1 question, 1 answer)
    tx_id = query_data[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"

    # Find the end of QNAME (marked by a 0x00 byte)
    idx = 12
    while idx < len(query_data):
        length = query_data[idx]
        if length == 0:
            idx += 1
            break
        idx += 1 + length

    # Copy Question: QNAME + QTYPE (2B) + QCLASS (2B)
    question_section = query_data[12:idx + 4]

    # Answer: pointer to QNAME (0xc00c) + Type A & Class IN + TTL 60s + 4-byte IP
    name_ptr = b"\xc0\x0c"
    type_class = b"\x00\x01\x00\x01"
    ttl = b"\x00\x00\x00\x3c"
    rdlength = b"\x00\x04"
    rdata = socket.inet_aton(fake_ip)

    answer = name_ptr + type_class + ttl + rdlength + rdata

    return tx_id + flags + counts + question_section + answer


def run_mock_server():
    """Run UDP mock DNS server."""
    config = load_config()
    ip = config["upstream_ip"]
    port = config["upstream_port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind((ip, port))
        print(f"[*] Mock Upstream DNS is running on {ip}:{port} (UDP)")
    except Exception as e:
        print(f"Failed to bind to {ip}:{port}: {e}")
        sys.exit(1)

    try:
        while True:
            # Receive query, generate fake response, and send back
            data, client_address = sock.recvfrom(512)
            print(f"[Mock] Received query ({len(data)} bytes) from {client_address}")

            response = build_mock_response(data)
            if response:
                sock.sendto(response, client_address)

    except KeyboardInterrupt:
        print("\n[*] Stopping Mock Upstream DNS.")
    finally:
        sock.close()


if __name__ == "__main__":
    run_mock_server()