import socket


def query_dns(domain, tx_id=b"\xaa\xbb", port=8053):
    """Build a raw DNS query packet, send it to the proxy, and return the resolved IP."""
    # 1. Construct the 12-byte DNS header
    header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    # 2. Encode the domain name into DNS wire format (e.g., google.com -> 6google3com0)
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode("utf-8")
    qname += b"\x00"

    # 3. Append QTYPE (Type A = 1) and QCLASS (IN = 1)
    packet = header + qname + b"\x00\x01\x00\x01"

    # 4. Send the packet over UDP and parse the response
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(packet, ("127.0.0.1", port))
        response, _ = sock.recvfrom(512)
        resolved_ip = socket.inet_ntoa(response[-4:])
        resp_tx_id = response[:2]
        return resolved_ip, resp_tx_id
    finally:
        sock.close()


def run_all_tests():
    print("Starting automated tests...\n")

    # Test 1: Exact ad-domain blocking
    ip, _ = query_dns("ads.example.com")
    assert ip == "0.0.0.0", f"Ad-block test failed: {ip}"
    print("[PASS] 1. Ad-block exact match")

    # Test 2: Subdomain ad-blocking (suffix matching)
    ip, _ = query_dns("banner.tracker.example.net")
    assert ip == "0.0.0.0", f"Subdomain ad-block test failed: {ip}"
    print("[PASS] 2. Ad-block subdomain match")

    # Test 3: Sanction-bypass redirection
    ip, _ = query_dns("service.example.org")
    assert ip == "192.0.2.10", f"Sanction bypass test failed: {ip}"
    print("[PASS] 3. Sanction bypass redirect")

    # Test 4: Policy priority when domain exists in both lists
    ip, _ = query_dns("both.example.com")
    assert ip == "0.0.0.0", f"Policy priority test failed: {ip}"
    print("[PASS] 4. Priority overlap (Ad > Sanction)")

    # Test 5: Upstream forwarding and cache Transaction ID replacement
    ip1, tx1 = query_dns("github.com", tx_id=b"\x11\x22")
    ip2, tx2 = query_dns("github.com", tx_id=b"\x33\x44")
    assert ip1 == "93.184.216.34" and tx1 == b"\x11\x22"
    assert ip2 == "93.184.216.34" and tx2 == b"\x33\x44"
    print("[PASS] 5. Upstream forward & Cache ID replacement")

    print("\nAll tests passed successfully!")


if __name__ == "__main__":
    run_all_tests()