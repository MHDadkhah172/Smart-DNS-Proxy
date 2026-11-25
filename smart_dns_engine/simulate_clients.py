import random
import socket
import string
import threading
import time
from security_gateway.packet_codec import parse_dns_query

SERVER_ADDR = ("127.0.0.1", 5300)

def build_query(domain: str) -> bytes:
    tx_id = random.randbytes(2)
    header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(p)]) + p.encode("utf-8") for p in domain.split(".")) + b"\x00"
    return header + qname + b"\x00\x01\x00\x01"


def parse_rcode(resp: bytes) -> int:
    return resp[3] & 0x0F if len(resp) >= 4 else -1


def normal_client_worker(name: str, duration_sec: float = 10.0) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    domains = ["github.com", "google.com", "python.org", "stackoverflow.com", "wikipedia.org"]
    ok_count, refused_count = 0, 0
    end_time = time.time() + duration_sec

    while time.time() < end_time:
        dom = random.choice(domains)
        try:
            sock.sendto(build_query(dom), SERVER_ADDR)
            resp, _ = sock.recvfrom(512)
            rcode = parse_rcode(resp)
            if rcode == 0:
                ok_count += 1
            elif rcode == 5:
                refused_count += 1
        except Exception:
            pass
        time.sleep(random.uniform(0.3, 0.7))

    sock.close()
    print(f"[{name}] Finished -> OK={ok_count}, REFUSED={refused_count}")


def attacker_client_worker(name: str, duration_sec: float = 10.0) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    ok_or_nx, refused_count = 0, 0
    end_time = time.time() + duration_sec

    while time.time() < end_time:
        rand_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        dga_domain = f"{rand_label}.com"
        try:
            sock.sendto(build_query(dga_domain), SERVER_ADDR)
            resp, _ = sock.recvfrom(512)
            rcode = parse_rcode(resp)
            if rcode == 5:
                refused_count += 1
            else:
                ok_or_nx += 1
        except Exception:
            pass
        time.sleep(0.03)  # ~33 req/s Flood + High-Entropy DGA

    sock.close()
    print(f"[{name}] Finished -> Passed={ok_or_nx}, REFUSED(Quarantined)={refused_count}")


if __name__ == "__main__":
    print("Starting multi-client simulation against 127.0.0.1:5353 ...\n")
    threads = [
        threading.Thread(target=normal_client_worker, args=("Normal_User_1", 10.0)),
        threading.Thread(target=normal_client_worker, args=("Normal_User_2", 10.0)),
        threading.Thread(target=attacker_client_worker, args=("Attacker_Bot", 10.0)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("\nSimulation complete! Check 'clients' and 'alerts' in dns_proxy CLI.")