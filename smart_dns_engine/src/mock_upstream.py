import socket


def start_mock_upstream(host="127.0.0.1", port=5354):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"Mock Upstream listening on {host}:{port}...")

    request_counter = 0

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            msg = data.decode("utf-8", errors="ignore").strip()

            if msg.startswith("QUERY "):
                domain = msg[6:].strip()
                request_counter += 1

                if domain == "missing.example.net":
                    reply = "NOT_FOUND"
                else:
                    reply = "OK 198.51.100.7 5"

                print(f"Request #{request_counter}: {domain} -> {reply}")
                sock.sendto(reply.encode("utf-8"), addr)
    except KeyboardInterrupt:
        print("\nMock Upstream stopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    start_mock_upstream()