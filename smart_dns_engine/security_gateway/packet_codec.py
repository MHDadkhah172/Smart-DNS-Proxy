import socket
import struct


def parse_dns_query(packet: bytes):
    """
    Extracts (transaction_id, domain_name, qtype) from a raw DNS UDP packet.
    Returns (None, None, None) if the packet is malformed.
    """
    if len(packet) < 12:
        return None, None, None

    tx_id = packet[:2]
    idx = 12
    labels = []
    max_len = len(packet)

    while idx < max_len:
        length = packet[idx]
        if length == 0:
            idx += 1
            break
        # Reject compressed pointers in question section for safety
        if (length & 0xC0) == 0xC0:
            return None, None, None
        idx += 1
        if idx + length > max_len:
            return None, None, None
        labels.append(packet[idx:idx + length].decode("ascii", errors="ignore"))
        idx += length

    if idx + 4 > max_len or not labels:
        return None, None, None

    domain = ".".join(labels).lower()
    qtype, _ = struct.unpack("!HH", packet[idx:idx + 4])
    return tx_id, domain, qtype


def build_dns_response(query_packet: bytes, ip_address: str = None, rcode: int = 0, ttl: int = 60) -> bytes:
    """
    Builds a standard DNS binary response echoing the client's Question section.
    rcode: 0 = NOERROR (with IP), 3 = NXDOMAIN (not found), 5 = REFUSED (quarantined)
    """
    if len(query_packet) < 12:
        return b""

    tx_id = query_packet[:2]
    # Preserve Recursion Desired (RD) bit, set QR=1 (Response) and RA=1 (Recursion Available)
    rd_bit = query_packet[2] & 0x01
    flags_hi = 0x80 | rd_bit
    flags_lo = 0x80 | (rcode & 0x0F)

    # Locate end of Question section
    idx = 12
    while idx < len(query_packet) and query_packet[idx] != 0:
        idx += 1 + query_packet[idx]
    q_end = min(idx + 5, len(query_packet))
    question_section = query_packet[12:q_end]

    if rcode == 0 and ip_address:
        header = struct.pack("!2sBBHHHH", tx_id, flags_hi, flags_lo, 1, 1, 0, 0)
        # Pointer to domain name at offset 12 (0xC00C), Type A (1), Class IN (1), TTL, RDLength (4)
        answer = struct.pack("!HHHLH", 0xC00C, 1, 1, ttl, 4) + socket.inet_aton(ip_address)
        return header + question_section + answer

    # Error or Refused response (0 Answer records)
    header = struct.pack("!2sBBHHHH", tx_id, flags_hi, flags_lo, 1, 0, 0, 0)
    return header + question_section