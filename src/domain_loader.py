import os
import sys

def normalize_domain(domain_str):
    """
    Normalize domain name:
    - Strip whitespace
    - Convert to lowercase
    - Remove trailing dot if present
    """
    domain = domain_str.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    return domain

def is_valid_domain(domain_str):
    """
    Basic sanity check for domain name:
    - Must not be empty
    - Must not contain spaces
    - Total length must not exceed 253 characters
    """
    if not domain_str:
        return False
    if " " in domain_str:
        return False
    if len(domain_str) > 253:
        return False
    return True

def load_domain_list(file_path):
    """
    Read, normalize, and load unique domains from a text file into a set.
    """
    domains = set()

    if not os.path.isfile(file_path):
        print(f"Domain loader error: File '{file_path}' not found.")
        sys.exit(1)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                normalized = normalize_domain(line)
                if is_valid_domain(normalized):
                    domains.add(normalized)

    except Exception as e:
        print(f"Domain loader error: Failed to read '{file_path}'. {e}")
        sys.exit(1)

    return domains