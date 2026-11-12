import os
import re

DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.?$")


def is_valid_domain(raw_input):
    """Check domain validity according to section 6.1."""
    if not raw_input:
        return False
    if " " in raw_input or "\t" in raw_input:
        return False
    if raw_input.startswith(".") or ".." in raw_input:
        return False
    if "*" in raw_input:
        return False
    return bool(DOMAIN_REGEX.match(raw_input))


def normalize_domain(domain):
    """Lowercase and remove a single trailing dot."""
    d = domain.strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def load_domain_list(filepath):
    """Load domain list file, print warning for invalid lines without stopping."""
    if not os.path.exists(filepath):
        raise ValueError(f"Config error: list file '{filepath}' not found.")

    domains = set()
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not is_valid_domain(stripped):
                print(f"Warning: bad line in {filepath}: {stripped}")
                continue
            domains.add(normalize_domain(stripped))
    return domains