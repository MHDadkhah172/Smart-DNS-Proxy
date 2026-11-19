import os
import re

DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.?$")


def resolve_path(filename):
    """Find file in current directory or parent directory (project root)."""
    if os.path.exists(filename):
        return filename
    parent_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", filename)
    if os.path.exists(parent_path):
        return os.path.normpath(parent_path)
    return filename


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
    resolved_filepath = resolve_path(filepath)
    if not os.path.exists(resolved_filepath):
        raise ValueError(f"Config error: list file '{filepath}' not found.")

    domains = set()
    with open(resolved_filepath, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not is_valid_domain(stripped):
                print(f"Warning: bad line in {filepath}: {stripped}")
                continue
            domains.add(normalize_domain(stripped))
    return domains