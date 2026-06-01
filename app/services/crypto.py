import hashlib
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")


def generate_nonce(target_url: str) -> str:
    """Generate a SHA256 nonce from timestamp + SECRET_KEY + target_url."""
    timestamp = datetime.now(timezone.utc).isoformat()
    data = f"{timestamp}{SECRET_KEY}{target_url}"
    return hashlib.sha256(data.encode()).hexdigest()
