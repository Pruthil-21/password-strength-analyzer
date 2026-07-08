"""
breach.py

Checks whether a password has appeared in known data breaches
using the Have I Been Pwned Pwned Passwords API.

Implements the k-Anonymity model: only the first 5 characters of the
password's SHA-1 hash are ever sent to the API. The full hash — and
therefore the password — never leaves this machine.
"""

import hashlib
import requests

from config import Config


def check_password_breach(password: str) -> dict:
    """
    Check if a password has been exposed in known breaches.

    Returns:
    {
        "breached": bool,
        "count": int
    }
    """

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:

        response = requests.get(
            Config.HIBP_API_URL + prefix,
            headers={"Add-Padding": "true"},
            timeout=Config.HIBP_REQUEST_TIMEOUT
        )

        response.raise_for_status()

    except requests.RequestException:

        return {
            "breached": False,
            "count": 0,
            "error": "Unable to connect to HIBP API."
        }

    hashes = response.text.splitlines()

    for line in hashes:

        hash_suffix, count = line.split(":")

        if hash_suffix == suffix:

            return {
                "breached": True,
                "count": int(count)
            }

    return {
        "breached": False,
        "count": 0
    }


if __name__ == "__main__":

    result = check_password_breach("password")

    print(result)