"""Authorization scope for wireless security testing.

Attack functions in deauth.py must call require_authorized() before
transmitting anything. A target is authorized only if it is listed in
authorized_targets.json — networks you own or have WRITTEN permission
to test. There is no override flag: if it is not in the file, it does
not run.
"""
from __future__ import annotations

import json
import os

SCOPE_FILENAME = "authorized_targets.json"
EXAMPLE_FILENAME = "authorized_targets.example.json"


class AuthorizationError(PermissionError):
    """Raised when a wireless attack is attempted outside the authorized scope."""


def _candidate_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    # ~/.config wins over the working directory: a planted scope file in a
    # shared directory must not silently widen the authorization gate.
    return [
        os.path.join(os.path.expanduser("~"), ".config", "shibacuddles", SCOPE_FILENAME),
        os.path.join(os.getcwd(), SCOPE_FILENAME),
        os.path.join(here, SCOPE_FILENAME),
        os.path.join(os.path.dirname(here), SCOPE_FILENAME),
    ]


def scope_file_path():
    """Return the path of the scope file in use, or None if none exists."""
    for path in _candidate_paths():
        if os.path.isfile(path):
            return path
    return None


def load_scope():
    """Return the list of authorized network entries. Empty list if no scope file."""
    path = scope_file_path()
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:  # ValueError covers JSONDecodeError
        raise AuthorizationError(f"Scope file unreadable: {path}: {e}")
    networks = data.get("networks", []) if isinstance(data, dict) else []
    return [n for n in networks if isinstance(n, dict)]


def _norm_bssid(value):
    if not value:
        return ""
    return str(value).strip().lower().replace("-", ":")


def is_authorized(ssid=None, bssid=None):
    """True if the given SSID or BSSID is listed in the authorized scope file."""
    ssid = str(ssid).strip() if ssid else ""
    bssid = _norm_bssid(bssid)
    if not ssid and not bssid:
        return False
    for entry in load_scope():
        e_ssid = str(entry.get("ssid", "")).strip()
        e_bssid = _norm_bssid(entry.get("bssid", ""))
        if bssid and e_bssid and bssid == e_bssid:
            return True
        if ssid and e_ssid and ssid == e_ssid:
            return True
    return False


def require_authorized(ssid=None, bssid=None, action="wireless attack"):
    """Raise AuthorizationError unless the target is in the authorized scope."""
    if not is_authorized(ssid=ssid, bssid=bssid):
        target = bssid or ssid or "<unspecified>"
        in_effect = scope_file_path()
        where = (f"Scope file in effect: {in_effect}."
                 if in_effect else "No scope file found in any search location.")
        raise AuthorizationError(
            f"Refusing {action} against '{target}': not in authorized scope. {where} "
            f"Add the network to {SCOPE_FILENAME} (see {EXAMPLE_FILENAME}) — "
            "only networks you own or have written permission to test may be listed."
        )


def require_scope_configured(action="wireless attack"):
    """Raise unless at least one authorized network is configured.

    Used for indiscriminate actions (e.g. channel jamming) that cannot be
    scoped to a single target: the operator must have deliberately set up
    an authorization scope first.
    """
    if not load_scope():
        searched = ", ".join(_candidate_paths())
        raise AuthorizationError(
            f"Refusing {action}: no authorized scope configured. "
            f"Create {SCOPE_FILENAME} (see {EXAMPLE_FILENAME}) listing the networks "
            "you own or have written permission to test. "
            f"Searched: {searched}."
        )
