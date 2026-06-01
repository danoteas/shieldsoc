"""
services/mitigation.py
"""

import subprocess
import shared_state as state


def _run_ipt(args: list[str]) -> bool:
    try:
        r = subprocess.run(
            ["sudo", "-n", "iptables"] + args,
            capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False


def block_ip_manual(ip: str) -> dict:
    if state.is_blocked(ip):
        return {"status": "already_blocked", "ip": ip}
    _run_ipt(["-A", "INPUT", "-s", ip, "-j", "DROP"])
    state.add_manual_block(ip)
    return {"status": "blocked", "ip": ip}


def unblock_ip_manual(ip: str) -> dict:
    _run_ipt(["-D", "INPUT", "-s", ip, "-j", "DROP"])
    state.remove_manual_block(ip)
    state.remove_auto_block(ip)
    return {"status": "unblocked", "ip": ip}


def get_blocked() -> list[str]:
    return state.all_blocked()
