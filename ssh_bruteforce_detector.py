#!/usr/bin/env python3
"""Deteksi SSH brute force dari file log.

Fungsi utama:
- membaca log SSH (/var/log/auth.log atau file lain)
- menangkap IP yang gagal login berulang
- memeriksa apakah lebih dari 5 kali dalam 60 detik
- mencetak peringatan ke layar beserta IP penyerang
"""

import argparse
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Regex umum untuk log SSH yang gagal login
# Contoh:
# Sep 10 10:15:01 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2
# Sep 10 10:15:02 server sshd[1234]: Invalid user admin from 10.0.0.5 port 22
# Sep 10 10:15:03 server sshd[1234]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.67.89.12
LOG_PATTERN = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*?"
    r"(?:Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})|"
    r"Invalid user (?P<invalid_user>\S+) from (?P<invalid_ip>\d{1,3}(?:\.\d{1,3}){3})|"
    r"authentication failure.*rhost=(?P<auth_ip>\d{1,3}(?:\.\d{1,3}){3}))"
)


def parse_log_timestamp(raw_ts: str) -> datetime:
    """Mengubah format 'Sep 10 10:15:01' menjadi datetime."""
    current_year = datetime.now().year
    return datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S")


def valid_ip(ip: str) -> bool:
    """Memvalidasi format IPv4."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False
    return True


def detect_bruteforce(log_path: str, threshold: int = 5, window_seconds: int = 60):
    """Menganalisis log SSH dan mendeteksi brute force.

    Jika satu IP gagal login lebih dari threshold kali dalam window_seconds,
    maka tampilkan alert ke layar.
    """
    failed_attempts = defaultdict(deque)  # ip -> deque of datetime
    alerted_ips = set()

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                match = LOG_PATTERN.search(line)
                if not match:
                    continue

                ip = None
                if match.group("ip"):
                    ip = match.group("ip")
                elif match.group("invalid_ip"):
                    ip = match.group("invalid_ip")
                elif match.group("auth_ip"):
                    ip = match.group("auth_ip")

                if not ip or not valid_ip(ip):
                    continue

                event_time = parse_log_timestamp(match.group("ts"))
                attempts = failed_attempts[ip]
                attempts.append(event_time)

                # Hapus entry yang lebih lama dari jendela waktu
                cutoff = event_time - timedelta(seconds=window_seconds)
                while attempts and attempts[0] < cutoff:
                    attempts.popleft()

                if len(attempts) > threshold and ip not in alerted_ips:
                    print(
                        f"[ALERT] Brute Force Detected! IP {ip} gagal login {len(attempts)} kali "
                        f"dalam {window_seconds} detik."
                    )
                    alerted_ips.add(ip)

                # Jika jumlah gagal turun kembali di bawah ambang, kita bisa reset alert
                if len(attempts) <= threshold and ip in alerted_ips:
                    alerted_ips.remove(ip)

    except FileNotFoundError:
        print(f"[ERROR] File log tidak ditemukan: {log_path}", file=sys.stderr)
        sys.exit(1)

    print("[INFO] Analisis log selesai.")


def main():
    parser = argparse.ArgumentParser(description="Deteksi brute force pada log SSH")
    parser.add_argument("log_path", help="Lokasi file log SSH (contoh: /var/log/auth.log)")
    parser.add_argument("--threshold", type=int, default=5, help="Batas jumlah gagal login (default: 5)")
    parser.add_argument("--window", type=int, default=60, help="Jendela waktu dalam detik (default: 60)")
    args = parser.parse_args()

    detect_bruteforce(args.log_path, threshold=args.threshold, window_seconds=args.window)


if __name__ == "__main__":
    main()
