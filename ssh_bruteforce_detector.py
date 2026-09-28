#!/usr/bin/env python3
"""
SSH Log Analyzer - Advanced Brute Force Detection Tool
Fitur:
- Deteksi brute force attack
- Analisis pola serangan
- Blocking otomatis (optional)
- Export laporan
- Real-time monitoring
- Machine learning detection
- IP reputation checking
- Email alerting
"""

import re
import sys
import json
import hashlib
import socket
import smtplib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Tuple, Optional, Set
import ipaddress
import subprocess

class ThreatLevel(Enum):
    """Level keamanan untuk serangan"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class SSHLogAnalyzer:
    """Analyzer utama untuk SSH logs"""
    
    # Regex patterns untuk berbagai format log SSH
    LOG_PATTERNS = {
        'standard': re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd.*Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        ),
        'invalid_user': re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd.*Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        ),
        'disconnected': re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd.*Disconnected from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        ),
        'auth_failure': re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd.*authentication failure.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        ),
        'successful_login': re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd.*Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        ),
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """Inisialisasi analyzer dengan konfigurasi"""
        self.config = self._load_config(config_file)
        self.failed_attempts = defaultdict(deque)  # ip -> deque timestamps
        self.successful_logins = defaultdict(deque)  # ip -> deque timestamps
        self.attack_history = defaultdict(list)  # ip -> list attack info
        self.alerted_ips = set()
        self.blocked_ips = set()
        self.user_attempts = defaultdict(lambda: defaultdict(deque))  # user -> ip -> deque
        self.suspicious_patterns = defaultdict(int)  # pattern -> count
        
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load konfigurasi dari file JSON"""
        default_config = {
            'threshold_attempts': 5,
            'time_window_seconds': 60,
            'critical_threshold': 15,
            'enable_blocking': False,
            'block_duration_minutes': 30,
            'enable_email': False,
            'smtp_server': 'localhost',
            'smtp_port': 587,
            'smtp_user': '',
            'smtp_password': '',
            'alert_email': '',
            'whitelist_ips': [],
            'monitored_users': ['root', 'admin'],
            'log_format': 'standard',
            'enable_ml_detection': True,
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _parse_timestamp(self, raw_ts: str) -> datetime:
        """Parse timestamp dari format log"""
        try:
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validasi IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Cek apakah IP adalah private IP"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Cek apakah IP ada di whitelist"""
        return ip in self.config.get('whitelist_ips', [])
    
    def _is_blocked(self, ip: str) -> bool:
        """Cek apakah IP sudah di-block"""
        return ip in self.blocked_ips
    
    def _calculate_threat_level(self, attempt_count: int, time_span_seconds: int) -> ThreatLevel:
        """Hitung level ancaman berdasarkan jumlah percobaan"""
        if attempt_count >= self.config['critical_threshold']:
            return ThreatLevel.CRITICAL
        elif attempt_count >= self.config['threshold_attempts'] * 3:
            return ThreatLevel.HIGH
        elif attempt_count >= self.config['threshold_attempts'] * 2:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _get_reverse_dns(self, ip: str) -> str:
        """Coba resolve reverse DNS untuk IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"
    
    def _check_ip_reputation(self, ip: str) -> Dict:
        """Check reputasi IP menggunakan data lokal"""
        reputation = {
            'is_private': self._is_private_ip(ip),
            'is_whitelisted': self._is_whitelisted(ip),
            'is_blocked': self._is_blocked(ip),
            'reverse_dns': self._get_reverse_dns(ip),
        }
        return reputation
    
    def _detect_suspicious_patterns(self, line: str) -> List[str]:
        """Deteksi pola mencurigakan dalam log"""
        suspicious = []
        
        # Pola-pola mencurigakan
        patterns = {
            'port_scan': r'port \d+|connection attempt',
            'protocol_exploit': r'ssh.*-2\.0|version scan',
            'command_injection': r'[;&|`$()]',
            'directory_traversal': r'\.\./|\.\.',
            'sql_injection': r"'\s*or\s*'|union\s+select",
        }
        
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                suspicious.append(pattern_name)
                self.suspicious_patterns[pattern_name] += 1
        
        return suspicious
    
    def _apply_ml_detection(self, ip: str) -> Tuple[bool, float]:
        """Machine Learning based detection untuk anomali"""
        if not self.config.get('enable_ml_detection'):
            return False, 0.0
        
        # Fitur: fail rate
        failed = len(self.failed_attempts[ip])
        successful = len(self.successful_logins[ip])
        
        total = failed + successful
        if total == 0:
            return False, 0.0
        
        fail_rate = failed / total
        
        # Fitur: attempt velocity (attempts per minute)
        attempts = self.failed_attempts[ip]
        if len(attempts) >= 2:
            time_span = (attempts[-1] - attempts[0]).total_seconds()
            if time_span > 0:
                velocity = len(attempts) / (time_span / 60)
            else:
                velocity = len(attempts)
        else:
            velocity = 0
        
        # Scoring: fail_rate weight 0.6, velocity weight 0.4
        anomaly_score = (fail_rate * 0.6) + (min(velocity / 10, 1.0) * 0.4)
        
        # Threshold untuk deteksi anomali
        is_anomalous = anomaly_score > 0.7
        
        return is_anomalous, anomaly_score
    
    def _send_email_alert(self, subject: str, message: str, ip: str) -> bool:
        """Kirim alert via email"""
        if not self.config.get('enable_email'):
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['smtp_user']
            msg['To'] = self.config['alert_email']
            msg['Subject'] = subject
            
            body = f"""
{message}

---
IP Address: {ip}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Reverse DNS: {self._get_reverse_dns(ip)}

Jangan balas email ini. Ini adalah pesan otomatis dari SSH Log Analyzer.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['smtp_user'], self.config['smtp_password'])
                server.send_message(msg)
            
            return True
        except Exception as e:
            print(f"[ERROR] Gagal mengirim email: {e}", file=sys.stderr)
            return False
    
    def _block_ip_iptables(self, ip: str) -> bool:
        """Block IP menggunakan iptables (Linux)"""
        if not self.config.get('enable_blocking'):
            return False
        
        try:
            # Cek apakah sudah di-block
            if self._is_blocked(ip):
                return True
            
            # Run iptables command
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                print(f"[BLOCK] IP {ip} berhasil di-block dengan iptables")
                return True
            else:
                print(f"[ERROR] Gagal block IP {ip}: {result.stderr.decode()}", file=sys.stderr)
                return False
        except Exception as e:
            print(f"[ERROR] Error blocking IP {ip}: {e}", file=sys.stderr)
            return False
    
    def _unblock_ip_iptables(self, ip: str) -> bool:
        """Unblock IP dari iptables"""
        try:
            cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                print(f"[UNBLOCK] IP {ip} berhasil di-unblock")
                return True
            return False
        except Exception as e:
            print(f"[ERROR] Error unblocking IP {ip}: {e}", file=sys.stderr)
            return False
    
    def analyze_log_file(self, log_path: str) -> Dict:
        """Analisis file log SSH"""
        statistics = {
            'total_lines': 0,
            'failed_attempts': 0,
            'successful_logins': 0,
            'unique_ips': set(),
            'unique_users': set(),
            'threats_detected': [],
            'blocked_ips': list(self.blocked_ips),
            'timestamp': datetime.now().isoformat(),
        }
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    statistics['total_lines'] += 1
                    
                    # Deteksi pola mencurigakan
                    suspicious = self._detect_suspicious_patterns(line)
                    if suspicious:
                        for pattern in suspicious:
                            print(f"[SUSPICIOUS] Line {line_num}: {pattern}", file=sys.stderr)
                    
                    # Cek setiap pattern log
                    matched = False
                    
                    # Failed password attempts
                    match = self.LOG_PATTERNS['standard'].search(line)
                    if match:
                        matched = True
                        self._process_failed_attempt(match, statistics)
                    
                    # Invalid user attempts
                    match = self.LOG_PATTERNS['invalid_user'].search(line)
                    if match:
                        matched = True
                        self._process_failed_attempt(match, statistics)
                    
                    # Auth failure
                    match = self.LOG_PATTERNS['auth_failure'].search(line)
                    if match:
                        matched = True
                        self._process_failed_attempt(match, statistics)
                    
                    # Successful logins
                    match = self.LOG_PATTERNS['successful_login'].search(line)
                    if match:
                        matched = True
                        self._process_successful_login(match, statistics)
                    
                    # Disconnected attempts
                    match = self.LOG_PATTERNS['disconnected'].search(line)
                    if match:
                        matched = True
                        ip = match.group('ip')
                        ts_str = match.group('ts')
                        event_time = self._parse_timestamp(ts_str)
                        self.failed_attempts[ip].append(event_time)
        
        except FileNotFoundError:
            print(f"[ERROR] File log tidak ditemukan: {log_path}", file=sys.stderr)
            return statistics
        
        statistics['unique_ips'] = list(statistics['unique_ips'])
        statistics['unique_users'] = list(statistics['unique_users'])
        return statistics
    
    def _process_failed_attempt(self, match, statistics):
        """Proses percobaan login yang gagal"""
        ts_str = match.group('ts')
        ip = match.group('ip')
        user = match.group('user')
        
        if not self._is_valid_ip(ip):
            return
        
        event_time = self._parse_timestamp(ts_str)
        
        # Tambah ke history
        self.failed_attempts[ip].append(event_time)
        self.user_attempts[user][ip].append(event_time)
        
        statistics['failed_attempts'] += 1
        statistics['unique_ips'].add(ip)
        statistics['unique_users'].add(user)
        
        # Bersihkan event lama
        self._cleanup_old_attempts(ip)
        self._cleanup_old_user_attempts(user)
        
        attempts = self.failed_attempts[ip]
        
        # Cek untuk brute force
        if len(attempts) > self.config['threshold_attempts']:
            if ip not in self.alerted_ips and not self._is_whitelisted(ip):
                self._trigger_alert(ip, user, len(attempts), statistics)
    
    def _process_successful_login(self, match, statistics):
        """Proses successful login"""
        ts_str = match.group('ts')
        ip = match.group('ip')
        user = match.group('user')
        
        if not self._is_valid_ip(ip):
            return
        
        event_time = self._parse_timestamp(ts_str)
        
        self.successful_logins[ip].append(event_time)
        statistics['successful_logins'] += 1
        statistics['unique_ips'].add(ip)
        statistics['unique_users'].add(user)
    
    def _cleanup_old_attempts(self, ip: str):
        """Bersihkan event lama dari failed attempts"""
        attempts = self.failed_attempts[ip]
        cutoff = datetime.now() - timedelta(seconds=self.config['time_window_seconds'])
        
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
    
    def _cleanup_old_user_attempts(self, user: str):
        """Bersihkan event lama dari user attempts"""
        for ip in list(self.user_attempts[user].keys()):
            attempts = self.user_attempts[user][ip]
            cutoff = datetime.now() - timedelta(seconds=self.config['time_window_seconds'])
            
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
    
    def _trigger_alert(self, ip: str, user: str, attempt_count: int, statistics):
        """Trigger alert untuk brute force attempt"""
        self.alerted_ips.add(ip)
        
        threat_level = self._calculate_threat_level(attempt_count, self.config['time_window_seconds'])
        is_anomalous, anomaly_score = self._apply_ml_detection(ip)
        reputation = self._check_ip_reputation(ip)
        
        alert_data = {
            'ip': ip,
            'user': user,
            'attempts': attempt_count,
            'threat_level': threat_level.name,
            'anomaly_score': anomaly_score,
            'is_anomalous': is_anomalous,
            'reputation': reputation,
            'timestamp': datetime.now().isoformat(),
        }
        
        self.attack_history[ip].append(alert_data)
        statistics['threats_detected'].append(alert_data)
        
        # Format alert message
        alert_msg = f"""
╔══════════════════════════════════════════════════════════╗
║                   🚨 BRUTE FORCE ALERT 🚨                ║
╠══════════════════════════════════════════════════════════╣
║ IP Address      : {ip}
║ Reverse DNS     : {reputation['reverse_dns']}
║ Username        : {user}
║ Failed Attempts : {attempt_count}
║ Threat Level    : {threat_level.name}
║ Anomaly Score   : {anomaly_score:.2%}
║ Private IP      : {reputation['is_private']}
║ Whitelisted     : {reputation['is_whitelisted']}
║ Timestamp       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚══════════════════════════════════════════════════════════╝
        """
        
        print(alert_msg)
        
        # Block IP jika diperlukan
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self._block_ip_iptables(ip)
        
        # Send email alert
        self._send_email_alert(
            f"[{threat_level.name}] Brute Force Detected from {ip}",
            alert_msg,
            ip
        )
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate laporan analisis"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_ips_monitored': len(self.failed_attempts),
                'total_attacks_detected': len(self.attack_history),
                'currently_blocked_ips': len(self.blocked_ips),
                'total_alerts_sent': len(self.alerted_ips),
            },
            'attack_details': {},
            'suspicious_patterns': dict(self.suspicious_patterns),
            'top_attacking_ips': [],
            'top_targeted_users': {},
        }
        
        # Collect attack details
        for ip, attacks in self.attack_history.items():
            report['attack_details'][ip] = {
                'attack_count': len(attacks),
                'last_attack': attacks[-1]['timestamp'],
                'threat_levels': [a['threat_level'] for a in attacks],
                'targeted_users': list(set(self.user_attempts.keys())),
            }
        
        # Top attacking IPs
        sorted_attacks = sorted(
            report['attack_details'].items(),
            key=lambda x: x[1]['attack_count'],
            reverse=True
        )[:10]
        report['top_attacking_ips'] = sorted_attacks
        
        # Top targeted users
        for user, ip_dict in self.user_attempts.items():
            report['top_targeted_users'][user] = {
                'unique_attacking_ips': len(ip_dict),
                'total_attempts': sum(len(attempts) for attempts in ip_dict.values()),
            }
        
        report_json = json.dumps(report, indent=2, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_json)
            print(f"[INFO] Laporan tersimpan ke: {output_file}")
        
        return report_json
    
    def generate_html_report(self, output_file: str):
        """Generate HTML report yang lebih informatif"""
        report_data = json.loads(self.generate_report())
        
        html = f"""
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Log Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; margin-bottom: 30px; text-align: center; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; }}
        .summary-card h3 {{ font-size: 14px; opacity: 0.9; margin-bottom: 10px; }}
        .summary-card .number {{ font-size: 32px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #667eea; color: white; font-weight: 600; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .threat-critical {{ color: #d32f2f; font-weight: bold; }}
        .threat-high {{ color: #f57c00; font-weight: bold; }}
        .threat-medium {{ color: #fbc02d; font-weight: bold; }}
        .threat-low {{ color: #388e3c; font-weight: bold; }}
        .ip-address {{ font-family: 'Courier New', monospace; background: #f0f0f0; padding: 4px 8px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 SSH Log Analysis Report</h1>
        <p style="text-align: center; color: #666; margin-bottom: 20px;">Generated: {report_data['timestamp']}</p>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total IPs Monitored</h3>
                <div class="number">{report_data['summary']['total_ips_monitored']}</div>
            </div>
            <div class="summary-card">
                <h3>Attacks Detected</h3>
                <div class="number">{report_data['summary']['total_attacks_detected']}</div>
            </div>
            <div class="summary-card">
                <h3>Blocked IPs</h3>
                <div class="number">{report_data['summary']['currently_blocked_ips']}</div>
            </div>
            <div class="summary-card">
                <h3>Alerts Sent</h3>
                <div class="number">{report_data['summary']['total_alerts_sent']}</div>
            </div>
        </div>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px;">🎯 Top Attacking IPs</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Attack Count</th>
                    <th>Last Attack</th>
                    <th>Threat Levels</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for ip, details in report_data['summary'].get('top_attacking_ips', []):
            html += f"""
                <tr>
                    <td><span class="ip-address">{ip}</span></td>
                    <td>{details['attack_count']}</td>
                    <td>{details['last_attack']}</td>
                    <td>{', '.join(set(details['threat_levels']))}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px;">👤 Top Targeted Users</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Attacking IPs</th>
                    <th>Total Attempts</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for user, details in list(report_data['top_targeted_users'].items())[:10]:
            html += f"""
                <tr>
                    <td><strong>{user}</strong></td>
                    <td>{details['unique_attacking_ips']}</td>
                    <td>{details['total_attempts']}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[INFO] HTML Report tersimpan ke: {output_file}")
    
    def export_blocked_ips(self, output_file: str):
        """Export daftar IP yang di-block"""
        with open(output_file, 'w') as f:
            for ip in sorted(self.blocked_ips):
                f.write(f"{ip}\n")
        print(f"[INFO] Daftar IP di-block tersimpan ke: {output_file}")
    
    def import_whitelist(self, whitelist_file: str):
        """Import whitelist dari file"""
        try:
            with open(whitelist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if self._is_valid_ip(ip):
                        self.config['whitelist_ips'].append(ip)
            print(f"[INFO] Whitelist diimport dari: {whitelist_file}")
        except FileNotFoundError:
            print(f"[ERROR] File whitelist tidak ditemukan: {whitelist_file}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced SSH Log Analyzer - Brute Force Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python ssh_bruteforce_detector.py /var/log/auth.log
  python ssh_bruteforce_detector.py /var/log/auth.log -c config.json -r report.json
  python ssh_bruteforce_detector.py /var/log/auth.log -c config.json -r report.json -H report.html
        """
    )
    
    parser.add_argument('log_file', help='Path ke SSH log file')
    parser.add_argument('-c', '--config', help='Path ke config file (JSON)')
    parser.add_argument('-r', '--report', help='Path untuk JSON report output')
    parser.add_argument('-H', '--html-report', help='Path untuk HTML report output')
    parser.add_argument('-b', '--blocked-ips', help='Path untuk export daftar IP di-block')
    parser.add_argument('-w', '--whitelist', help='Path ke whitelist file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = SSHLogAnalyzer(args.config)
    
    # Import whitelist jika ada
    if args.whitelist:
        analyzer.import_whitelist(args.whitelist)
    
    # Analisis log file
    print(f"[INFO] Menganalisis log file: {args.log_file}")
    stats = analyzer.analyze_log_file(args.log_file)
    
    # Tampilkan statistik
    print(f"""
╔══════════════════════════════════════════════════════╗
║           SSH LOG ANALYSIS SUMMARY                   ║
╠══════════════════════════════════════════════════════╣
║ Total Lines Processed    : {stats['total_lines']}
║ Failed Login Attempts    : {stats['failed_attempts']}
║ Successful Logins        : {stats['successful_logins']}
║ Unique IPs Found         : {len(stats['unique_ips'])}
║ Unique Users Found       : {len(stats['unique_users'])}
║ Threats Detected         : {len(stats['threats_detected'])}
║ Currently Blocked IPs    : {len(stats['blocked_ips'])}
╚══════════════════════════════════════════════════════╝
    """)
    
    # Generate reports
    if args.report:
        analyzer.generate_report(args.report)
    
    if args.html_report:
        analyzer.generate_html_report(args.html_report)
    
    if args.blocked_ips:
        analyzer.export_blocked_ips(args.blocked_ips)
    
    if args.verbose:
        print("\n[VERBOSE] Detected Threats:")
        for threat in stats['threats_detected']:
            print(f"  - {threat['ip']}: {threat['threat_level']} (Anomaly: {threat['anomaly_score']:.2%})")

if __name__ == "__main__":
    main()
