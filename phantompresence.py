#!/usr/bin/env python3
"""
PhantomPresence v2.0 -  Deception System
Generates realistic fake system activity to confuse attackers and simulate user behavior
For educational/defensive purposes
Author : Mikhiel Miller
"""

import random
import time
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict,  Any
import uuid
import hashlib
from dataclasses import dataclass



# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Configuration for PhantomPresence"""
    log_file: str = "phantom_presence.log"
    syslog_server: str = "127.0.0.1:514"  # Optional syslog forwarding
    simulation_mode: str = "enterprise"  # Options: enterprise, developer, admin, mixed
    intensity: float = 0.7  # 0.1 to 1.0 (how frequently events occur)
    include_weekends: bool = True
    business_hours_only: bool = False
    timezone: str = "local"
    generate_fake_files: bool = True
    fake_file_directory: str = "./honey_files/"
    rotate_logs: bool = True
    max_log_size_mb: int = 10


config = Config()

# ============================================================================
# DATA LIBRARIES
# ============================================================================

# Realistic user personas with different behavior patterns
PERSONAS = {
    "developer": {
        "users": ["j.miller", "k.thomas", "s.roberts", "a.green", "d.morgan"],
        "processes": ["vscode.exe", "git.exe", "docker.exe", "node.exe", "python.exe", "postman.exe"],
        "files": ["backend_api.py", "database_schema.sql", "config.env", "docker-compose.yml"],
        "servers": ["gitlab.company.com", "jenkins.internal", "docker-registry.local"]
    },
    "sysadmin": {
        "users": ["admin_jackson", "root_sys", "netadmin_lee"],
        "processes": ["powershell.exe", "ssh.exe", "ansible.exe", "terraform.exe", "nmap.exe"],
        "files": ["firewall_rules.txt", "backup_script.ps1", "server_inventory.csv"],
        "servers": ["dc1.company.com", "vcenter.internal", "splunk.company.com"]
    },
    "executive": {
        "users": ["ceo_smith", "cfo_jones", "cio_wilson"],
        "processes": ["outlook.exe", "teams.exe", "excel.exe", "zoom.exe"],
        "files": ["q4_earnings.xlsx", "board_presentation.pptx", "merger_plan.docx"],
        "servers": ["sharepoint.company.com", "salesforce.com", "workday.com"]
    }
}

# Expanded data sets
PROCESSES = [
    "ChromeHelper_32.exe", "UpdaterTaskHost.exe", "TeamsSyncWorker.exe",
    "WinDefendScanner.exe", "msedge_autoservice.exe", "svchost.exe",
    "explorer.exe", "System", "RuntimeBroker.exe", "SearchIndexer.exe",
    "spoolsv.exe", "WmiPrvSE.exe", "dwm.exe", "csrss.exe", "lsass.exe"
]

DOMAINS = [
    "update.microsoft.com", "clients2.google.com", "teams.live.com",
    "time.windows.com", "oca.telemetry.microsoft.com", "ctldl.windowsupdate.com",
    "software-download.microsoft.com", "events.data.microsoft.com"
]

INTERNAL_SERVERS = [
    "dc01.corp.local", "fileserver01", "exchange01", "sql01", "vcenter01",
    "backup01", "monitoring01", "git01", "jenkins01", "docker01"
]

HONEY_CREDS = [
    {"username": "backup_admin", "password": "Summer2024!", "domain": "CORP"},
    {"username": "sql_service", "password": "P@ssw0rd123", "domain": "CORP"},
    {"username": "vpn_user", "password": "VPNaccess!2024", "domain": "CORP"},
    {"username": "administrator", "password": "Changeme123!", "domain": "WORKGROUP"}
]


# ============================================================================
# EVENT GENERATORS
# ============================================================================

class EventGenerator:
    """Base class for all event generators"""

    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.event_count = 0

    def generate_id(self) -> str:
        """Generate unique event ID"""
        self.event_count += 1
        return f"EVT-{self.session_id[:8]}-{self.event_count:06d}"

    def get_timestamp(self, random_offset_minutes: int = 120) -> str:
        """Get timestamp with optional random offset"""
        if random_offset_minutes > 0:
            offset = random.randint(-random_offset_minutes, random_offset_minutes)
            ts = datetime.now() + timedelta(minutes=offset)
        else:
            ts = datetime.now()
        return ts.isoformat()


class AuthenticationGenerator(EventGenerator):
    """Generate fake authentication events"""

    def login_event(self, success: bool = None) -> Dict[str, Any]:
        """Generate login event"""
        if success is None:
            success = random.random() > 0.1  # 90% success rate

        persona = random.choice(list(PERSONAS.keys()))
        user = random.choice(PERSONAS[persona]["users"])

        event = {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "authentication",
            "sub_type": "login",
            "user": user,
            "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(10, 200)}",
            "destination": random.choice(INTERNAL_SERVERS),
            "success": success,
            "auth_method": random.choice(["password", "smartcard", "kerberos"]),
            "session_id": str(uuid.uuid4()),
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Microsoft Office/16.0",
                "RDP Client"
            ])
        }

        if not success:
            event["failure_reason"] = random.choice([
                "Invalid credentials",
                "Account locked",
                "Password expired",
                "Smartcard not found"
            ])

        return event

    def logout_event(self) -> Dict[str, Any]:
        """Generate logout event"""
        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "authentication",
            "sub_type": "logout",
            "user": random.choice(PERSONAS["developer"]["users"]),
            "session_duration": random.randint(300, 28800),  # 5 min to 8 hours
            "bytes_transferred": random.randint(1024, 104857600)  # 1KB to 100MB
        }


class ProcessGenerator(EventGenerator):
    """Generate fake process events"""

    def process_start(self) -> Dict[str, Any]:
        """Generate process start event"""
        persona = random.choice(list(PERSONAS.keys()))

        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "process",
            "sub_type": "start",
            "process_name": random.choice(PERSONAS[persona]["processes"]),
            "pid": random.randint(1000, 9999),
            "parent_pid": random.randint(1, 999),
            "user": random.choice(PERSONAS[persona]["users"]),
            "command_line": self._generate_command_line(),
            "working_directory": random.choice([
                r"C:\Users\j.miller\Documents",
                r"C:\Program Files\Microsoft VS Code",
                r"D:\Projects\backend",
                "/home/jmiller/projects"
            ])
        }

    def process_end(self) -> Dict[str, Any]:
        """Generate process end event"""
        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "process",
            "sub_type": "end",
            "process_name": random.choice(PROCESSES),
            "pid": random.randint(1000, 9999),
            "exit_code": random.choice([0, 0, 0, 1, -1]),  # Mostly success
            "cpu_time": random.randint(1, 300),
            "peak_memory": random.randint(1024, 1048576)  # 1KB to 1GB
        }

    def _generate_command_line(self) -> str:
        """Generate realistic command line"""
        templates = [
            r'"C:\Program Files\Microsoft VS Code\Code.exe" --file-uri file:///D:/Projects/api/main.py',
            'git pull origin develop',
            'docker-compose up --build',
            'python -m pytest tests/ --verbose',
            'powershell.exe -ExecutionPolicy Bypass -File deploy.ps1',
            'ssh admin@server01 "systemctl restart nginx"'
        ]
        return random.choice(templates)


class FileSystemGenerator(EventGenerator):
    """Generate fake file system events"""

    def __init__(self):
        super().__init__()
        self.fake_files_created = []

    def file_access(self) -> Dict[str, Any]:
        """Generate file access event"""
        persona = random.choice(list(PERSONAS.keys()))
        operation = random.choice(["read", "write", "modify", "delete"])

        # Generate fake file names that look enticing
        fake_files = [
            "passwords_backup_2024.txt",
            "salary_details_q4.xlsx",
            "vpn_configuration.conf",
            "ssh_private_key.ppk",
            "database_backup.sql",
            "employee_records.csv",
            "merger_confidential.docx",
            "bank_accounts.xlsx"
        ]

        event = {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "filesystem",
            "sub_type": operation,
            "filename": random.choice(fake_files),
            "user": random.choice(PERSONAS[persona]["users"]),
            "path": random.choice([
                r"C:\Users\j.miller\Documents\Confidential",
                r"\\fileserver01\finance\reports",
                r"/home/jmiller/secret",
                r"D:\Backup\""
            ]),
            "size": random.randint(1024, 10485760),  # 1KB to 10MB
            "hash": hashlib.md5(os.urandom(16)).hexdigest()
        }

        return event

    def create_honey_file(self) -> Dict[str, Any]:
        """Generate honey file creation event"""
        honey_names = [
            "credentials.txt",
            "passwords.xlsx",
            "backup_passwords.7z",
            "ssh_keys.tar.gz",
            "database_dump.sql",
            "config_with_secrets.env"
        ]

        filename = random.choice(honey_names)
        self.fake_files_created.append(filename)

        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "honey_file",
            "filename": filename,
            "path": f"{config.fake_file_directory}{filename}",
            "enticement_level": random.choice(["low", "medium", "high", "critical"]),
            "content_type": random.choice(["credentials", "config", "backup", "keys"]),
            "fake_content": self._generate_fake_content()
        }

    def _generate_fake_content(self) -> str:
        """Generate fake enticing content"""
        templates = [
            "username: admin\npassword: P@ssw0rd123!\n\nDB_HOST=192.168.1.100\nDB_PASS=Secret123",
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            "vpn_user:pass123\nadmin:admin123\nroot:toor",
            "Server: prod-db01\nPort: 5432\nUsername: postgres\nPassword: postgres123"
        ]
        return random.choice(templates)


class NetworkGenerator(EventGenerator):
    """Generate fake network events"""

    def dns_query(self) -> Dict[str, Any]:
        """Generate DNS query event"""
        query_type = random.choice(["A", "AAAA", "CNAME", "MX", "TXT"])

        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "network",
            "sub_type": "dns_query",
            "query": random.choice(DOMAINS),
            "query_type": query_type,
            "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(10, 200)}",
            "response": self._generate_dns_response(query_type),
            "response_time": random.randint(1, 500)  # ms
        }

    def network_connection(self) -> Dict[str, Any]:
        """Generate network connection event"""
        is_internal = random.random() > 0.3

        if is_internal:
            dest_ip = f"10.0.{random.randint(1, 5)}.{random.randint(10, 200)}"
            dest_port = random.choice([80, 443, 22, 3389, 5985])
        else:
            dest_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            dest_port = random.choice([443, 80, 53, 123, 995])

        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "network",
            "sub_type": "connection",
            "source_ip": f"10.0.{random.randint(1, 5)}.{random.randint(10, 200)}",
            "destination_ip": dest_ip,
            "destination_port": dest_port,
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes_sent": random.randint(100, 1048576),  # 100B to 1MB
            "bytes_received": random.randint(100, 5242880),  # 100B to 5MB
            "duration": random.randint(1, 3600)  # 1s to 1h
        }

    def beacon_traffic(self) -> Dict[str, Any]:
        """Generate C2 beacon-like traffic"""
        beacon_types = [
            {"name": "CobaltStrike", "pattern": "interval=60s jitter=20%", "ports": [443, 80]},
            {"name": "Metasploit", "pattern": "sleep=30", "ports": [4444, 8080]},
            {"name": "Sliver", "pattern": "beacon=polymorphic", "ports": [443, 53]},
            {"name": "Empire", "pattern": "delay=5", "ports": [80, 8080]}
        ]

        beacon = random.choice(beacon_types)

        return {
            "event_id": self.generate_id(),
            "timestamp": self.get_timestamp(),
            "event_type": "suspicious",
            "sub_type": "beacon_traffic",
            "beacon_type": beacon["name"],
            "pattern": beacon["pattern"],
            "destination_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "destination_port": random.choice(beacon["ports"]),
            "data_size": random.randint(50, 5000),
            "encrypted": random.choice([True, False]),
            "mimic": random.choice(["chrome", "onedrive", "windows_update", "teams"])
        }

    def _generate_dns_response(self, query_type: str) -> str:
        """Generate realistic DNS response"""
        if query_type == "A":
            return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        elif query_type == "AAAA":
            return f"2001:0db8:{random.randint(1000, 9999)}:{random.randint(1000, 9999)}::{random.randint(1, 9999)}"
        elif query_type == "CNAME":
            return random.choice(["cdn.microsoft.com", "lb.amazonaws.com", "googleusercontent.com"])
        elif query_type == "MX":
            return f"10 mail.{random.choice(['company.com', 'gmail.com', 'outlook.com'])}"
        else:
            return "v=spf1 include:_spf.google.com ~all"


# ============================================================================
# MAIN SIMULATION ENGINE
# ============================================================================

class PhantomPresence:
    """Main simulation engine"""

    def __init__(self, config: Config):
        self.config = config
        self.generators = {
            "auth": AuthenticationGenerator(),
            "process": ProcessGenerator(),
            "filesystem": FileSystemGenerator(),
            "network": NetworkGenerator()
        }
        self.running = False
        self.setup_logging()

        # Create honey file directory if needed
        if config.generate_fake_files and not os.path.exists(config.fake_file_directory):
            os.makedirs(config.fake_file_directory, exist_ok=True)

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("PhantomPresence")

    def is_business_hours(self) -> bool:
        """Check if current time is within business hours"""
        if not self.config.business_hours_only:
            return True

        now = datetime.now()
        # Business hours: Mon-Fri, 8 AM - 6 PM
        if now.weekday() >= 5:  # Saturday (5) or Sunday (6)
            return False

        hour = now.hour
        return 8 <= hour < 18

    def should_generate_event(self) -> bool:
        """Determine if an event should be generated based on intensity and time"""
        if not self.is_business_hours():
            # Reduce intensity outside business hours
            adjusted_intensity = self.config.intensity * 0.2
        else:
            adjusted_intensity = self.config.intensity

        return random.random() < adjusted_intensity

    def generate_event(self) -> Dict[str, Any]:
        """Generate a random event"""
        event_type = random.choices(
            ["auth", "process", "filesystem", "network", "suspicious"],
            weights=[0.3, 0.2, 0.2, 0.2, 0.1]  # Weighted probabilities
        )[0]

        if event_type == "auth":
            if random.random() > 0.8:  # 20% logout events
                return self.generators["auth"].logout_event()
            else:
                return self.generators["auth"].login_event()

        elif event_type == "process":
            if random.random() > 0.7:  # 30% process end events
                return self.generators["process"].process_end()
            else:
                return self.generators["process"].process_start()

        elif event_type == "filesystem":
            if random.random() > 0.9 and self.config.generate_fake_files:  # 10% honey files
                return self.generators["filesystem"].create_honey_file()
            else:
                return self.generators["filesystem"].file_access()

        elif event_type == "network":
            if random.random() > 0.5:
                return self.generators["network"].dns_query()
            else:
                return self.generators["network"].network_connection()

        else:  # suspicious
            return self.generators["network"].beacon_traffic()

    def write_event(self, event: Dict[str, Any]):
        """Write event to log file"""
        try:
            # Convert to JSON with pretty formatting for readability
            event_json = json.dumps(event, indent=2)

            # Log to file
            with open(self.config.log_file, "a", encoding="utf-8") as f:
                f.write(event_json + "\n")

            # Also print to console (optional)
            if random.random() > 0.8:  # Print only 20% of events to avoid spam
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Generated: {event['event_type']}.{event.get('sub_type', 'event')}")

            # Optional: Forward to syslog
            if self.config.syslog_server:
                self._forward_to_syslog(event)

        except Exception as e:
            self.logger.error(f"Error writing event: {e}")

    def _forward_to_syslog(self, event: Dict[str, Any]):
        """Forward event to syslog server (simplified)"""
        # This is a placeholder for actual syslog forwarding
        pass

    def rotate_logs_if_needed(self):
        """Rotate log file if it gets too large"""
        if not self.config.rotate_logs:
            return

        try:
            if os.path.exists(self.config.log_file):
                size_mb = os.path.getsize(self.config.log_file) / (1024 * 1024)
                if size_mb > self.config.max_log_size_mb:
                    # Rotate the log file
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    rotated_name = f"{self.config.log_file}.{timestamp}"
                    os.rename(self.config.log_file, rotated_name)
                    self.logger.info(f"Rotated log file to {rotated_name}")
        except Exception as e:
            self.logger.error(f"Error rotating logs: {e}")

    def run(self):
        """Main simulation loop"""
        self.running = True
        self.logger.info("PhantomPresence simulation started")
        print(f"""
╔══════════════════════════════════════════════════════╗
║             PHANTOM PRESENCE v2.0                    ║
║      Advanced Behavioral Deception System            ║
║                                                      ║
║  • Generating fake system activity                   ║
║  • Creating honey files and credentials              ║
║  • Simulating user behavior                          ║
║  • Logging to: {self.config.log_file:30}║
╚══════════════════════════════════════════════════════╝
        """)

        try:
            while self.running:
                if self.should_generate_event():
                    event = self.generate_event()
                    self.write_event(event)

                # Rotate logs periodically
                if random.random() > 0.99:  # 1% chance each loop
                    self.rotate_logs_if_needed()

                # Dynamic sleep based on intensity
                sleep_time = random.uniform(0.1, 3.0) * (1 / self.config.intensity)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            self.logger.info("Simulation stopped by user")
            print("\n\nSimulation stopped. Log file contains all generated events.")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            self.running = False


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_arguments():
    """Parse command line arguments"""
    import argparse

    parser = argparse.ArgumentParser(
        description="PhantomPresence - Generate fake system activity for defensive deception",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --intensity 0.5 --mode enterprise
  %(prog)s --business-hours-only --log-file /var/log/phantom.log
  %(prog)s --generate-fake-files --fake-file-dir ./honey/
        """
    )

    parser.add_argument("--log-file", default="phantom_presence.log",
                        help="Output log file path (default: phantom_presence.log)")
    parser.add_argument("--mode", choices=["enterprise", "developer", "admin", "mixed"],
                        default="mixed", help="Simulation mode (default: mixed)")
    parser.add_argument("--intensity", type=float, default=0.7,
                        help="Event generation intensity 0.1-1.0 (default: 0.7)")
    parser.add_argument("--business-hours-only", action="store_true",
                        help="Only generate events during business hours")
    parser.add_argument("--generate-fake-files", action="store_true",
                        help="Generate honey file events")
    parser.add_argument("--fake-file-dir", default="./honey_files/",
                        help="Directory for fake honey files (default: ./honey_files/)")

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()

    # Update config with command line arguments
    config.log_file = args.log_file
    config.simulation_mode = args.mode
    config.intensity = max(0.1, min(1.0, args.intensity))  # Clamp between 0.1 and 1.0
    config.business_hours_only = args.business_hours_only
    config.generate_fake_files = args.generate_fake_files
    config.fake_file_directory = args.fake_file_dir

    # Create and run simulation
    simulator = PhantomPresence(config)
    simulator.run()


if __name__ == "__main__":
    main()