import sqlite3
import whois
import re
from pathlib import Path

def database_record(target):
    info = whois.whois(target)

    # normalized whois data
    registrar = getattr(info, "registrar", None)
    expire = str(info.expiration_date) if hasattr(info, "expiration_date") else None
    dnssec = getattr(info, "dnssec", None)

    # nameservers
    if hasattr(info, "name_servers"):
        if isinstance(info.name_servers, list):
            nameserver_list = sorted(info.name_servers)
        else:
            nameserver_list = [info.name_servers]
    else:
        nameserver_list = []

    whois_raw = info.text if hasattr(info, "text") else ""

    # dnskeys
    dnskey_records = []

    if whois_raw:
        lines = whois_raw.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            # regex for line starting with dnskey
            m = re.match(r'^\s*(?i:dnskey)\s*:?\s*(\d+)\s+(\d+)\s+(\d+)\s*(.*)$', line)
            if m:
                flags = m.group(1)
                protocol = m.group(2)
                algorithm = m.group(3)
                pub = m.group(4).strip()

                # handling dnskey on a new line
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if re.match(r'^\s+[A-Za-z0-9+/=]+$', next_line):
                        pub += next_line.strip()
                        j += 1
                    else:
                        break

                i = j
                dnskey_records.append((int(flags), int(protocol), int(algorithm), pub))
                continue 
            i += 1

    # db creation
    output_dir = Path("database")
    output_dir.mkdir(parents=True, exist_ok=True)

    db_path = output_dir / "domain_audit.db"
    connect = sqlite3.connect(db_path)
    cursor = connect.cursor()

    # domains
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL
    );
    """)

    # scans
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        registrar TEXT,
        expire TEXT,
        dnssec TEXT,
        scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (domain_id) REFERENCES domains(id)
    );
    """)

    # nameservers
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_nameservers (
        scan_id INTEGER,
        ns TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );
    """)

    # dnskey table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_dnskeys (
        scan_id INTEGER,
        flags INTEGER,
        protocol INTEGER,
        algorithm INTEGER,
        public_key TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );
    """)

    # domain insert / find
    cursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?)", (target,))
    cursor.execute("SELECT id FROM domains WHERE domain = ?", (target,))
    domain_id = cursor.fetchone()[0]

    # insert scan
    cursor.execute("""
        INSERT INTO scans (domain_id, registrar, expire, dnssec)
        VALUES (?, ?, ?, ?)
    """, (domain_id, registrar, expire, dnssec))
    scan_id = cursor.lastrowid

    # insert nameservers
    for ns in nameserver_list:
        cursor.execute("INSERT INTO scan_nameservers (scan_id, ns) VALUES (?, ?)", (scan_id, ns))

    # insert dnskeys parsed from whois
    if dnskey_records:
        for flags, protocol, algorithm, pub in dnskey_records:
            cursor.execute("""
                INSERT INTO scan_dnskeys (scan_id, flags, protocol, algorithm, public_key)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, flags, protocol, algorithm, pub))
    else:
        pass

    connect.commit()
    connect.close()

    print("\033[92m[+] Record added to the database\033[0m")