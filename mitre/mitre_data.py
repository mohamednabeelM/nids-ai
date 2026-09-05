"""
mitre/mitre_data.py — Static MITRE ATT&CK technique database.

Maps every attack class detected by NIDS to its corresponding
ATT&CK Tactics, Techniques, and Sub-Techniques.

Source: https://attack.mitre.org  (Framework v14)
"""

# ─── Tactic Definitions ──────────────────────────────────────────────────────
TACTICS = {
    "TA0001": {"id": "TA0001", "name": "Initial Access",
               "desc": "Techniques to gain initial foothold in a network."},
    "TA0004": {"id": "TA0004", "name": "Privilege Escalation",
               "desc": "Techniques to gain higher permissions."},
    "TA0005": {"id": "TA0005", "name": "Defense Evasion",
               "desc": "Techniques to avoid detection."},
    "TA0006": {"id": "TA0006", "name": "Credential Access",
               "desc": "Techniques to steal credentials."},
    "TA0007": {"id": "TA0007", "name": "Discovery",
               "desc": "Techniques to gather information about the network."},
    "TA0040": {"id": "TA0040", "name": "Impact",
               "desc": "Techniques to disrupt availability or integrity."},
    "TA0043": {"id": "TA0043", "name": "Reconnaissance",
               "desc": "Techniques to gather info before attacking."},
}

# ─── Technique Definitions ───────────────────────────────────────────────────
TECHNIQUES = {

    # ── DoS Techniques ──────────────────────────────────────────────────────
    "T1498": {
        "id":       "T1498",
        "name":     "Network Denial of Service",
        "tactic_id":"TA0040",
        "tactic":   "Impact",
        "desc":     "Adversaries flood network infrastructure to degrade or "
                    "block availability for target users. Direct network "
                    "floods and amplification/reflection attacks are the "
                    "two main sub-techniques.",
        "url":      "https://attack.mitre.org/techniques/T1498/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {
                "id":   "T1498.001",
                "name": "Direct Network Flood",
                "desc": "SYN floods, ICMP floods, and UDP floods that "
                        "directly overwhelm target bandwidth or connection tables.",
                "url":  "https://attack.mitre.org/techniques/T1498/001/",
            },
            {
                "id":   "T1498.002",
                "name": "Reflection Amplification",
                "desc": "Uses third-party servers (DNS, NTP, SSDP) to amplify "
                        "traffic toward the target using spoofed source IPs.",
                "url":  "https://attack.mitre.org/techniques/T1498/002/",
            },
        ],
        "mitigations": [
            "M1037 — Filter Network Traffic (block spoofed source IPs at ingress)",
            "M1035 — Limit Access to Resource Over Network",
            "Upstream ISP-level traffic scrubbing / rate limiting",
        ],
        "detection_signals": [
            "Packet rate 100× above baseline",
            "SYN ratio > 0.9 with high serror_rate",
            "Single destination IP with massive volume",
        ],
    },

    "T1499": {
        "id":       "T1499",
        "name":     "Endpoint Denial of Service",
        "tactic_id":"TA0040",
        "tactic":   "Impact",
        "desc":     "Adversaries perform DoS attacks to degrade or block "
                    "availability of targeted resources at the application "
                    "or operating system layer.",
        "url":      "https://attack.mitre.org/techniques/T1499/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {
                "id":   "T1499.001",
                "name": "OS Exhaustion Flood",
                "desc": "Floods OS resources such as memory, CPU, or "
                        "network connections to render the system unresponsive.",
                "url":  "https://attack.mitre.org/techniques/T1499/001/",
            },
            {
                "id":   "T1499.002",
                "name": "Service Exhaustion Flood",
                "desc": "Floods specific services (HTTP, DNS, database "
                        "connections) to exhaust per-service limits.",
                "url":  "https://attack.mitre.org/techniques/T1499/002/",
            },
        ],
        "mitigations": [
            "M1037 — Filter Network Traffic",
            "M1050 — Exploit Protection (resource limits per connection)",
            "Rate limiting on application endpoints",
        ],
        "detection_signals": [
            "High count to same service (srv_count > 400)",
            "dst_host_same_srv_rate near 1.0",
            "Low duration with high packet volume",
        ],
    },

    # ── Probe / Scanning Techniques ─────────────────────────────────────────
    "T1046": {
        "id":       "T1046",
        "name":     "Network Service Discovery",
        "tactic_id":"TA0007",
        "tactic":   "Discovery",
        "desc":     "Adversaries scan victim networks to discover services "
                    "running on remote hosts. Tools like Nmap, Masscan, and "
                    "Netcat are commonly used. Results inform later stages "
                    "of an attack (exploitation, lateral movement).",
        "url":      "https://attack.mitre.org/techniques/T1046/",
        "severity": "HIGH",
        "sub_techniques": [],
        "mitigations": [
            "M1030 — Network Segmentation (limit scan visibility)",
            "M1031 — Network Intrusion Prevention",
            "Firewall rules blocking ICMP and unsolicited SYN to unused ports",
        ],
        "detection_signals": [
            "High diff_srv_rate (scanning many different ports)",
            "Low bytes per connection (just probing)",
            "High RST ratio (many closed ports hit)",
        ],
    },

    "T1595": {
        "id":       "T1595",
        "name":     "Active Scanning",
        "tactic_id":"TA0043",
        "tactic":   "Reconnaissance",
        "desc":     "Adversaries actively probe victim infrastructure using "
                    "port scans, vulnerability scans, and host discovery "
                    "techniques. This precedes exploitation and is one of "
                    "the earliest detectable stages of an attack.",
        "url":      "https://attack.mitre.org/techniques/T1595/",
        "severity": "HIGH",
        "sub_techniques": [
            {
                "id":   "T1595.001",
                "name": "Scanning IP Blocks",
                "desc": "Scans entire IP ranges to identify live hosts "
                        "before focusing on specific targets.",
                "url":  "https://attack.mitre.org/techniques/T1595/001/",
            },
            {
                "id":   "T1595.002",
                "name": "Vulnerability Scanning",
                "desc": "Probes for known software vulnerabilities on "
                        "discovered services using tools like Nessus or OpenVAS.",
                "url":  "https://attack.mitre.org/techniques/T1595/002/",
            },
            {
                "id":   "T1595.003",
                "name": "Wordlist Scanning",
                "desc": "Brute-forces web directories, DNS subdomains, or "
                        "credentials using wordlists.",
                "url":  "https://attack.mitre.org/techniques/T1595/003/",
            },
        ],
        "mitigations": [
            "M1056 — Pre-compromise (cannot be mitigated after scan completes)",
            "Deploy honeypots to detect scanning activity early",
            "Block source IPs with > N connection attempts per minute",
        ],
        "detection_signals": [
            "Sequential port access from single source",
            "Very short duration with low or zero dst_bytes",
            "dst_host_diff_srv_rate approaching 1.0",
        ],
    },

    "T1590": {
        "id":       "T1590",
        "name":     "Gather Victim Network Information",
        "tactic_id":"TA0043",
        "tactic":   "Reconnaissance",
        "desc":     "Adversaries gather information about the target's "
                    "network infrastructure including IP ranges, topology, "
                    "domain names, and network security appliances.",
        "url":      "https://attack.mitre.org/techniques/T1590/",
        "severity": "HIGH",
        "sub_techniques": [
            {
                "id":   "T1590.004",
                "name": "Network Topology",
                "desc": "Identifies routers, switches, firewalls, and the "
                        "overall structure of the target network.",
                "url":  "https://attack.mitre.org/techniques/T1590/004/",
            },
        ],
        "mitigations": [
            "M1056 — Pre-compromise hardening",
            "Minimise publicly available network topology information",
        ],
        "detection_signals": [
            "ICMP and traceroute-like packet patterns",
            "Systematic probing of different subnet ranges",
        ],
    },

    # ── R2L Techniques ───────────────────────────────────────────────────────
    "T1110": {
        "id":       "T1110",
        "name":     "Brute Force",
        "tactic_id":"TA0006",
        "tactic":   "Credential Access",
        "desc":     "Adversaries use brute force techniques to attempt "
                    "access to accounts when passwords are unknown or when "
                    "password hashes are obtained. Targets include SSH, "
                    "FTP, RDP, and web login forms.",
        "url":      "https://attack.mitre.org/techniques/T1110/",
        "severity": "HIGH",
        "sub_techniques": [
            {
                "id":   "T1110.001",
                "name": "Password Guessing",
                "desc": "Systematically guesses passwords using common lists "
                        "or variations of known username patterns.",
                "url":  "https://attack.mitre.org/techniques/T1110/001/",
            },
            {
                "id":   "T1110.003",
                "name": "Password Spraying",
                "desc": "Tries a single common password against many accounts "
                        "to avoid account lockout triggers.",
                "url":  "https://attack.mitre.org/techniques/T1110/003/",
            },
            {
                "id":   "T1110.004",
                "name": "Credential Stuffing",
                "desc": "Uses leaked credential pairs from other breaches "
                        "to attempt access on the target system.",
                "url":  "https://attack.mitre.org/techniques/T1110/004/",
            },
        ],
        "mitigations": [
            "M1032 — Multi-factor Authentication (MFA)",
            "M1036 — Account Use Policies (lockout after N failures)",
            "M1027 — Password Policies (minimum complexity and length)",
            "Disable password authentication for SSH; use key-based auth",
        ],
        "detection_signals": [
            "Long duration connection to port 22 or 21",
            "Repeated connections from same source with small intervals",
            "High dst_bytes (server responses to failed auth attempts)",
        ],
    },

    "T1021": {
        "id":       "T1021",
        "name":     "Remote Services",
        "tactic_id":"TA0001",
        "tactic":   "Initial Access",
        "desc":     "Adversaries use valid credentials to log into a service "
                    "specifically designed to accept remote connections such "
                    "as SSH, RDP, SMB, and VNC.",
        "url":      "https://attack.mitre.org/techniques/T1021/",
        "severity": "HIGH",
        "sub_techniques": [
            {
                "id":   "T1021.004",
                "name": "SSH",
                "desc": "Adversaries log into remote systems using SSH with "
                        "valid credentials, often obtained via brute force "
                        "or credential theft.",
                "url":  "https://attack.mitre.org/techniques/T1021/004/",
            },
            {
                "id":   "T1021.002",
                "name": "SMB / Windows Admin Shares",
                "desc": "Adversaries connect to remote systems via SMB "
                        "to transfer files or execute commands.",
                "url":  "https://attack.mitre.org/techniques/T1021/002/",
            },
        ],
        "mitigations": [
            "M1032 — Multi-factor Authentication",
            "M1042 — Disable or Remove Feature or Program (disable RDP if unused)",
            "M1035 — Limit Access to Resource Over Network",
        ],
        "detection_signals": [
            "Successful connection to port 22/23/445 after multiple failures",
            "Unusual source IP accessing administrative ports",
        ],
    },

    "T1078": {
        "id":       "T1078",
        "name":     "Valid Accounts",
        "tactic_id":"TA0001",
        "tactic":   "Initial Access",
        "desc":     "Adversaries obtain and abuse credentials of existing "
                    "accounts as a means of gaining initial access, "
                    "persistence, privilege escalation, or defense evasion.",
        "url":      "https://attack.mitre.org/techniques/T1078/",
        "severity": "HIGH",
        "sub_techniques": [
            {
                "id":   "T1078.003",
                "name": "Local Accounts",
                "desc": "Adversaries may obtain and abuse credentials of "
                        "a local account as a means of gaining access.",
                "url":  "https://attack.mitre.org/techniques/T1078/003/",
            },
        ],
        "mitigations": [
            "M1027 — Password Policies",
            "M1026 — Privileged Account Management",
            "M1013 — Application Developer Guidance",
        ],
        "detection_signals": [
            "Login from unusual geographic source",
            "Login at unusual time for the account",
            "Multiple accounts accessed from same IP",
        ],
    },

    # ── U2R Techniques ───────────────────────────────────────────────────────
    "T1068": {
        "id":       "T1068",
        "name":     "Exploitation for Privilege Escalation",
        "tactic_id":"TA0004",
        "tactic":   "Privilege Escalation",
        "desc":     "Adversaries exploit software vulnerabilities in an "
                    "attempt to elevate privileges. This is the primary "
                    "mechanism by which attackers move from a user-level "
                    "shell to root/SYSTEM access.",
        "url":      "https://attack.mitre.org/techniques/T1068/",
        "severity": "CRITICAL",
        "sub_techniques": [],
        "mitigations": [
            "M1051 — Update Software (patch management)",
            "M1019 — Threat Intelligence Program",
            "M1048 — Application Isolation and Sandboxing",
            "M1038 — Execution Prevention (disable unsafe binaries)",
        ],
        "detection_signals": [
            "Very long duration sessions (200+ seconds)",
            "High src_bytes (data staging before escalation)",
            "Privilege escalation commands in process arguments",
        ],
    },

    "T1055": {
        "id":       "T1055",
        "name":     "Process Injection",
        "tactic_id":"TA0004",
        "tactic":   "Privilege Escalation",
        "desc":     "Adversaries inject code into processes to evade "
                    "process-based defences and possibly elevate privileges. "
                    "Running code in the context of another process may "
                    "allow access to the process's memory and permissions.",
        "url":      "https://attack.mitre.org/techniques/T1055/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {
                "id":   "T1055.001",
                "name": "Dynamic-link Library Injection",
                "desc": "Injects a DLL into a running process to execute "
                        "malicious code in that process's context.",
                "url":  "https://attack.mitre.org/techniques/T1055/001/",
            },
            {
                "id":   "T1055.012",
                "name": "Process Hollowing",
                "desc": "Creates a process in a suspended state then "
                        "replaces its memory with malicious code.",
                "url":  "https://attack.mitre.org/techniques/T1055/012/",
            },
        ],
        "mitigations": [
            "M1026 — Privileged Account Management",
            "M1040 — Behavior Prevention on Endpoint",
            "Deploy EDR with process injection detection",
        ],
        "detection_signals": [
            "Unusual parent-child process relationships",
            "Process writing to another process's memory space",
            "Network connections from typically non-networking processes",
        ],
    },

    "T1059": {
        "id":       "T1059",
        "name":     "Command and Scripting Interpreter",
        "tactic_id":"TA0004",
        "tactic":   "Privilege Escalation",
        "desc":     "Adversaries abuse command and script interpreters to "
                    "execute commands, scripts, or binaries. These can be "
                    "used to run a series of actions for persistence, "
                    "privilege escalation, or data exfiltration.",
        "url":      "https://attack.mitre.org/techniques/T1059/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {
                "id":   "T1059.004",
                "name": "Unix Shell",
                "desc": "Adversaries abuse Unix shell commands and scripts "
                        "for execution — especially /bin/bash and /bin/sh.",
                "url":  "https://attack.mitre.org/techniques/T1059/004/",
            },
            {
                "id":   "T1059.006",
                "name": "Python",
                "desc": "Adversaries abuse Python to execute scripts and "
                        "commands for privilege escalation and persistence.",
                "url":  "https://attack.mitre.org/techniques/T1059/006/",
            },
        ],
        "mitigations": [
            "M1042 — Disable or Remove Feature or Program",
            "M1038 — Execution Prevention (application allowlisting)",
            "M1049 — Antivirus / Antimalware",
        ],
        "detection_signals": [
            "Shell spawned by unexpected parent process",
            "Interpreter executing base64-encoded commands",
            "Outbound connection opened by shell process",
        ],
    },

    "T1548": {
        "id":       "T1548",
        "name":     "Abuse Elevation Control Mechanism",
        "tactic_id":"TA0004",
        "tactic":   "Privilege Escalation",
        "desc":     "Adversaries bypass mechanisms designed to control "
                    "elevate privileges to perform privileged actions. "
                    "Includes sudo abuse, SUID/SGID exploitation, and "
                    "UAC bypass on Windows.",
        "url":      "https://attack.mitre.org/techniques/T1548/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {
                "id":   "T1548.001",
                "name": "Setuid and Setgid",
                "desc": "Adversaries exploit SUID/SGID bits on binaries "
                        "to execute code with elevated permissions.",
                "url":  "https://attack.mitre.org/techniques/T1548/001/",
            },
            {
                "id":   "T1548.003",
                "name": "Sudo and Sudo Caching",
                "desc": "Adversaries abuse sudo to elevate privileges, "
                        "particularly when sudo rules are misconfigured.",
                "url":  "https://attack.mitre.org/techniques/T1548/003/",
            },
        ],
        "mitigations": [
            "M1028 — Operating System Configuration",
            "M1026 — Privileged Account Management",
            "Audit SUID/SGID binaries regularly",
        ],
        "detection_signals": [
            "Unusual sudo commands in system logs",
            "SUID binary executed by non-root user",
            "Privilege change event without corresponding auth log",
        ],
    },
}

# ─── Attack Class → MITRE Technique Mapping ──────────────────────────────────
ATTACK_CLASS_MAP = {
    "dos": {
        "primary_technique":   "T1498",
        "secondary_technique": "T1499",
        "tactic":              "Impact (TA0040)",
        "technique_ids":       ["T1498", "T1499"],
        "kill_chain_phase":    "Actions on Objectives",
        "severity":            "CRITICAL",
        "summary": (
            "DoS attacks aim to deny access to services by exhausting network "
            "or system resources. Detected via packet_rate, serror_rate, and "
            "connection count anomalies."
        ),
    },
    "probe": {
        "primary_technique":   "T1046",
        "secondary_technique": "T1595",
        "tactic":              "Discovery (TA0007) + Reconnaissance (TA0043)",
        "technique_ids":       ["T1046", "T1595", "T1590"],
        "kill_chain_phase":    "Reconnaissance",
        "severity":            "HIGH",
        "summary": (
            "Probe attacks scan the network to discover hosts, open ports, "
            "and running services. Detected via diff_srv_rate, RST ratios, "
            "and sequential port access patterns."
        ),
    },
    "r2l": {
        "primary_technique":   "T1110",
        "secondary_technique": "T1021",
        "tactic":              "Credential Access (TA0006) + Initial Access (TA0001)",
        "technique_ids":       ["T1110", "T1021", "T1078"],
        "kill_chain_phase":    "Exploitation",
        "severity":            "HIGH",
        "summary": (
            "R2L attacks attempt to gain local access from a remote machine "
            "by exploiting weak credentials or vulnerabilities. Detected via "
            "long duration, high dst_bytes, and repeated auth attempts."
        ),
    },
    "u2r": {
        "primary_technique":   "T1068",
        "secondary_technique": "T1055",
        "tactic":              "Privilege Escalation (TA0004)",
        "technique_ids":       ["T1068", "T1055", "T1059", "T1548"],
        "kill_chain_phase":    "Privilege Escalation",
        "severity":            "CRITICAL",
        "summary": (
            "U2R attacks escalate from normal user to root/admin privileges "
            "by exploiting vulnerabilities or misconfigurations. Detected via "
            "very long sessions, high src_bytes, and anomaly scoring."
        ),
    },
    "normal": {
        "primary_technique":   None,
        "secondary_technique": None,
        "tactic":              "N/A — Legitimate Traffic",
        "technique_ids":       [],
        "kill_chain_phase":    "N/A",
        "severity":            "CLEAN",
        "summary":             "No malicious intent detected. Normal network flow.",
    },
}


# ─── Updated ATTACK_CLASS_MAP for 10 Granular Classes ────────────────────────
ATTACK_CLASS_MAP = {
    "normal": {
        "primary_technique": None, "secondary_technique": None,
        "tactic": "N/A — Legitimate Traffic",
        "technique_ids": [], "kill_chain_phase": "N/A",
        "severity": "CLEAN",
        "summary": "No malicious intent detected. Normal network flow.",
    },
    "dos": {
        "primary_technique": "T1498", "secondary_technique": "T1499",
        "tactic": "Impact (TA0040)",
        "technique_ids": ["T1498", "T1499"],
        "kill_chain_phase": "Actions on Objectives",
        "severity": "CRITICAL",
        "summary": "Single-source DoS floods targeting network bandwidth or "
                   "service availability. Detected via packet_rate, serror_rate "
                   "and count anomalies.",
    },
    "ddos": {
        "primary_technique": "T1498", "secondary_technique": "T1499",
        "tactic": "Impact (TA0040)",
        "technique_ids": ["T1498", "T1499"],
        "kill_chain_phase": "Actions on Objectives",
        "severity": "CRITICAL",
        "summary": "Distributed multi-source flooding — significantly higher "
                   "packet volume than single-source DoS. Amplification and "
                   "reflection techniques are common.",
    },
    "port_scan": {
        "primary_technique": "T1046", "secondary_technique": "T1595",
        "tactic": "Discovery (TA0007) + Reconnaissance (TA0043)",
        "technique_ids": ["T1046", "T1595", "T1590"],
        "kill_chain_phase": "Reconnaissance",
        "severity": "MEDIUM",
        "summary": "Sequential port probing using Nmap, ipsweep, or portsweep "
                   "to discover open services. Detected via high diff_srv_rate "
                   "and RST ratio with low bytes.",
    },
    "vuln_scan": {
        "primary_technique": "T1595", "secondary_technique": "T1590",
        "tactic": "Reconnaissance (TA0043)",
        "technique_ids": ["T1595", "T1590", "T1046"],
        "kill_chain_phase": "Reconnaissance",
        "severity": "HIGH",
        "summary": "Targeted vulnerability enumeration against specific services "
                   "using tools like Satan, Nessus, or OpenVAS. More selective "
                   "than port scanning.",
    },
    "brute_force": {
        "primary_technique": "T1110", "secondary_technique": "T1021",
        "tactic": "Credential Access (TA0006)",
        "technique_ids": ["T1110", "T1021", "T1078"],
        "kill_chain_phase": "Exploitation",
        "severity": "HIGH",
        "summary": "Repeated authentication attempts against SSH, FTP, or HTTP. "
                   "Detected via high same_srv_rate, rerror_rate, and repeated "
                   "connections to auth ports 21/22/80.",
    },
    "exploit": {
        "primary_technique": "T1068", "secondary_technique": "T1055",
        "tactic": "Privilege Escalation (TA0004)",
        "technique_ids": ["T1068", "T1055", "T1059", "T1548"],
        "kill_chain_phase": "Privilege Escalation",
        "severity": "CRITICAL",
        "summary": "Buffer overflow, shellcode injection, or kernel module "
                   "exploitation to gain root/SYSTEM access. Detected via "
                   "very high src_bytes, long duration, and urgent flags.",
    },
    "web_attack": {
        "primary_technique": "T1190", "secondary_technique": "T1059",
        "tactic": "Initial Access (TA0001) + Execution (TA0002)",
        "technique_ids": ["T1190", "T1059", "T1210"],
        "kill_chain_phase": "Exploitation",
        "severity": "HIGH",
        "summary": "SQL injection, XSS, or HTTP exploitation targeting "
                   "web applications on port 80/443. Detected via crafted "
                   "payloads in HTTP requests with unusual byte patterns.",
    },
    "infiltration": {
        "primary_technique": "T1071", "secondary_technique": "T1105",
        "tactic": "Command and Control (TA0011) + Lateral Movement (TA0008)",
        "technique_ids": ["T1071", "T1105", "T1021", "T1133"],
        "kill_chain_phase": "Command and Control",
        "severity": "CRITICAL",
        "summary": "Persistent backdoor or C2 channel maintaining covert "
                   "access. Detected via long session duration on non-standard "
                   "ports with low but steady traffic patterns.",
    },
    "exfiltration": {
        "primary_technique": "T1041", "secondary_technique": "T1048",
        "tactic": "Exfiltration (TA0010)",
        "technique_ids": ["T1041", "T1048", "T1567"],
        "kill_chain_phase": "Exfiltration",
        "severity": "CRITICAL",
        "summary": "Large unauthorised outbound data transfer via FTP, HTTP, "
                   "or covert channels. Detected via abnormally high dst_bytes "
                   "and byte_rate on standard ports.",
    },
}

# ─── Additional Techniques for New Classes ────────────────────────────────────
TECHNIQUES.update({
    "T1190": {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001", "tactic": "Initial Access",
        "desc": "Adversaries exploit weaknesses in internet-facing software "
                "including web applications, databases, and standard services. "
                "SQL injection and XSS are the most common sub-techniques.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "severity": "HIGH",
        "sub_techniques": [
            {"id": "T1190.001", "name": "SQL Injection",
             "desc": "Inserts malicious SQL into queries to dump databases, "
                     "bypass auth, or execute OS commands.",
             "url": "https://attack.mitre.org/techniques/T1190/"},
            {"id": "T1190.002", "name": "Cross-Site Scripting (XSS)",
             "desc": "Injects client-side scripts into web pages to steal "
                     "session tokens or redirect users.",
             "url": "https://attack.mitre.org/techniques/T1190/"},
        ],
        "mitigations": [
            "M1048 — Application Isolation and Sandboxing",
            "M1050 — Exploit Protection (WAF deployment)",
            "M1016 — Vulnerability Scanning and patching",
            "Use parameterised queries / prepared statements",
        ],
        "detection_signals": [
            "Unusual payload sizes on port 80/443",
            "High byte rate to web server",
            "Responses indicating SQL errors or script injection",
        ],
    },
    "T1071": {
        "id": "T1071", "name": "Application Layer Protocol",
        "tactic_id": "TA0011", "tactic": "Command and Control",
        "desc": "Adversaries communicate using application layer protocols "
                "to avoid detection. HTTP, HTTPS, DNS, and SMTP are "
                "commonly abused for C2 traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {"id": "T1071.001", "name": "Web Protocols",
             "desc": "Uses HTTP/HTTPS to blend C2 traffic with legitimate "
                     "web traffic, often using GET/POST requests.",
             "url": "https://attack.mitre.org/techniques/T1071/001/"},
            {"id": "T1071.004", "name": "DNS",
             "desc": "Encodes C2 data in DNS queries to exfiltrate "
                     "data or receive commands covertly.",
             "url": "https://attack.mitre.org/techniques/T1071/004/"},
        ],
        "mitigations": [
            "M1031 — Network Intrusion Prevention",
            "M1037 — Filter Network Traffic",
            "Analyse DNS query frequency and entropy for tunnelling",
        ],
        "detection_signals": [
            "Persistent low-traffic connection on unusual port",
            "Regular beacon interval (heartbeat pattern)",
            "Encrypted traffic to previously unknown destination",
        ],
    },
    "T1041": {
        "id": "T1041", "name": "Exfiltration Over C2 Channel",
        "tactic_id": "TA0010", "tactic": "Exfiltration",
        "desc": "Adversaries steal data over the existing C2 channel. "
                "This avoids creating new outbound connections that might "
                "be detected by DLP or firewall rules.",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "severity": "CRITICAL",
        "sub_techniques": [],
        "mitigations": [
            "M1031 — Network Intrusion Prevention",
            "M1057 — Data Loss Prevention (DLP)",
            "Baseline and alert on abnormal outbound data volume",
        ],
        "detection_signals": [
            "Abnormally high dst_bytes in single connection",
            "Very high byte_rate on standard port",
            "Connection to external IP with large upload",
        ],
    },
    "T1048": {
        "id": "T1048", "name": "Exfiltration Over Alternative Protocol",
        "tactic_id": "TA0010", "tactic": "Exfiltration",
        "desc": "Adversaries use protocols other than the C2 channel to "
                "exfiltrate data — DNS tunnelling, ICMP, or FTP to "
                "avoid monitoring of primary channels.",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {"id": "T1048.001", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
             "desc": "Uses encrypted protocols like SFTP or HTTPS to a "
                     "non-C2 destination to transfer stolen data.",
             "url": "https://attack.mitre.org/techniques/T1048/001/"},
            {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
             "desc": "Uses FTP, HTTP, or DNS to transfer data in cleartext, "
                     "making it detectable by network monitoring.",
             "url": "https://attack.mitre.org/techniques/T1048/003/"},
        ],
        "mitigations": [
            "M1057 — Data Loss Prevention (DLP)",
            "M1031 — Network Intrusion Prevention",
            "Block outbound FTP from production servers",
        ],
        "detection_signals": [
            "FTP/HTTP upload of large files to external IPs",
            "DNS query payload entropy indicating tunnelling",
            "Outbound ICMP with unusually large payloads",
        ],
    },
    "T1105": {
        "id": "T1105", "name": "Ingress Tool Transfer",
        "tactic_id": "TA0011", "tactic": "Command and Control",
        "desc": "Adversaries transfer tools or malware from external "
                "systems into a compromised network environment. "
                "wget, curl, PowerShell and BITS are commonly used.",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "severity": "CRITICAL",
        "sub_techniques": [],
        "mitigations": [
            "M1037 — Filter Network Traffic",
            "M1042 — Disable or Remove Feature (curl/wget on servers)",
            "Egress filtering on production servers",
        ],
        "detection_signals": [
            "Inbound file transfer on non-standard port",
            "Download of executable from external IP",
            "High src_bytes to internal host from untrusted source",
        ],
    },
    "T1133": {
        "id": "T1133", "name": "External Remote Services",
        "tactic_id": "TA0001", "tactic": "Initial Access",
        "desc": "Adversaries leverage external-facing remote services such "
                "as VPN, Citrix, RDP, and SSH to gain initial access. "
                "Often combined with valid credentials obtained via phishing.",
        "url": "https://attack.mitre.org/techniques/T1133/",
        "severity": "HIGH",
        "sub_techniques": [],
        "mitigations": [
            "M1032 — Multi-factor Authentication",
            "M1042 — Disable or Remove Feature (disable unused services)",
            "M1035 — Limit Access to Resource Over Network",
        ],
        "detection_signals": [
            "Login from unusual geographic source",
            "Access at abnormal hours for the account",
            "New device or IP accessing remote services",
        ],
    },
    "T1567": {
        "id": "T1567", "name": "Exfiltration Over Web Service",
        "tactic_id": "TA0010", "tactic": "Exfiltration",
        "desc": "Adversaries use legitimate web services (Google Drive, "
                "Dropbox, GitHub, Pastebin) to exfiltrate data, blending "
                "with normal web traffic to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1567/",
        "severity": "CRITICAL",
        "sub_techniques": [
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage",
             "desc": "Uploads stolen data to cloud storage services like "
                     "OneDrive, Google Drive, or Dropbox using legitimate APIs.",
             "url": "https://attack.mitre.org/techniques/T1567/002/"},
        ],
        "mitigations": [
            "M1057 — Data Loss Prevention",
            "Proxy inspection of cloud storage traffic",
            "Alert on anomalous upload volume to cloud services",
        ],
        "detection_signals": [
            "Large HTTPS PUT/POST to cloud storage domains",
            "Abnormal volume of data to legitimate web services",
            "Sensitive file types (*.csv, *.db) in upload traffic",
        ],
    },
    "T1210": {
        "id": "T1210", "name": "Exploitation of Remote Services",
        "tactic_id": "TA0008", "tactic": "Lateral Movement",
        "desc": "Adversaries exploit remote services to gain access to "
                "internal systems. This includes exploiting vulnerabilities "
                "in network services exposed on the internal network.",
        "url": "https://attack.mitre.org/techniques/T1210/",
        "severity": "CRITICAL",
        "sub_techniques": [],
        "mitigations": [
            "M1051 — Update Software",
            "M1019 — Threat Intelligence Program",
            "Network segmentation to limit lateral movement",
        ],
        "detection_signals": [
            "Exploit signatures in payload bytes",
            "Unexpected process spawned after connection",
            "Connection to internal service from unusual source",
        ],
    },
})
