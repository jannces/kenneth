"""Predefined mitigation knowledge base.

This is the educational heart of AETHRA-SEC.  Each entry maps a threat category
to a structured, beginner-friendly recommendation.  The system only *advises* -
it never blocks attacks or edits firewall rules, matching the manuscript scope.

The data here is seeded into ``mitigation_recommendations`` on first run and can
subsequently be edited by an administrator through the Mitigation Center.
"""

from __future__ import annotations

from typing import Dict, List

from utils.constants import ThreatCategory, Severity


# Each record contains the full step-by-step guidance required by the spec:
# problem, why it happened, risk, how to verify, immediate actions, long-term
# prevention, references, plus a plain-language educational explanation.
RECOMMENDATIONS: List[Dict[str, str]] = [
    {
        "alert_type": ThreatCategory.PORT_SCAN.value,
        "severity": Severity.MEDIUM.value,
        "recommendation_title": "Respond to Port Scanning Activity",
        "educational": (
            "A port scan is when a device checks another computer to discover "
            "which network services are available. Attackers often perform port "
            "scans before attempting further attacks. This does not always mean "
            "the scan is malicious, but repeated scanning may indicate "
            "reconnaissance."
        ),
        "explanation": (
            "One host is probing many ports on a target to map exposed services."
        ),
        "problem": "A device is systematically probing ports to enumerate services.",
        "why_it_happened": (
            "Exposed or unnecessary services are reachable on the network, making "
            "the host an attractive target for reconnaissance."
        ),
        "risk": "Discovered services can be targeted for exploitation or brute force.",
        "how_to_verify": (
            "Correlate the source IP against the packet log; a burst of SYN packets "
            "to sequential ports from one source confirms scanning."
        ),
        "immediate_actions": (
            "1. Identify the scanning source IP.\n"
            "2. Confirm whether it is an authorised laboratory host.\n"
            "3. Note which ports responded as open."
        ),
        "long_term_prevention": (
            "Restrict unnecessary open ports.\nReview firewall rules.\n"
            "Disable unused services.\nMonitor repeated scanning attempts.\n"
            "Verify exposed services regularly."
        ),
        "recommendation": (
            "Restrict unnecessary open ports. Review firewall rules. Disable "
            "unused services. Monitor repeated scanning attempts. Verify exposed "
            "services."
        ),
        "reference": "NIST SP 800-115; MITRE ATT&CK T1046 (Network Service Discovery)",
        "difficulty": "Easy",
    },
    {
        "alert_type": ThreatCategory.BRUTE_FORCE.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Contain Brute-Force Login Attempts",
        "educational": (
            "A brute-force attack repeatedly guesses usernames and passwords "
            "until it finds a valid combination. Many failed logins from one "
            "source in a short time is the classic signature."
        ),
        "explanation": "Repeated authentication failures indicate password guessing.",
        "problem": "An attacker is attempting many credential combinations.",
        "why_it_happened": (
            "An authentication service (SSH, RDP, FTP, web login) is reachable and "
            "does not sufficiently limit repeated attempts."
        ),
        "risk": "Account compromise leading to unauthorised access.",
        "how_to_verify": (
            "Review authentication logs for a spike of failures from a single "
            "source IP targeting one or more accounts."
        ),
        "immediate_actions": (
            "1. Identify targeted account(s) and source IP.\n"
            "2. Confirm no successful login followed the failures.\n"
            "3. Force a password reset if any account may be compromised."
        ),
        "long_term_prevention": (
            "Enable account lockout.\nUse strong passwords.\nEnable MFA if "
            "available.\nReview login logs.\nLimit repeated authentication attempts."
        ),
        "recommendation": (
            "Enable account lockout. Use strong passwords. Enable MFA if "
            "available. Review login logs. Limit repeated authentication attempts."
        ),
        "reference": "OWASP Authentication Cheat Sheet; MITRE ATT&CK T1110 (Brute Force)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.TCP_FLOOD.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Mitigate a TCP Flood",
        "educational": (
            "A TCP flood sends a very large number of TCP connection requests to "
            "overwhelm a target, exhausting its resources so legitimate users "
            "cannot connect."
        ),
        "explanation": "A surge of TCP SYN traffic is targeting a host.",
        "problem": "Excessive TCP connection attempts are consuming resources.",
        "why_it_happened": (
            "A host is being targeted by many connection requests, possibly a "
            "SYN flood denial-of-service pattern."
        ),
        "risk": "Service degradation or outage (availability impact).",
        "how_to_verify": (
            "Check the bandwidth monitor and connection tracker for an abnormal "
            "spike of half-open TCP connections from one or few sources."
        ),
        "immediate_actions": (
            "1. Identify the source address(es).\n"
            "2. Confirm the affected service is still responsive.\n"
            "3. Note the sustained packets-per-second rate."
        ),
        "long_term_prevention": (
            "Review firewall policies.\nRate-limit connections.\nInvestigate "
            "source addresses.\nMonitor bandwidth.\nVerify server availability."
        ),
        "recommendation": (
            "Review firewall policies. Rate-limit connections. Investigate source "
            "addresses. Monitor bandwidth. Verify server availability."
        ),
        "reference": "CISA DDoS Guidance; MITRE ATT&CK T1499 (Endpoint DoS)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.UDP_FLOOD.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Mitigate a UDP Flood",
        "educational": (
            "A UDP flood sends many UDP packets to random ports on a target. The "
            "target wastes resources replying that no service exists, which can "
            "exhaust bandwidth and CPU."
        ),
        "explanation": "A high volume of UDP packets is targeting a host.",
        "problem": "Excessive UDP traffic is saturating the target.",
        "why_it_happened": "The host is reachable and being flooded with UDP datagrams.",
        "risk": "Bandwidth exhaustion and service unavailability.",
        "how_to_verify": (
            "Inspect the protocol distribution chart for an abnormal UDP share and "
            "correlate with source IPs in the packet log."
        ),
        "immediate_actions": (
            "1. Identify source addresses.\n2. Measure the UDP packet rate.\n"
            "3. Verify the target's continued availability."
        ),
        "long_term_prevention": (
            "Rate-limit UDP where feasible.\nBlock unused UDP ports at the "
            "firewall.\nMonitor bandwidth.\nInvestigate repeated sources."
        ),
        "recommendation": (
            "Rate-limit UDP traffic. Restrict unused UDP ports. Monitor bandwidth. "
            "Investigate repeated source addresses."
        ),
        "reference": "CISA DDoS Guidance; MITRE ATT&CK T1498 (Network DoS)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.ICMP_FLOOD.value,
        "severity": Severity.MEDIUM.value,
        "recommendation_title": "Mitigate an ICMP Flood",
        "educational": (
            "An ICMP flood (ping flood) sends many ICMP echo requests to overwhelm "
            "a target with traffic it must answer, consuming bandwidth."
        ),
        "explanation": "A large number of ICMP packets is targeting a host.",
        "problem": "Excessive ICMP echo traffic is consuming network capacity.",
        "why_it_happened": "ICMP is unrestricted and the host is being flooded with pings.",
        "risk": "Bandwidth consumption and potential availability impact.",
        "how_to_verify": (
            "Review the protocol statistics for an ICMP spike and identify the "
            "source addresses generating the echo requests."
        ),
        "immediate_actions": (
            "1. Identify repeated ICMP sources.\n2. Measure the ICMP rate.\n"
            "3. Confirm network availability is maintained."
        ),
        "long_term_prevention": (
            "Limit ICMP if operationally acceptable.\nMonitor bandwidth.\n"
            "Identify repeated ICMP sources.\nReview network availability."
        ),
        "recommendation": (
            "Limit ICMP if operationally acceptable. Monitor bandwidth. Identify "
            "repeated ICMP sources. Review network availability."
        ),
        "reference": "NIST SP 800-41; MITRE ATT&CK T1498 (Network DoS)",
        "difficulty": "Easy",
    },
    {
        "alert_type": ThreatCategory.HTTP_ATTACK.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Investigate Abnormal HTTP Traffic",
        "educational": (
            "Abnormal HTTP traffic can mean an attacker is flooding a web server "
            "with requests or probing web applications for vulnerabilities such as "
            "injection or path traversal."
        ),
        "explanation": "Unusual volume or pattern of HTTP requests detected.",
        "problem": "A web service is receiving abnormal or excessive requests.",
        "why_it_happened": "A web application is exposed and being probed or flooded.",
        "risk": "Web application compromise or denial of service.",
        "how_to_verify": (
            "Review web server logs and the packet log for repeated requests, "
            "unusual user agents, or suspicious URL patterns."
        ),
        "immediate_actions": (
            "1. Review web server logs.\n2. Inspect unusual request rates.\n"
            "3. Identify the source addresses."
        ),
        "long_term_prevention": (
            "Review web server logs.\nInspect unusual request rates.\nValidate "
            "web application configuration.\nMonitor ongoing traffic.\nConsider a "
            "web application firewall."
        ),
        "recommendation": (
            "Review web server logs. Inspect unusual request rates. Validate web "
            "application configuration. Monitor ongoing traffic."
        ),
        "reference": "OWASP Top 10; MITRE ATT&CK T1190 (Exploit Public-Facing App)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.DNS_ATTACK.value,
        "severity": Severity.MEDIUM.value,
        "recommendation_title": "Investigate Suspicious DNS Activity",
        "educational": (
            "DNS attacks include flooding a resolver with queries or abusing DNS to "
            "tunnel data. Unusual DNS volume can indicate misuse of the name "
            "resolution service."
        ),
        "explanation": "Abnormal DNS query volume or patterns detected.",
        "problem": "A DNS service is receiving unusual query traffic.",
        "why_it_happened": "A resolver is exposed and being queried abnormally.",
        "risk": "Resolver overload or data exfiltration via DNS tunneling.",
        "how_to_verify": (
            "Examine DNS query counts and look for repetitive or oversized queries "
            "from a single source."
        ),
        "immediate_actions": (
            "1. Identify the query source.\n2. Review query volume and patterns.\n"
            "3. Confirm the resolver remains responsive."
        ),
        "long_term_prevention": (
            "Restrict recursion to trusted clients.\nRate-limit DNS queries.\n"
            "Monitor for tunneling patterns.\nKeep resolver software updated."
        ),
        "recommendation": (
            "Restrict DNS recursion to trusted clients. Rate-limit queries. Monitor "
            "for tunneling. Keep resolvers updated."
        ),
        "reference": "NIST SP 800-81; MITRE ATT&CK T1071.004 (DNS)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.FTP_ATTACK.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Secure FTP Services",
        "educational": (
            "FTP transmits credentials and data in clear text. Attacks include "
            "credential guessing and interception of unencrypted transfers."
        ),
        "explanation": "Suspicious activity against an FTP service detected.",
        "problem": "An FTP service is being targeted or misused.",
        "why_it_happened": "A clear-text FTP service is exposed on the network.",
        "risk": "Credential theft and data interception.",
        "how_to_verify": (
            "Review FTP authentication attempts and check whether the service uses "
            "encryption (FTPS/SFTP)."
        ),
        "immediate_actions": (
            "1. Identify the source of the activity.\n2. Confirm whether FTP is "
            "required.\n3. Check for successful unauthorised logins."
        ),
        "long_term_prevention": (
            "Replace FTP with SFTP/FTPS.\nEnforce strong credentials.\nRestrict "
            "access by IP.\nMonitor authentication attempts."
        ),
        "recommendation": (
            "Replace FTP with SFTP/FTPS. Enforce strong credentials. Restrict "
            "access by IP. Monitor authentication attempts."
        ),
        "reference": "NIST SP 800-52; MITRE ATT&CK T1110 (Brute Force)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.SSH_ATTACK.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Harden SSH Against Attacks",
        "educational": (
            "SSH provides encrypted remote administration, but exposed SSH is a "
            "common brute-force target. Repeated login failures indicate someone "
            "is trying to guess credentials."
        ),
        "explanation": "Suspicious SSH authentication activity detected.",
        "problem": "An SSH service is being targeted, likely by credential guessing.",
        "why_it_happened": "SSH is reachable and remote logins are permitted.",
        "risk": "Remote shell access if credentials are compromised.",
        "how_to_verify": (
            "Review SSH authentication logs for repeated failures from one source "
            "and correlate with the Snort alert source IP."
        ),
        "immediate_actions": (
            "1. Identify the source IP and targeted accounts.\n2. Confirm no "
            "successful login occurred.\n3. Consider temporarily restricting SSH."
        ),
        "long_term_prevention": (
            "Use key-based authentication.\nDisable root login.\nEnable account "
            "lockout / fail2ban-style limits.\nRestrict SSH by source IP.\nEnable MFA."
        ),
        "recommendation": (
            "Use key-based authentication. Disable root login. Rate-limit attempts. "
            "Restrict SSH by source IP. Enable MFA where possible."
        ),
        "reference": "NIST SP 800-123; MITRE ATT&CK T1021.004 (SSH)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.WEB_ATTACK.value,
        "severity": Severity.HIGH.value,
        "recommendation_title": "Respond to Web Application Attack",
        "educational": (
            "Web attacks attempt to exploit application flaws such as SQL "
            "injection, cross-site scripting, or path traversal to steal data or "
            "gain control."
        ),
        "explanation": "A signature associated with web exploitation was detected.",
        "problem": "A web application is being probed for exploitable flaws.",
        "why_it_happened": "A public-facing web application has exploitable inputs.",
        "risk": "Data breach or server compromise.",
        "how_to_verify": (
            "Inspect web server logs for injection payloads or unusual parameters "
            "matching the alert."
        ),
        "immediate_actions": (
            "1. Identify the targeted endpoint.\n2. Review the request payloads.\n"
            "3. Confirm whether the attempt succeeded."
        ),
        "long_term_prevention": (
            "Validate and sanitise all inputs.\nUse parameterised queries.\nDeploy "
            "a web application firewall.\nKeep frameworks patched."
        ),
        "recommendation": (
            "Validate and sanitise inputs. Use parameterised queries. Deploy a WAF. "
            "Keep software patched."
        ),
        "reference": "OWASP Top 10; MITRE ATT&CK T1190",
        "difficulty": "Hard",
    },
    {
        "alert_type": ThreatCategory.RECONNAISSANCE.value,
        "severity": Severity.LOW.value,
        "recommendation_title": "Monitor Reconnaissance Activity",
        "educational": (
            "Reconnaissance is the information-gathering stage where an attacker "
            "maps the network and its services before attacking."
        ),
        "explanation": "Activity consistent with network reconnaissance detected.",
        "problem": "A host is gathering information about the network.",
        "why_it_happened": "Devices and services are discoverable on the network.",
        "risk": "Collected information may enable a targeted follow-up attack.",
        "how_to_verify": "Correlate the source with scanning and probing patterns in the logs.",
        "immediate_actions": (
            "1. Identify the source host.\n2. Determine what information was "
            "reachable.\n3. Record the activity for trend analysis."
        ),
        "long_term_prevention": (
            "Minimise exposed services.\nSegment the network.\nMonitor for repeated "
            "probing.\nKeep an inventory of authorised hosts."
        ),
        "recommendation": (
            "Minimise exposed services. Segment the network. Monitor repeated "
            "probing. Maintain an authorised-host inventory."
        ),
        "reference": "MITRE ATT&CK TA0043 (Reconnaissance)",
        "difficulty": "Easy",
    },
    {
        "alert_type": ThreatCategory.SUSPICIOUS_TRAFFIC.value,
        "severity": Severity.MEDIUM.value,
        "recommendation_title": "Review Suspicious Traffic",
        "educational": (
            "Suspicious traffic is activity that deviates from normal patterns "
            "without matching a specific known attack. It warrants a closer look."
        ),
        "explanation": "Traffic matched a general suspicious-activity signature.",
        "problem": "Unusual traffic patterns were observed.",
        "why_it_happened": "Behaviour deviated from the expected baseline.",
        "risk": "May be an early indicator of a developing incident.",
        "how_to_verify": "Examine the involved hosts, ports, and payloads in the packet log.",
        "immediate_actions": (
            "1. Review the source and destination.\n2. Compare against normal "
            "baseline traffic.\n3. Decide whether escalation is warranted."
        ),
        "long_term_prevention": (
            "Establish traffic baselines.\nTune detection rules.\nMonitor recurring "
            "anomalies.\nDocument findings."
        ),
        "recommendation": (
            "Establish baselines. Tune detection rules. Monitor recurring anomalies. "
            "Document findings."
        ),
        "reference": "NIST SP 800-94 (IDS/IPS Guide)",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.MALFORMED_PACKET.value,
        "severity": Severity.MEDIUM.value,
        "recommendation_title": "Handle Malformed Packets",
        "educational": (
            "Malformed packets violate protocol rules. They can be crafted to "
            "crash software, evade detection, or probe how systems respond."
        ),
        "explanation": "Packets violating protocol structure were detected.",
        "problem": "Malformed or crafted packets are present on the network.",
        "why_it_happened": "A source is sending non-conforming packets, possibly deliberately.",
        "risk": "Denial of service or detection evasion.",
        "how_to_verify": "Inspect the flagged packets' headers and flags in the packet log.",
        "immediate_actions": (
            "1. Identify the source.\n2. Examine the malformed fields.\n"
            "3. Confirm target stability."
        ),
        "long_term_prevention": (
            "Keep network stacks patched.\nEnable protocol validation at the "
            "firewall.\nMonitor for repeated malformed traffic."
        ),
        "recommendation": (
            "Keep systems patched. Enable protocol validation. Monitor for repeated "
            "malformed traffic."
        ),
        "reference": "NIST SP 800-94; MITRE ATT&CK T1499",
        "difficulty": "Moderate",
    },
    {
        "alert_type": ThreatCategory.UNKNOWN_THREAT.value,
        "severity": Severity.LOW.value,
        "recommendation_title": "Investigate Unclassified Alert",
        "educational": (
            "This alert did not match a known category. Investigate the details to "
            "understand what triggered it and whether action is needed."
        ),
        "explanation": "An alert that could not be automatically categorised.",
        "problem": "An intrusion signature fired without a mapped category.",
        "why_it_happened": "A custom or uncommon Snort rule matched the traffic.",
        "risk": "Unknown until investigated; treat with appropriate caution.",
        "how_to_verify": "Look up the Snort SID and rule message, then review the involved hosts.",
        "immediate_actions": (
            "1. Review the alert description and SID.\n2. Examine source and "
            "destination.\n3. Classify manually if a pattern emerges."
        ),
        "long_term_prevention": (
            "Refine rule categorisation.\nDocument new signatures.\nMonitor for "
            "recurrence."
        ),
        "recommendation": (
            "Review the alert details and Snort SID. Investigate the involved hosts. "
            "Classify and document."
        ),
        "reference": "Snort Rule Documentation; NIST SP 800-94",
        "difficulty": "Moderate",
    },
]


def get_default_recommendations() -> List[Dict[str, str]]:
    """Return a copy of the predefined recommendation set."""
    return [dict(item) for item in RECOMMENDATIONS]
