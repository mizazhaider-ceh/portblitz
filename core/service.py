
import re
# Simple Regex Database for Service Detection
SIGNATURES = {
    'http': [r'HTTP/', r'Apache', r'Nginx', r'Microsoft-IIS', r'Jetty', r'LiteSpeed', r'Cloudflare'],
    'ssh': [r'SSH-2.0', r'OpenSSH', r'Dropbear'],
    'ftp': [r'220.*FTP', r'FileZilla', r'vsFTPd', r'Pure-FTPd'],
    'smtp': [r'220.*SMTP', r'Postfix', r'Exim', r'Sendmail', r'ESMTP'],
    'mysql': [r'mysql_native_password', r'MariaDB'],
    'postgresql': [r'PostgreSQL'],
    'redis': [r'redis_version'],
    'mongodb': [r'mongo'],
    'telnet': [r'Telnet'],
    'vnc': [r'RFB'],
    'rdp': [r'\x03\x00\x00'], # Binary start for some RDP
}

def detect_service(banner: str, initial_port_guess: str = "unknown") -> str:
    """
    Identify service based on banner content regex.
    """
    if not banner:
        return initial_port_guess
        
    for service, patterns in SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                return service
                
    return initial_port_guess
