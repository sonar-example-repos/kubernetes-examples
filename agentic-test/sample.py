"""Small sample with intentional code smells, used to exercise the SonarQube Remediation Agent."""


def parse_port(value, default, unused_flag):
    result = None
    try:
        port = int(value)
    except:
        port = default
    return port


def build_label(name):
    label = name.strip()
    count = 0
    return name.strip()
