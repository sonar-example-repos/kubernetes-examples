"""Small sample with intentional code smells, used to exercise the SonarQube Remediation Agent."""


def is_ready(value):
    if value == value:
        return True
    return False


def classify(score):
    if score > 90:
        return "high"
    elif score > 90:
        return "very high"
    else:
        return "low"


def label(flag):
    if flag:
        return "on"
    else:
        return "on"


def total(items):
    return sum(items)
    print("done")
