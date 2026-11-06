"""Small sample with intentional cross-function vulnerabilities, used to exercise the SonarQube Hunter Agent.

The user input is read in one function and reaches the sink in another, so the flaws need data-flow
reasoning across functions rather than a single-line pattern match.
"""
import os
import sqlite3


def read_request_param(request, name):
    # untrusted input enters here
    return request.args.get(name, "")


def build_lookup_query(username):
    # taint flows from the request into the SQL text unescaped
    return "SELECT id, email FROM users WHERE name = '" + username + "'"


def find_user(request, db_path="app.db"):
    username = read_request_param(request, "user")
    query = build_lookup_query(username)
    with sqlite3.connect(db_path) as conn:
        return conn.execute(query).fetchall()  # SQL injection


def resolve_report_path(report_dir, filename):
    # no normalization, so "../" escapes report_dir
    return os.path.join(report_dir, filename)


def read_report(request, report_dir="/var/app/reports"):
    filename = read_request_param(request, "file")
    with open(resolve_report_path(report_dir, filename)) as handle:  # path traversal
        return handle.read()


def run_diagnostics(request):
    host = read_request_param(request, "host")
    return os.popen("ping -c 1 " + host).read()  # OS command injection
