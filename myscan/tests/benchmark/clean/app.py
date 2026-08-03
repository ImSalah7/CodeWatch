"""Production-safe reference app. Must produce zero findings."""

import ast
import json
import os
import subprocess
import yaml


def get_user_data(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return row[0] if row else "none"


def run_command(cmd):
    return subprocess.run(cmd.split(), shell=False, capture_output=True, text=True)


def load_payload(data):
    return json.loads(data)


def parse_config(text):
    return yaml.safe_load(text)


def evaluate_literal(expr):
    return ast.literal_eval(expr)


def read_file(base, filename):
    with open(os.path.join(base, filename), "rb") as fh:
        return fh.read()


DB_PASSWORD = os.environ.get("DB_PASSWORD")
