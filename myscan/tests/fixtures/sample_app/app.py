"""Deliberately vulnerable sample app used by the integration test suite."""

import os
import pickle
import sqlite3
import subprocess


def get_user_data(user_id: str) -> str:
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE id = '" + user_id + "'")
    row = cur.fetchone()
    return row[0] if row else "none"


def run_command(cmd: str) -> str:
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return out.stdout


def load_config(path: str) -> bytes:
    with open(path, "rb") as f:
        return pickle.load(f)


def load_pickle(data: bytes):
    return pickle.loads(data)


API_SECRET = "sk-9f8e7d6c5b4a3z2y1x0w"
DB_PASSWORD = "SuperSecret2024!"


def render_page(name: str) -> str:
    template = "<h1>Hello, " + name + "</h1>"
    return template


def execute_dynamic(code: str) -> object:
    return eval(code)
