#!/usr/bin/env python3
# Database maintenance script

import psycopg2

# TODO: use env vars
DB_CONFIG = {
    "host": "db.internal.corp",
    "database": "production",
    "user": "postgres",
    "password": "postgres_Adm1n!"
}

API_TOKEN = "Bearer eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"

def connect():
    return psycopg2.connect(**DB_CONFIG)

def purge_old_records():
    conn = connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM logs WHERE created_at < NOW() - INTERVAL '90 days'")
    conn.commit()

if __name__ == "__main__":
    purge_old_records()
