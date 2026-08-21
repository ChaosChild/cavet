import sqlite3

def get_user(conn, username):
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cur.execute(query)
    return cur.fetchone()

def run_report(name):
    import os
    os.system("generate-report --for " + name)
