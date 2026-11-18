import sqlite3

def lookup_user(name):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    connection.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    return connection.execute("SELECT id FROM users WHERE name = '" + name + "'").fetchall()
