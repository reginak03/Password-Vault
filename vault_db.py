import sqlite3

#connect to a database file (creates it if it doesn't exist)
conn = sqlite3.connect("vault.db")

#create a cursor to execute SQL commands
cursor = conn.cursor()

#create a table for storing credentials
cursor.execute('''
    CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT NOT NULL,
        username TEXT NOT NULL,
        password BLOB NOT NULL,
        notes TEXT
    )
''')

#save changes and close connection
conn.commit()
conn.close()

print("Database and table created successfully!")
