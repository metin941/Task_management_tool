import bcrypt
import sqlite3

# Replace 'your_database.db' with the actual path to your SQLite database file
db_file_path = 'instance/users.db'

# Connect to the SQLite database
connection = sqlite3.connect(db_file_path)
cursor = connection.cursor()

# Replace 'your_table' with the actual name of your table
table_name = 'user_login'

# Replace 'admin' with the actual password you want to hash
username = "Metin"
password = "admin"

# Hash the password
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Insert the username and hashed password into the database
cursor.execute("INSERT INTO {} (username, password_hash) VALUES (?, ?);".format(table_name), (username, hashed_password.decode('utf-8')))

# Commit the changes
connection.commit()

# Close the database connection
connection.close()

print(f"Username '{username}' and hashed password inserted into the database.")
