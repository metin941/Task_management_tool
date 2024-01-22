import sqlite3
import csv

# Connect to the SQLite database
db_file_path = 'instance/users.db'  # Replace with the actual path to your SQLite database file
connection = sqlite3.connect(db_file_path)
cursor = connection.cursor()

# Execute a query to retrieve data from a table (replace 'your_table' and 'your_columns' accordingly)
query = "SELECT * FROM user_login;"
cursor.execute(query)

# Fetch all rows from the result set
rows = cursor.fetchall()

# Close the database connection
connection.close()

# Specify the path for the CSV file to be exported
csv_file_path = 'exported_data.csv'  # Replace with the desired path for the CSV file

# Write the data to a CSV file
with open(csv_file_path, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    
    # Write header if needed
    header = [description[0] for description in cursor.description]
    if header:
        csv_writer.writerow(header)
    
    # Write data rows
    csv_writer.writerows(rows)

print(f'Data exported to {csv_file_path}')
