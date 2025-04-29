import bcrypt
import mysql.connector

# Test bcrypt
print("Testing bcrypt...")
password = "test123"
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
print("Hashed password:", hashed)

# Test MySQL connection
print("Testing MySQL connection...")
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Harshu@2807',
    database='HealthCare',
    auth_plugin='mysql_native_password'
)
cursor = conn.cursor()
cursor.execute("SHOW TABLES;")
tables = cursor.fetchall()
print("Tables in database:", tables)
cursor.close()
conn.close()