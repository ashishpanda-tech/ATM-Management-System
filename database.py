import mysql.connector

def get_connection():
    conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="ashishpanda@2007",
    database="atm_system"
    )
    return conn

