import psycopg2
import sys


def get_connection():
    try:
        connection = psycopg2.connect(
            dbname="security_logs",
            user="postgres",
            password="securelab123",
            host="localhost",
            port="5432"
        )
        return connection

    except psycopg2.OperationalError as e:
        print(f"[ERROR] Could not connect to database: {e}")
        print("[INFO] Make sure PostgreSQL is running:")
        print("       sudo service postgresql start")
        sys.exit(1)


def run_query(connection, sql):
    cursor = connection.cursor()
    cursor.execute(sql)
    column_names = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    cursor.close()
    return column_names, rows
