import psycopg2
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


try:
    connection = psycopg2.connect("dbname='bds' user='adm' host='localhost' password='1234'  sslmode='disable'")
except Exception as e:
    print("Error: " + e.message)

"""def insert_values(src_ip, dest_ip, confidence, remark):
	conn = sqlite3.connect(BASE_DIR + '/dashboard/db3.sqlite')
	conn.execute("INSERT INTO db_name (src, dest, breach, rem) VALUES (src_ip, dest_ip, confidence, remark)")
	conn.commit()
	conn.close()
"""
def execute_query(query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
    except psycopg2.IntegrityError as e:
        pass
    connection.commit()
    cursor.close()

def get_data(query):
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor