import sqlite3
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))



def insert_values(src_ip, dest_ip, confidence, remark):
	conn = sqlite3.connect(BASE_DIR + '/dashboard/db3.sqlite')
	conn.execute("INSERT INTO db_name (src, dest, breach, rem) VALUES (src_ip, dest_ip, confidence, remark)")
	conn.commit()
	conn.close()

def execute_query(query):
    conn = sqlite3.connect(BASE_DIR + '/adashboard/db3.sqlite')
    conn.execute(query)
    conn.commit()
    conn.close()