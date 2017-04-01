import sqlite3

def insert_values(src_ip, dest_ip, confidence, remark):
	conn = sqlite3.connect('db3.sqlite')
	conn.execute("INSERT INTO db_name (src, dest, breach, rem) VALUES (src_ip, dest_ip, confidence, remark)")
	conn.commit()
	conn.close()

def execute_query(query)
    conn = sqlite3.connect('db3.sqlite')
    conn.execute(query)
    conn.commit()
    conn.close()