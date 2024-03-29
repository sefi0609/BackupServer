import sqlite3


class DataBase:
    """
    DataBase class - handles the database
    create, save rows to tables, and update needed fields
    """
    def __init__(self):
        self.name = 'server.db'
        self.clients_columns = 5
        self.update_verified = 4
        self.update_aes = 3
        self.update_last = 2

    def create_database(self):
        """
        create a database as described in maman15
        need to use only one time to create the database
        """
        conn = sqlite3.connect(self.name)
        conn.text_factory = bytes

        conn.executescript("""
        CREATE TABLE clients(
        ID blob NOT NULL PRIMARY KEY,
        Name text,
        PublicKey blob,
        LastSeen NUMERIC,
        AESkey blob
        );
        CREATE TABLE files(
        ID text,
        FileName text,
        PathName text,
        Verified NUMERIC,
        PRIMARY KEY (ID, FileName)
        FOREIGN KEY(ID) REFERENCES clients(ID)
        );""")

        conn.commit()
        conn.close()

    def get_tables(self):
        """ get clients and files tables from database """
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute("""SELECT * FROM clients""")
                clients_table = cur.fetchall()
                cur.execute("""SELECT * FROM files""")
                files_table = cur.fetchall()
            return clients_table, files_table
        except Exception as e:
            print(f'Exception at get_tables(): {e}')

    def get_files_table(self):
        """ get just the files table from database """
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute("""SELECT * FROM files""")
                files_table = cur.fetchall()
            return files_table
        except Exception as e:
            print(f'Exception at get_files_table(): {e}')

    def get_clients_table(self):
        """ get just the clients table from database """
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute("""SELECT * FROM clients""")
                clients_table = cur.fetchall()
            return clients_table
        except Exception as e:
            print(f'Exception at get_clients_table(): {e}')

    def save_to_clients(self, *argv):
        """ save a new row to clients table """
        if len(argv) != self.clients_columns:
            raise Exception('Need 5 fields for clients table')
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute(f"INSERT INTO clients VALUES(?, ? ,? ,? ,?)", argv)
                conn.commit()
                print('Saved to client table successfully')
        except Exception as e:
            print(f'Exception at save_to_clients(): {e}')
            raise e

    def save_to_files(self, client_id, file_name, file_path, verified, last_seen):
        """ save a new row to files table """
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute(f"INSERT INTO files VALUES(?, ? ,? ,?)", (client_id, file_name, file_path, verified))
                cur.execute(f"UPDATE clients SET lastseen = ? WHERE id = ?", (last_seen, client_id))
                conn.commit()
                print('Saved to files table successfully')
                print('Client table updated successfully')
        except Exception as e:
            print(f'Exception at save_to_files(): {e}')
            raise e

    def update_aes_key(self, *argv):
        """ update aes key and last seen in clients table """
        if len(argv) != self.update_aes:
            raise Exception('Need 3 fields to update aes key on clients table')
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute(f"UPDATE clients SET lastseen = ?, AESkey = ? WHERE id = ?", argv)
                conn.commit()
                print('Client table updated successfully')
        except Exception as e:
            print(f'Exception at update_aes_key(): {e}')

    def update_files(self, verified, client_id, file_name, last_seen):
        """ update verified field in files table """
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute(f"UPDATE files SET verified = ? WHERE id = ? and filename = ?",
                            (verified, client_id, file_name))
                cur.execute(f"UPDATE clients SET lastseen = ? WHERE id = ?", (last_seen, client_id))
                conn.commit()
                print('Files table updated successfully')
                print('Client table updated successfully')
        except Exception as e:
            print(f'Exception at update_files(): {e}')
            raise e
            
    def update_last_seen(self, *argv):
        """ update last seen at clients table """
        if len(argv) != self.update_last:
            raise Exception('Need 2 fields to update aes key on clients table')
        try:
            with sqlite3.connect(self.name) as conn:
                cur = conn.cursor()
                cur.execute(f"UPDATE clients SET lastseen = ? WHERE id = ?", argv)
                conn.commit()
                print('Client table updated successfully')
        except Exception as e:
            print(f'Exception at update_last_seen(): {e}')
