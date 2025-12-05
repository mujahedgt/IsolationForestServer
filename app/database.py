import mysql.connector
from mysql.connector import Error
from app.config import settings


class Database:
    def __init__(self):
        self.connection = None

    def connect(self):
        """Establish connection to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=settings.MYSQL_HOST,
                port=settings.MYSQL_PORT,
                user=settings.MYSQL_USER,
                password=settings.MYSQL_PASSWORD,
                database=settings.MYSQL_DATABASE
            )
            if self.connection.is_connected():
                print(f"Successfully connected to MySQL database: {settings.MYSQL_DATABASE}")
            return self.connection
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return None

    def disconnect(self):
        """Close the database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection closed")

    def execute_query(self, query, params=None):
        """Execute a query that modifies data (INSERT, UPDATE, DELETE)"""
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(query, params or ())
            self.connection.commit()
            return cursor
        except Error as e:
            print(f"Error executing query: {e}")
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def fetch_one(self, query, params=None):
        """Fetch a single row from the database"""
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(query, params or ())
            return cursor.fetchone()
        except Error as e:
            print(f"Error fetching data: {e}")
            raise
        finally:
            cursor.close()

    def fetch_all(self, query, params=None):
        """Fetch all matching rows from the database"""
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(query, params or ())
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching data: {e}")
            raise
        finally:
            cursor.close()


# Global database instance (to be initialized at startup)
db = Database()