"""
db_manager.py — Manages MySQL database operations for CyberShield.

Handles:
    - Creating the 'threats' table if it doesn't exist
    - Inserting detected threats
    - Retrieving threat history
    - Clearing all records
"""

import mysql.connector
from mysql.connector import Error
from utils.logger import get_logger

logger = get_logger(__name__)

# Default MySQL connection configuration
DEFAULT_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",         # ← Set your MySQL root password here
    "database": "cybershield"
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS threats (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    timestamp       VARCHAR(50)   NOT NULL,
    ip_address      VARCHAR(45)   NOT NULL,
    threat_type     VARCHAR(100)  NOT NULL,
    occurrences     INT           NOT NULL,
    risk_level      VARCHAR(10)   NOT NULL,
    detected_at     DATETIME      DEFAULT CURRENT_TIMESTAMP
)
"""

INSERT_THREAT_SQL = """
INSERT INTO threats (timestamp, ip_address, threat_type, occurrences, risk_level)
VALUES (%s, %s, %s, %s, %s)
"""

SELECT_ALL_SQL = """
SELECT id, timestamp, ip_address, threat_type, occurrences, risk_level, detected_at
FROM threats
ORDER BY detected_at DESC
"""

DELETE_ALL_SQL = "DELETE FROM threats"


class DBManager:
    """
    MySQL database manager for storing and retrieving threat records.

    Usage:
        db = DBManager()
        if db.connect():
            db.create_table()
            db.insert_threat(threat_dict)
            rows = db.get_all_threats()
            db.close()
    """

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.connection = None

    def connect(self):
        """
        Establish a connection to MySQL.

        Returns:
            bool: True if connection succeeded, False otherwise.
        """
        try:
            self.connection = mysql.connector.connect(**self.config)

            if self.connection.is_connected():
                logger.info("Connected to MySQL database '%s'", self.config["database"])
                return True

        except Error as e:
            logger.error("MySQL connection failed: %s", e)

        return False

    def create_table(self):
        """Create the 'threats' table if it doesn't already exist."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(CREATE_TABLE_SQL)
            self.connection.commit()
            cursor.close()

            logger.info("Table 'threats' is ready.")

        except Error as e:
            logger.error("Failed to create table: %s", e)

    def insert_threat(self, threat):
        """
        Insert a single detected threat into the database.

        Args:
            threat (dict): Must contain keys:
                'timestamp' (or first item from 'events'),
                'ip', 'threat', 'count', 'risk'.
        """
        try:
            cursor = self.connection.cursor()

            # Use first event timestamp, or the threat-level timestamp
            timestamp = threat.get("timestamp", "")
            if not timestamp and threat.get("events"):
                timestamp = threat["events"][0]

            values = (
                timestamp,
                threat["ip"],
                threat["threat"],
                threat["count"],
                threat["risk"],
            )

            cursor.execute(INSERT_THREAT_SQL, values)
            self.connection.commit()
            cursor.close()

            logger.info("Inserted threat: IP=%s, Type=%s", threat["ip"], threat["threat"])

        except Error as e:
            logger.error("Failed to insert threat: %s", e)

    def insert_threats(self, threats):
        """Insert multiple threats at once."""
        for threat in threats:
            self.insert_threat(threat)

    def get_all_threats(self):
        """
        Retrieve all threat records from the database.

        Returns:
            list[dict]: List of threat records.
        """
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(SELECT_ALL_SQL)
            rows = cursor.fetchall()
            cursor.close()

            logger.info("Retrieved %d threat records.", len(rows))
            return rows

        except Error as e:
            logger.error("Failed to fetch threats: %s", e)
            return []

    def clear_all(self):
        """Delete all records from the threats table."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(DELETE_ALL_SQL)
            self.connection.commit()
            cursor.close()

            logger.info("Cleared all threat records.")

        except Error as e:
            logger.error("Failed to clear threats: %s", e)

    def close(self):
        """Close the MySQL connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.info("MySQL connection closed.")
