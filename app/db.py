import mysql.connector
from mysql.connector.connection import MySQLConnection

from config import get_settings


def get_connection() -> MySQLConnection:
    settings = get_settings()
    return mysql.connector.connect(
        host=settings.db_host,
        port=settings.db_port,
        user=settings.db_user,
        password=settings.db_password,
        database=settings.db_name,
    )


def init_schema() -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS encryption_keys (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          logical_name VARCHAR(64) NOT NULL,
          dek_wrapped VARBINARY(512) NOT NULL,
          kek_id VARCHAR(128) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          status ENUM('active','retiring','retired') DEFAULT 'active'
        ) ENGINE=InnoDB;
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contact_form (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          first_name_enc VARBINARY(512) NOT NULL,
          middle_name_enc VARBINARY(512),
          last_name_enc VARBINARY(512) NOT NULL,
          phone_enc VARBINARY(512) NOT NULL,
          email_enc VARBINARY(512) NOT NULL,
          phone_dnc TINYINT(1) NOT NULL,
          email_dnc TINYINT(1) NOT NULL,
          key_id BIGINT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (key_id) REFERENCES encryption_keys(id)
        ) ENGINE=InnoDB;
        """
    )

    conn.commit()
    cur.close()
    conn.close()
