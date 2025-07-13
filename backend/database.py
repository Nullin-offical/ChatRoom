"""
Database utilities for ChatRoom application
Provides thread-safe database connections with WAL mode and robust error handling
"""

import sqlite3
import os
import time
import logging
from typing import Callable, Any

db_logger = logging.getLogger('database')

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')

# --- Core DB Connection ---
def get_db() -> sqlite3.Connection:
    """
    Get a SQLite connection with WAL mode and thread safety.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    return conn

# --- Context Manager ---
class DatabaseContext:
    """
    Context manager for safe DB access (auto-commit/rollback/close).
    Usage: with DatabaseContext() as conn:
    """
    def __enter__(self) -> sqlite3.Connection:
        self.conn = get_db()
        return self.conn
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type:
                self.conn.rollback()
            else:
                self.conn.commit()
        finally:
            self.conn.close()

# --- Retry Decorator ---
def with_db_retry(fn: Callable[..., Any], *args, **kwargs) -> Any:
    """
    Retry a DB operation on 'database is locked' errors (exponential backoff).
    Usage: with_db_retry(lambda: ...)
    """
    max_retries = 5
    delay = 0.2
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                db_logger.warning(f"Database locked, retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                delay *= 2
                continue
            db_logger.error(f"Database operation failed after {max_retries} attempts: {e}")
            raise
        except Exception as e:
            db_logger.error(f"Database operation error: {e}")
            raise 