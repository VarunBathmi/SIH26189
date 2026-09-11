import logging
from typing import Optional
from neo4j import GraphDatabase, Driver
from app.config import settings

logger = logging.getLogger(__name__)

_driver: Optional[Driver] = None

def get_neo4j_driver() -> Optional[Driver]:
    """
    Get or initialize singleton Neo4j driver connection.
    Returns None if Neo4j is not reachable.
    """
    global _driver
    if _driver is None:
        try:
            _driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=5.0
            )
            # Verify connectivity
            _driver.verify_connectivity()
            logger.info("Connected to Neo4j graph database.")
        except Exception as e:
            logger.warning(f"Neo4j connection failed ({settings.NEO4J_URI}): {e}. Dual-engine will utilize NetworkX.")
            _driver = None
    return _driver

def is_neo4j_available() -> bool:
    """Check if Neo4j is currently online and healthy."""
    driver = get_neo4j_driver()
    if driver is None:
        return False
    try:
        driver.verify_connectivity()
        return True
    except Exception:
        return False

def close_neo4j_driver():
    """Close Neo4j connection on shutdown."""
    global _driver
    if _driver is not None:
        try:
            _driver.close()
            logger.info("Closed Neo4j driver connection.")
        except Exception as e:
            logger.error(f"Error closing Neo4j driver: {e}")
        _driver = None
