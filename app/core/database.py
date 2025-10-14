"""
Database connection and session management
Handles async operations and connection pooling
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from contextlib import asynccontextmanager
import structlog
from app.core.config import DatabaseConfig

logger = structlog.get_logger()

Base = declarative_base()


class DatabaseManager:
    """Manages database connections and sessions"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine = None
        self.session_factory = None
    
    async def initialize(self):
        """Initialize the database engine and session factory"""
        # Determine if we should use pool_pre_ping (not for SQLite)
        engine_args = {
            "echo": self.config.echo_sql,
        }
        
        # Only add pooling options for non-SQLite databases
        if "sqlite" not in self.config.database_url:
            engine_args.update({
                "pool_size": self.config.pool_size,
                "max_overflow": self.config.max_overflow,
                "pool_timeout": self.config.pool_timeout,
                "pool_pre_ping": True,  # Verify connections are alive
            })
        
        # Create async engine with connection pooling
        self.engine = create_async_engine(
            self.config.database_url,
            **engine_args
        )
        
        # Create session factory
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database initialized", url=self.config.database_url)
    
    @asynccontextmanager
    async def get_session(self):
        """Provide a transactional scope for database operations"""
        async with self.session_factory() as session:
            try:
                yield session
                
                # Check if session is in a valid state before committing
                if session.is_active and not session.in_transaction():
                    # No transaction to commit
                    pass
                elif session.is_active:
                    # Session is active and has a transaction
                    await session.commit()
                else:
                    # Session is not active (already rolled back or closed)
                    logger.warning("Session not active at commit time, skipping commit")
            
            except Exception as e:
                # Check if session needs rollback
                if session.is_active:
                    try:
                        await session.rollback()
                        logger.debug("Session rolled back after exception", error=str(e))
                    except Exception as rollback_error:
                        logger.error("Failed to rollback session", error=str(rollback_error))
                else:
                    logger.debug("Session already rolled back", error=str(e))
                
                raise
            
            finally:
                # Always try to close the session
                try:
                    await session.close()
                except Exception as close_error:
                    logger.error("Failed to close session", error=str(close_error))
    
    async def close(self):
        """Close all database connections"""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connections closed")