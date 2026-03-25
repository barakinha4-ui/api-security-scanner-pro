import os
import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

logger = logging.getLogger("app_logger")

DATABASE_URL = os.getenv("DATABASE_URL")

engine = None
AsyncSessionLocal = None
Base = declarative_base()

if DATABASE_URL:
    try:
        engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True, prepared_statement_cache_size=0)
        AsyncSessionLocal = async_sessionmaker(
            bind=engine, class_=AsyncSession, expire_on_commit=False
        )
        logger.info("Database engine initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database engine: {e}")

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if not AsyncSessionLocal:
        raise Exception("Database not configured")
    
    async with AsyncSessionLocal() as session:
        yield session

async def init_models():
    if engine:
        async with engine.begin() as conn:
            # Em prod seria melhor usar Alembic, mas pro MVP criaremos tabelas direto.
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database models initialized/verified.")
