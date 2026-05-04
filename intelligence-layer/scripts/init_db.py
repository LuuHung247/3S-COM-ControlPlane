#!/usr/bin/env python3
"""Create Postgres tables."""
import asyncio
import sys
sys.path.insert(0, ".")

from src.config import get_settings
from src.storage.postgres import PostgresStore


async def main():
    settings = get_settings()
    store = PostgresStore(settings.postgres_url)
    await store.connect()
    print("Database tables created successfully.")
    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
