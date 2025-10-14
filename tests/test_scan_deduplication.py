"""
Test scan deduplication and error recovery
"""

import asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# This is a minimal test to verify deduplication logic works
# Full integration tests would require more setup


async def test_dedup_manager_initialization():
    """Test that DeduplicationManager can initialize from database"""
    from app.scanner.dedup import DeduplicationManager
    from app.models.domain import Domain, Subdomain
    from app.core.database import Base
    
    # Create in-memory database
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with session_factory() as session:
        # Create test domain
        domain = Domain(domain="example.com", created_at=datetime.utcnow())
        session.add(domain)
        await session.flush()
        
        # Add some subdomains
        for i in range(5):
            subdomain = Subdomain(
                subdomain=f"sub{i}.example.com",
                domain_id=domain.id,
                discovered_at=datetime.utcnow(),
                discovery_method="passive",
                discovery_sources='["ct_logs"]',
                recursion_level=0
            )
            session.add(subdomain)
        
        await session.commit()
        
        # Test dedup manager initialization
        dedup_manager = DeduplicationManager()
        count = await dedup_manager.initialize_from_database(session, domain.id)
        
        # Verify
        assert count > 0, "Should have loaded records"
        assert dedup_manager.initialized_for_domain == domain.id
        
        # Verify bloom filter has the subdomains
        for i in range(5):
            subdomain_name = f"sub{i}.example.com"
            # Should return False because they're already in the bloom filter
            is_new = dedup_manager.add_subdomain(subdomain_name, "test")
            assert not is_new, f"{subdomain_name} should already be in bloom filter"
        
        # New subdomain should return True
        is_new = dedup_manager.add_subdomain("new.example.com", "test")
        assert is_new, "New subdomain should be marked as new"
    
    await engine.dispose()
    print("✓ Deduplication manager initialization test passed")


async def test_upsert_subdomain():
    """Test that subdomain upsert logic works"""
    from app.scanner.vertical.passive import PassiveEnumerator
    from app.scanner.rate_limiter import ScanProfileRateLimiter
    from app.scanner.dedup import DeduplicationManager
    from app.models.domain import Domain, Subdomain
    from app.core.database import Base
    from app.core.config import Config
    
    # Create in-memory database
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with session_factory() as session:
        # Create test domain
        domain = Domain(domain="example.com", created_at=datetime.utcnow())
        session.add(domain)
        await session.flush()
        
        # Create PassiveEnumerator
        config = Config()
        rate_limiter = ScanProfileRateLimiter("normal")
        dedup_manager = DeduplicationManager()
        passive_enum = PassiveEnumerator(config, rate_limiter, dedup_manager)
        
        # First upsert (should insert)
        result1 = await passive_enum._upsert_subdomain(
            session,
            "test.example.com",
            domain.id,
            "passive",
            ["ct_logs"],
            0
        )
        await session.commit()
        assert result1 is True, "First insert should return True"
        
        # Second upsert (should update)
        result2 = await passive_enum._upsert_subdomain(
            session,
            "test.example.com",
            domain.id,
            "passive",
            ["subfinder"],
            0
        )
        await session.commit()
        assert result2 is False, "Second insert should return False (updated)"
        
        # Verify sources were merged
        from sqlalchemy import select
        result = await session.execute(
            select(Subdomain).where(
                Subdomain.subdomain == "test.example.com",
                Subdomain.domain_id == domain.id
            )
        )
        subdomain = result.scalar_one()
        
        import json
        sources = json.loads(subdomain.discovery_sources)
        assert "ct_logs" in sources, "Should have ct_logs source"
        assert "subfinder" in sources, "Should have subfinder source"
        assert len(sources) == 2, "Should have exactly 2 sources"
    
    await engine.dispose()
    print("✓ Subdomain upsert test passed")


if __name__ == "__main__":
    print("Running deduplication tests...")
    asyncio.run(test_dedup_manager_initialization())
    asyncio.run(test_upsert_subdomain())
    print("\n✅ All tests passed!")

