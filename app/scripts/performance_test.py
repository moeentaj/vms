# scripts/performance_test.py
import time
from app.core.database import SessionLocal
from app.services.enhanced_adapter import EnhancedCVEAdapter

async def performance_test():
    db = SessionLocal()
    adapter = EnhancedCVEAdapter(db)
    
    print("Starting performance test...")
    start_time = time.time()
    
    # Collect and enhance CVEs for the last 30 days
    stats = await adapter.collect_and_enhance_cves(30)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\nPerformance Test Results:")
    print(f"Duration: {duration:.2f} seconds")
    print(f"CVEs processed: {stats['enhanced']}")
    print(f"CVEs correlated: {stats['correlated']}")
    print(f"Processing rate: {stats['enhanced']/duration:.2f} CVEs/second")
    
    enhanced_stats = adapter.get_enhanced_cve_stats()
    print(f"\nOverall Statistics:")
    print(f"Total CVEs: {enhanced_stats['total_cves']}")
    print(f"Processing rate: {enhanced_stats['processing_rate']:.1f}%")
    print(f"Correlation rate: {enhanced_stats['correlation_rate']:.1f}%")
    
    db.close()

if __name__ == "__main__":
    import asyncio
    asyncio.run(performance_test())