import asyncio
from core.database import SessionLocal
from services.cve_collector import CVECollector

async def test_file_download():
    db = SessionLocal()
    collector = CVECollector()
    
    print("Testing file-based CVE collection...")
    await collector.run_service_specific_collection(db, days_back=7, use_files=True)
    
    # Check results
    from app.models.cve import CVE
    recent_cves = db.query(CVE).order_by(CVE.id.desc()).limit(5).all()
    
    print(f"Found {len(recent_cves)} recent CVEs:")
    for cve in recent_cves:
        print(f"  - {cve.cve_id}: {cve.cvss_score} ({cve.severity})")
    
    db.close()

if __name__ == "__main__":
    asyncio.run(test_file_download())