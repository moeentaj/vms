from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://vsadmin:adminVS2025@db:5432/vulndb"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # AI Models
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    DEFAULT_MODEL: str = "llama3.1:8b"
    
    # ChromaDB
    CHROMA_DB_PATH: str = "./chroma_db"
    
    # CVE Sources
    NVD_API_KEY: Optional[str] = None
    
    # Application
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Enhanced CVE settings
    CORRELATION_CONFIDENCE_THRESHOLD: float = 0.7
    MAX_CORRELATIONS_PER_CVE: int = 50
    ENABLE_AI_CORRELATION: bool = True
    CORRELATION_CACHE_TTL: int = 3600  # 1 hour
    
    # NVD API settings
    NVD_RATE_LIMIT_DELAY: int = 6  # seconds between requests
    NVD_MAX_RESULTS_PER_PAGE: int = 100
    
    # CPE Integration Settings (Updated for JSON API)
    CPE_CACHE_DIR: str = "./cpe_cache"
    CPE_AUTO_INGEST: bool = True
    CPE_INGEST_SCHEDULE: str = "0 2 * * 0"  # Weekly on Sunday at 2 AM
    CPE_MIN_CONFIDENCE: float = 0.6
    CPE_AUTO_CREATE_THRESHOLD: float = 0.8
    
    # NIST API Configuration (Updated for new JSON endpoints)
    NIST_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json"
    NIST_CPE_API_URL: str = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    NIST_CVE_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # NVD API Key (optional but recommended for higher rate limits)
    # Get your API key from: https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY: Optional[str] = "b69b19ae-7267-4d2c-8820-2421aa2d1ed2"
    
    # Rate limiting for NIST API (with API key: 50 requests per 30 seconds, without: 5 per 30 seconds)
    NIST_RATE_LIMIT_WITH_KEY: int = 50  # requests per 30 seconds
    NIST_RATE_LIMIT_WITHOUT_KEY: int = 5  # requests per 30 seconds
    NIST_RATE_LIMIT_WINDOW: int = 30  # seconds
    
    # CPE data freshness
    CPE_CACHE_EXPIRY_HOURS: int = 24  # How often to refresh CPE data
    CPE_BATCH_SIZE: int = 2000  # Number of CPE entries to fetch per request
    
    # Enhanced filtering for CPE products
    CPE_INCLUDE_DEPRECATED: bool = False
    CPE_MIN_PRODUCT_VERSIONS: int = 2  # Minimum versions to consider for suggestions
    
    class Config:
        env_file = ".env"

settings = Settings()