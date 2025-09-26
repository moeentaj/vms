from pydantic_settings import BaseSettings
from typing import Optional, List
from pydantic import    validator
import os

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
    APP_NAME: str = "VULN MGMT"
    
    # Security settings
    SECRET_KEY: str = "your-secret-key-here-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # NIST NVD API settings
    NVD_API_KEY: Optional[str] = None
    NIST_RATE_LIMIT_WITH_KEY: int = 50  # requests per second with API key
    NIST_RATE_LIMIT_WITHOUT_KEY: int = 5  # requests per second without API key
    
    # Enhanced CPE Dictionary and Matching settings
    CPE_CACHE_DIR: str = "./cache/cpe"
    CPE_INCLUDE_DEPRECATED: bool = False
    CPE_AUTO_REFRESH_HOURS: int = 24
    CPE_SEARCH_TIMEOUT_SECONDS: int = 30
    CPE_MAX_SEARCH_RESULTS: int = 100
    CPE_CORRELATION_CONFIDENCE_THRESHOLD: float = 0.7
    
    # CPE Data Feed URLs (NIST CPE 2.0)
    CPE_DICTIONARY_URL: str = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
    CPE_MATCH_URL: str = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"
    
    # CVE Data Feed settings
    CVE_DATA_FEED_BASE_URL: str = "https://nvd.nist.gov/feeds/json/cve/2.0"
    CVE_CACHE_DIR: str = "./cache/cve"
    CVE_AUTO_REFRESH_HOURS: int = 6
    CVE_BATCH_SIZE: int = 1000
    
    # Asset correlation settings
    ASSET_CORRELATION_ENABLED: bool = True
    ASSET_CORRELATION_BATCH_SIZE: int = 100
    ASSET_CORRELATION_TIMEOUT_MINUTES: int = 30
    
    # Background task settings
    ENABLE_BACKGROUND_INGESTION: bool = True
    BACKGROUND_TASK_INTERVAL_MINUTES: int = 60
    MAX_CONCURRENT_CORRELATIONS: int = 10
    
    # Cache management settings
    ENABLE_REDIS_CACHE: bool = False
    REDIS_URL: Optional[str] = None
    CACHE_TTL_SECONDS: int = 3600
    
    # Performance optimization settings
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    HTTP_TIMEOUT_SECONDS: int = 300
    ASYNC_CONCURRENCY_LIMIT: int = 50
    
    # Monitoring and alerting
    ENABLE_METRICS: bool = False
    METRICS_PORT: int = 9090
    ALERT_WEBHOOK_URL: Optional[str] = None
    
    # AI/ML Enhancement settings (for future use)
    ENABLE_AI_ENHANCEMENT: bool = False
    AI_MODEL_PATH: Optional[str] = None
    AI_BATCH_SIZE: int = 50
    
    # Data retention settings
    CVE_RETENTION_DAYS: int = 730  # 2 years
    CORRELATION_LOG_RETENTION_DAYS: int = 90
    METRICS_RETENTION_DAYS: int = 30
    
    # Security scanning settings
    ENABLE_VULNERABILITY_SCANNING: bool = True
    SCAN_INTERVAL_HOURS: int = 24
    SCAN_TIMEOUT_MINUTES: int = 60
    
    # Export and reporting settings
    ENABLE_EXPORTS: bool = True
    EXPORT_FORMATS: List[str] = ["json", "csv", "pdf"]
    MAX_EXPORT_RECORDS: int = 10000
    
    # Integration settings
    ENABLE_SLACK_NOTIFICATIONS: bool = False
    SLACK_WEBHOOK_URL: Optional[str] = None
    ENABLE_EMAIL_NOTIFICATIONS: bool = False
    SMTP_SERVER: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    
    @validator('CPE_CACHE_DIR', 'CVE_CACHE_DIR')
    def validate_cache_dirs(cls, v):
        """Ensure cache directories exist"""
        if v:
            os.makedirs(v, exist_ok=True)
        return v
    
    @validator('CPE_CORRELATION_CONFIDENCE_THRESHOLD')
    def validate_confidence_threshold(cls, v):
        """Ensure confidence threshold is between 0 and 1"""
        if not 0 <= v <= 1:
            raise ValueError('Confidence threshold must be between 0 and 1')
        return v
    
    @validator('LOG_LEVEL')
    def validate_log_level(cls, v):
        """Ensure log level is valid"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Log level must be one of: {valid_levels}')
        return v.upper()
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        
        # Environment variable mappings
        fields = {
            'DATABASE_URL': {'env': ['DATABASE_URL', 'DB_URL']},
            'NVD_API_KEY': {'env': ['NVD_API_KEY', 'NIST_API_KEY']},
            'SECRET_KEY': {'env': ['SECRET_KEY', 'JWT_SECRET']},
            'REDIS_URL': {'env': ['REDIS_URL', 'CACHE_URL']},
        }

# Global settings instance
settings = Settings()

# Helper functions for common configuration tasks

def get_cpe_cache_path(filename: str = "") -> str:
    """Get full path for CPE cache file"""
    cache_dir = os.path.abspath(settings.CPE_CACHE_DIR)
    return os.path.join(cache_dir, filename) if filename else cache_dir

def get_cve_cache_path(filename: str = "") -> str:
    """Get full path for CVE cache file"""
    cache_dir = os.path.abspath(settings.CVE_CACHE_DIR)
    return os.path.join(cache_dir, filename) if filename else cache_dir

def get_database_config() -> dict:
    """Get database configuration for SQLAlchemy"""
    return {
        'url': settings.DATABASE_URL,
        'pool_size': settings.DATABASE_POOL_SIZE,
        'max_overflow': settings.DATABASE_MAX_OVERFLOW,
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'echo': settings.DEBUG
    }

def get_http_client_config() -> dict:
    """Get HTTP client configuration"""
    return {
        'timeout': settings.HTTP_TIMEOUT_SECONDS,
        'limits': {
            'max_connections': settings.ASYNC_CONCURRENCY_LIMIT,
            'max_keepalive_connections': 10
        },
        'headers': {
            'User-Agent': f'{settings.APP_NAME}/1.0'
        }
    }

def get_nist_api_config() -> dict:
    """Get NIST API configuration"""
    config = {
        'base_url': 'https://services.nvd.nist.gov/rest/json',
        'rate_limit': settings.NIST_RATE_LIMIT_WITHOUT_KEY,
        'timeout': settings.HTTP_TIMEOUT_SECONDS,
        'headers': {}
    }
    
    if settings.NVD_API_KEY:
        config['headers']['apiKey'] = settings.NVD_API_KEY
        config['rate_limit'] = settings.NIST_RATE_LIMIT_WITH_KEY
    
    return config

def get_cpe_ingestion_config() -> dict:
    """Get CPE data ingestion configuration"""
    return {
        'dictionary_url': settings.CPE_DICTIONARY_URL,
        'match_url': settings.CPE_MATCH_URL,
        'cache_dir': settings.CPE_CACHE_DIR,
        'include_deprecated': settings.CPE_INCLUDE_DEPRECATED,
        'auto_refresh_hours': settings.CPE_AUTO_REFRESH_HOURS,
        'search_timeout': settings.CPE_SEARCH_TIMEOUT_SECONDS,
        'max_results': settings.CPE_MAX_SEARCH_RESULTS,
        'correlation_threshold': settings.CPE_CORRELATION_CONFIDENCE_THRESHOLD
    }

def get_correlation_config() -> dict:
    """Get vulnerability correlation configuration"""
    return {
        'enabled': settings.ASSET_CORRELATION_ENABLED,
        'batch_size': settings.ASSET_CORRELATION_BATCH_SIZE,
        'timeout_minutes': settings.ASSET_CORRELATION_TIMEOUT_MINUTES,
        'confidence_threshold': settings.CPE_CORRELATION_CONFIDENCE_THRESHOLD,
        'max_concurrent': settings.MAX_CONCURRENT_CORRELATIONS
    }

def should_enable_feature(feature_name: str) -> bool:
    """Check if a feature should be enabled based on configuration"""
    feature_flags = {
        'ai_enhancement': settings.ENABLE_AI_ENHANCEMENT,
        'background_ingestion': settings.ENABLE_BACKGROUND_INGESTION,
        'vulnerability_scanning': settings.ENABLE_VULNERABILITY_SCANNING,
        'redis_cache': settings.ENABLE_REDIS_CACHE,
        'metrics': settings.ENABLE_METRICS,
        'exports': settings.ENABLE_EXPORTS,
        'slack_notifications': settings.ENABLE_SLACK_NOTIFICATIONS,
        'email_notifications': settings.ENABLE_EMAIL_NOTIFICATIONS,
        'asset_correlation': settings.ASSET_CORRELATION_ENABLED
    }
    
    return feature_flags.get(feature_name, False)

def get_notification_config() -> dict:
    """Get notification configuration"""
    return {
        'slack': {
            'enabled': settings.ENABLE_SLACK_NOTIFICATIONS,
            'webhook_url': settings.SLACK_WEBHOOK_URL
        },
        'email': {
            'enabled': settings.ENABLE_EMAIL_NOTIFICATIONS,
            'smtp_server': settings.SMTP_SERVER,
            'smtp_port': settings.SMTP_PORT,
            'username': settings.SMTP_USERNAME,
            'password': settings.SMTP_PASSWORD
        },
        'alert_webhook': settings.ALERT_WEBHOOK_URL
    }

def get_export_config() -> dict:
    """Get export configuration"""
    return {
        'enabled': settings.ENABLE_EXPORTS,
        'formats': settings.EXPORT_FORMATS,
        'max_records': settings.MAX_EXPORT_RECORDS
    }

# Validation helpers
def validate_environment() -> list:
    """Validate environment configuration and return any issues"""
    issues = []
    
    # Required settings
    if not settings.SECRET_KEY or settings.SECRET_KEY == "your-secret-key-here-change-in-production":
        issues.append("SECRET_KEY must be set to a secure value in production")
    
    if not settings.DATABASE_URL:
        issues.append("DATABASE_URL must be configured")
    
    # Cache directory validation
    try:
        os.makedirs(settings.CPE_CACHE_DIR, exist_ok=True)
        os.makedirs(settings.CVE_CACHE_DIR, exist_ok=True)
    except Exception as e:
        issues.append(f"Cannot create cache directories: {e}")
    
    # NIST API key recommendation
    if not settings.NVD_API_KEY:
        issues.append("NVD_API_KEY not set - using public rate limits (slower)")
    
    # Redis configuration if enabled
    if settings.ENABLE_REDIS_CACHE and not settings.REDIS_URL:
        issues.append("REDIS_URL must be set when ENABLE_REDIS_CACHE is True")
    
    # SMTP configuration if email notifications enabled
    if settings.ENABLE_EMAIL_NOTIFICATIONS:
        if not all([settings.SMTP_SERVER, settings.SMTP_USERNAME, settings.SMTP_PASSWORD]):
            issues.append("SMTP configuration incomplete for email notifications")
    
    # Slack configuration if enabled
    if settings.ENABLE_SLACK_NOTIFICATIONS and not settings.SLACK_WEBHOOK_URL:
        issues.append("SLACK_WEBHOOK_URL must be set when ENABLE_SLACK_NOTIFICATIONS is True")
    
    return issues

# Development/testing helpers
def get_test_config() -> dict:
    """Get configuration for testing environment"""
    return {
        'database_url': 'sqlite:///./test.db',
        'debug': True,
        'log_level': 'DEBUG',
        'cpe_cache_dir': './test_cache/cpe',
        'cve_cache_dir': './test_cache/cve',
        'enable_background_ingestion': False,
        'enable_metrics': False,
        'correlation_batch_size': 10,
        'max_concurrent_correlations': 2
    }

def override_settings_for_testing(**kwargs):
    """Temporarily override settings for testing"""
    original_values = {}
    
    for key, value in kwargs.items():
        if hasattr(settings, key.upper()):
            original_values[key.upper()] = getattr(settings, key.upper())
            setattr(settings, key.upper(), value)
    
    return original_values

def restore_settings(original_values: dict):
    """Restore original settings after testing"""
    for key, value in original_values.items():
        setattr(settings, key, value)

# Environment-specific configurations
class DevelopmentSettings(Settings):
    """Development environment settings"""
    DEBUG: bool = True
    LOG_LEVEL: str = "DEBUG"
    ENABLE_METRICS: bool = True
    CPE_AUTO_REFRESH_HOURS: int = 1  # More frequent refresh for development
    
class ProductionSettings(Settings):
    """Production environment settings"""
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    ENABLE_METRICS: bool = True
    ENABLE_REDIS_CACHE: bool = True
    DATABASE_POOL_SIZE: int = 50
    DATABASE_MAX_OVERFLOW: int = 50
    
class TestingSettings(Settings):
    """Testing environment settings"""
    DEBUG: bool = True
    LOG_LEVEL: str = "WARNING"  # Reduce noise in tests
    DATABASE_URL: str = "sqlite:///./test.db"
    CPE_CACHE_DIR: str = "./test_cache/cpe"
    CVE_CACHE_DIR: str = "./test_cache/cve"
    ENABLE_BACKGROUND_INGESTION: bool = False
    ASSET_CORRELATION_BATCH_SIZE: int = 10

# Factory function to get environment-specific settings
def get_settings(environment: str = None) -> Settings:
    """Get settings based on environment"""
    if environment is None:
        environment = os.getenv('ENVIRONMENT', 'development').lower()
    
    settings_map = {
        'development': DevelopmentSettings,
        'production': ProductionSettings,
        'testing': TestingSettings
    }
    
    settings_class = settings_map.get(environment, Settings)
    return settings_class()

# Export commonly used settings
__all__ = [
    'Settings',
    'settings',
    'get_cpe_cache_path',
    'get_cve_cache_path',
    'get_database_config',
    'get_http_client_config',
    'get_nist_api_config',
    'get_cpe_ingestion_config',
    'get_correlation_config',
    'should_enable_feature',
    'get_notification_config',
    'get_export_config',
    'validate_environment',
    'get_test_config',
    'override_settings_for_testing',
    'restore_settings',
    'get_settings',
    'DevelopmentSettings',
    'ProductionSettings',
    'TestingSettings'
]