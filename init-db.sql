-- init-db.sql
-- Database initialization script for Vulnerability Management System

-- Create database user and set permissions
\echo 'Starting database initialization...'

-- Create the vsadmin user and database
DO $$ 
BEGIN
    -- Create the application database user if it doesn't exist
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'vsadmin') THEN
        CREATE USER vsadmin WITH PASSWORD 'adminVS2025';
        RAISE NOTICE 'Created user: vsadmin';
    ELSE
        RAISE NOTICE 'User vsadmin already exists';
    END IF;
EXCEPTION
    WHEN others THEN
        RAISE NOTICE 'Error creating user: %', SQLERRM;
END $$;

-- Grant database-level permissions
GRANT CONNECT ON DATABASE vulndb TO vsadmin;
GRANT USAGE ON SCHEMA public TO vsadmin;
GRANT CREATE ON SCHEMA public TO vsadmin;

-- Grant permissions on existing objects
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vsadmin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vsadmin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO vsadmin;

-- Grant permissions on future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vsadmin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO vsadmin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO vsadmin;

-- Create extensions for enhanced functionality
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

\echo '✅ Database user vsadmin configured successfully'
\echo '🔐 Password: adminVS2025'
\echo '🔗 Connection: postgresql://vsadmin:adminVS2025@db:5432/vulndb (Docker)'
\echo '🔗 Connection: postgresql://vsadmin:adminVS2025@localhost:5432/vulndb (Local)'
\echo ''
\echo 'Database initialization complete!'

-- Create enum types for consistency
DO $$ BEGIN
    CREATE TYPE assignment_status AS ENUM (
        'assigned',
        'in_progress', 
        'under_review',
        'completed',
        'closed'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE assignment_priority AS ENUM (
        'low',
        'medium',
        'high', 
        'critical',
        'urgent'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE user_role AS ENUM (
        'admin',
        'manager',
        'analyst',
        'viewer'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE asset_environment AS ENUM (
        'production',
        'staging',
        'development',
        'testing'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE asset_criticality AS ENUM (
        'low',
        'medium',
        'high',
        'critical'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE cve_severity AS ENUM (
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create a function to calculate risk score
CREATE OR REPLACE FUNCTION calculate_combined_risk_score(
    cvss_score NUMERIC,
    ai_risk_score NUMERIC,
    asset_criticality TEXT,
    asset_environment TEXT
) RETURNS NUMERIC AS $$
DECLARE
    base_score NUMERIC := COALESCE(cvss_score, 5.0);
    ai_score NUMERIC := COALESCE(ai_risk_score, 5.0);
    criticality_multiplier NUMERIC := 1.0;
    environment_multiplier NUMERIC := 1.0;
    combined_score NUMERIC;
BEGIN
    -- Set criticality multiplier
    CASE LOWER(asset_criticality)
        WHEN 'low' THEN criticality_multiplier := 0.8;
        WHEN 'medium' THEN criticality_multiplier := 1.0;
        WHEN 'high' THEN criticality_multiplier := 1.3;
        WHEN 'critical' THEN criticality_multiplier := 1.5;
        ELSE criticality_multiplier := 1.0;
    END CASE;
    
    -- Set environment multiplier
    CASE LOWER(asset_environment)
        WHEN 'development' THEN environment_multiplier := 0.5;
        WHEN 'testing' THEN environment_multiplier := 0.6;
        WHEN 'staging' THEN environment_multiplier := 0.8;
        WHEN 'production' THEN environment_multiplier := 1.5;
        ELSE environment_multiplier := 1.0;
    END CASE;
    
    -- Calculate combined score (max 10.0)
    combined_score := LEAST(((base_score + ai_score) / 2) * criticality_multiplier * environment_multiplier, 10.0);
    
    RETURN ROUND(combined_score, 2);
END;
$$ LANGUAGE plpgsql;

-- Create a function to validate CVE ID format
CREATE OR REPLACE FUNCTION is_valid_cve_id(cve_id TEXT) 
RETURNS BOOLEAN AS $$
BEGIN
    RETURN cve_id ~ '^CVE-\d{4}-\d{4,}$';
END;
$$ LANGUAGE plpgsql;

-- Create a function to get severity from CVSS score
CREATE OR REPLACE FUNCTION get_severity_from_cvss(cvss_score NUMERIC)
RETURNS TEXT AS $$
BEGIN
    CASE 
        WHEN cvss_score IS NULL THEN RETURN 'UNKNOWN';
        WHEN cvss_score >= 9.0 THEN RETURN 'CRITICAL';
        WHEN cvss_score >= 7.0 THEN RETURN 'HIGH';
        WHEN cvss_score >= 4.0 THEN RETURN 'MEDIUM';
        ELSE RETURN 'LOW';
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- Create a view for dashboard statistics
CREATE OR REPLACE VIEW dashboard_stats AS
SELECT 
    (SELECT COUNT(*) FROM cves) as total_cves,
    (SELECT COUNT(*) FROM cves WHERE cvss_score >= 7.0) as high_risk_cves,
    (SELECT COUNT(*) FROM cves WHERE published_date >= CURRENT_DATE - INTERVAL '30 days') as recent_cves,
    (SELECT COUNT(*) FROM assets) as total_assets,
    (SELECT COUNT(*) FROM assets WHERE criticality = 'critical') as critical_assets,
    (SELECT COUNT(*) FROM vulnerability_assignments WHERE status IN ('assigned', 'in_progress')) as active_assignments,
    (SELECT COUNT(*) FROM vulnerability_assignments WHERE due_date < CURRENT_TIMESTAMP AND status IN ('assigned', 'in_progress')) as overdue_assignments,
    (SELECT COUNT(*) FROM users WHERE is_active = true) as active_users;

-- Grant permissions on the view to vsadmin
GRANT SELECT ON dashboard_stats TO vsadmin;

-- Create a simple health check function
CREATE OR REPLACE FUNCTION database_health_check()
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'status', 'healthy',
        'timestamp', CURRENT_TIMESTAMP,
        'database_name', current_database(),
        'database_user', 'vsadmin',
        'version', version(),
        'total_tables', (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public')
    ) INTO result;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission on health check function
GRANT EXECUTE ON FUNCTION database_health_check() TO vsadmin;

-- Final setup message
\echo '✅ Database initialization completed successfully!'
\echo '👤 Database User: vsadmin'
\echo '🔐 Database Password: adminVS2025'
\echo '🔧 Created functions and views with proper permissions'
\echo ''
\echo 'Connection string format:'
\echo 'postgresql://vsadmin:adminVS2025@localhost:5432/vulndb'
\echo ''
\echo 'Next steps:'
\echo '1. Update your .env file with the new database credentials'
\echo '2. Run Alembic migrations: alembic upgrade head'
\echo '3. Create application users: python create_admin_user.py'
\echo ''
\echo 'Database is ready!'