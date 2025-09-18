-- Complete cleanup of auto-categorized CPE data
-- This will remove all auto-created categories and service types, keeping only manual entries

-- 1. First, let's see what we're about to clean up
SELECT 
    'Before cleanup:' as status,
    (SELECT COUNT(*) FROM service_categories WHERE data_source = 'cpe') as cpe_categories,
    (SELECT COUNT(*) FROM service_categories WHERE data_source = 'manual' OR data_source IS NULL) as manual_categories,
    (SELECT COUNT(*) FROM service_types WHERE data_source = 'cpe') as cpe_service_types,
    (SELECT COUNT(*) FROM service_types WHERE data_source = 'manual' OR data_source IS NULL) as manual_service_types,
    (SELECT COUNT(*) FROM service_instances WHERE data_source = 'cpe') as cpe_instances,
    (SELECT COUNT(*) FROM service_instances WHERE data_source = 'manual' OR data_source IS NULL) as manual_instances;

-- 2. Backup existing data (recommended)
DROP TABLE IF EXISTS service_categories_backup;
DROP TABLE IF EXISTS service_types_backup; 
DROP TABLE IF EXISTS service_instances_backup;

CREATE TABLE service_categories_backup AS SELECT * FROM service_categories;
CREATE TABLE service_types_backup AS SELECT * FROM service_types;
CREATE TABLE service_instances_backup AS SELECT * FROM service_instances;

-- 3. Delete service instances from CPE-created service types first (to handle foreign keys)
DELETE FROM service_instances 
WHERE service_type_id IN (
    SELECT id FROM service_types WHERE data_source = 'cpe'
);

-- 4. Delete all CPE auto-created service types
DELETE FROM service_types WHERE data_source = 'cpe';

-- 5. Delete all CPE auto-created categories (including those with the suspicious names)
DELETE FROM service_categories 
WHERE data_source = 'cpe' 
OR name IN (
    'web_servers', 'databases', 'operating_systems', 'application_servers',
    'monitoring_tools', 'security_tools', 'container_platforms', 'load_balancers',
    'messaging_systems', 'cache_systems', 'development_tools', 'virtualization',
    'Web Servers', 'Databases', 'Operating Systems', 'Application Servers',
    'Monitoring Tools', 'Security Tools', 'Container Platforms', 'Load Balancers',
    'Messaging Systems', 'Cache Systems', 'Development Tools', 'Virtualization'
);

-- 6. Clean up any orphaned service types (service types whose categories were deleted)
DELETE FROM service_instances 
WHERE service_type_id IN (
    SELECT st.id FROM service_types st 
    LEFT JOIN service_categories sc ON st.category_id = sc.id 
    WHERE sc.id IS NULL
);

DELETE FROM service_types 
WHERE category_id NOT IN (SELECT id FROM service_categories);

-- 7. Reset data_source for remaining entries to 'manual' for consistency
UPDATE service_categories 
SET data_source = 'manual' 
WHERE data_source IS NULL OR data_source != 'manual';

UPDATE service_types 
SET data_source = 'manual' 
WHERE data_source IS NULL OR data_source != 'manual';

UPDATE service_instances 
SET data_source = 'manual' 
WHERE data_source IS NULL OR data_source != 'manual';

-- 8. Clear CPE-specific fields from service types (since we're going back to manual only)
UPDATE service_types 
SET 
    cpe_product = NULL,
    cpe_name = NULL,
    cpe_name_id = NULL,
    vendor_aliases = NULL,
    product_aliases = NULL,
    correlation_keywords = NULL,
    nvd_product_names = NULL,
    confidence_score = NULL,
    source_reference = NULL,
    source_metadata = NULL
WHERE data_source = 'manual';

-- 9. Clear CPE fields from instances too
UPDATE service_instances 
SET 
    source_reference = NULL,
    source_metadata = NULL,
    detection_confidence = NULL,
    source_reference = NULL
WHERE data_source = 'manual';

-- 10. Show results after cleanup
SELECT 
    'After cleanup:' as status,
    (SELECT COUNT(*) FROM service_categories) as total_categories,
    (SELECT COUNT(*) FROM service_types) as total_service_types,
    (SELECT COUNT(*) FROM service_instances) as total_instances;

-- 11. Show remaining categories and their service counts
SELECT 
    c.id,
    c.name as category_name,
    c.description,
    COUNT(st.id) as service_types_count,
    COUNT(si.id) as service_instances_count
FROM service_categories c
LEFT JOIN service_types st ON c.id = st.category_id
LEFT JOIN service_instances si ON st.id = si.service_type_id
GROUP BY c.id, c.name, c.description
ORDER BY c.name;

-- 12. Verification queries - these should all return 0
SELECT 'Verification - should all be 0:' as check_name;
SELECT 'CPE categories remaining:' as check_name, COUNT(*) as count FROM service_categories WHERE data_source = 'cpe';
SELECT 'CPE service types remaining:' as check_name, COUNT(*) as count FROM service_types WHERE data_source = 'cpe';
SELECT 'CPE instances remaining:' as check_name, COUNT(*) as count FROM service_instances WHERE data_source = 'cpe';
SELECT 'Orphaned service types:' as check_name, COUNT(*) as count FROM service_types WHERE category_id NOT IN (SELECT id FROM service_categories);
SELECT 'Service types with CPE fields:' as check_name, COUNT(*) as count FROM service_types WHERE cpe_name_id IS NOT NULL;

-- 13. Optional: Refresh materialized view if it exists
-- REFRESH MATERIALIZED VIEW data_source_stats;