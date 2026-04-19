-- Drop all restrictive CHECK constraints so new enum values (monitor types,
-- alert contact types, statuses, etc.) can be added without schema migrations.
-- Validation is enforced at the API layer.
PRAGMA writable_schema = 1;

UPDATE sqlite_master
SET sql = replace(sql,
    ' CHECK (type IN (''http'', ''port'', ''keyword'', ''ssl'', ''heartbeat''))',
    '')
WHERE type = 'table' AND name = 'monitors';

UPDATE sqlite_master
SET sql = replace(sql,
    ' CHECK (keyword_type IN ('''', ''contains'', ''not_contains''))',
    '')
WHERE type = 'table' AND name = 'monitors';

UPDATE sqlite_master
SET sql = replace(sql,
    ' CHECK (status IN (''up'', ''down'', ''unknown''))',
    '')
WHERE type = 'table' AND name = 'monitors';

UPDATE sqlite_master
SET sql = replace(sql,
    ' CHECK (status IN (''up'', ''down''))',
    '')
WHERE type = 'table' AND name = 'check_results';

UPDATE sqlite_master
SET sql = replace(sql,
    ' CHECK (type IN (''email'', ''slack'', ''webhook''))',
    '')
WHERE type = 'table' AND name = 'alert_contacts';

UPDATE sqlite_master
SET sql = replace(sql,
    ' CHECK (type IN (''down'', ''up''))',
    '')
WHERE type = 'table' AND name = 'alert_log';

PRAGMA writable_schema = 0;

-- Bump schema_version so pooled connections reload the schema.
CREATE TABLE IF NOT EXISTS __schema_bump (x INTEGER);
DROP TABLE IF EXISTS __schema_bump;
