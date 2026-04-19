ALTER TABLE monitors ADD COLUMN dns_record_type TEXT NOT NULL DEFAULT '';
ALTER TABLE monitors ADD COLUMN dns_expected_value TEXT NOT NULL DEFAULT '';
ALTER TABLE monitors ADD COLUMN dns_resolver TEXT NOT NULL DEFAULT '';
