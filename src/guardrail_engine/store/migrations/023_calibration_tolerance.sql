-- M4-02 regression gate: the tenant's recall tolerance, a setting beside its calibration targets.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 020.
-- The service role's table-level grants on tenant_calibration_targets (021) already cover the
-- column. Points of golden-set recall a version may lose against the active one (AC-A3): 0 to 20,
-- in steps of 0.5 (the code checks the step; the database holds the range).

ALTER TABLE tenant_calibration_targets
    ADD COLUMN IF NOT EXISTS recall_tolerance numeric(4,1) NOT NULL DEFAULT 2.0
        CHECK (recall_tolerance BETWEEN 0 AND 20);
