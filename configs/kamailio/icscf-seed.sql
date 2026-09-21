-- Data seed for the I-CSCF routing tables (icscf.sql only ships the CREATE TABLE
-- statements, no rows -- without this, I-CSCF has no S-CSCF to route REGISTER/
-- INVITE to, and every registration attempt fails before it ever reaches HSS).
--
-- This is what was missing from the uploaded imsconfig bundle. See install.sh,
-- which loads this file into the `icscf` database right after icscf.sql.

USE icscf;

INSERT INTO nds_trusted_domains (id, trusted_domain)
VALUES (1, 'ims.mnc001.mcc001.3gppnetwork.org');

INSERT INTO s_cscf (id, name, s_cscf_uri)
VALUES (1, 'S-CSCF', 'sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:6060');

-- capability 0 = default/no specific capability required, capability 1 = generic
-- match; two rows so the I-CSCF's S-CSCF-selection logic has something to match
-- against regardless of what capability value HSS/Cx (or the fallback path)
-- asks for, since there's only one S-CSCF in this deployment anyway.
INSERT INTO s_cscf_capabilities (id, id_s_cscf, capability)
VALUES (1, 1, 0), (2, 1, 1);
