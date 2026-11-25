SELECT pgactive_live_capture_reset();
SELECT * FROM pgactive_parse_replident_name('pgactive_123_1_2_3_');
SELECT encode(pgactive_live_capture_bytes(),'hex');
