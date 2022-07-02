BEGIN;

/*
Title: Test
Description: Sample WhiteBeam data
Publisher: WhiteBeam Security, Inc.
Version: 0.3.0-dev
*/

CREATE TEMPORARY TABLE IF NOT EXISTS global_const
AS SELECT (SELECT "/lib/" || (SELECT value FROM Setting WHERE param="SystemArchitecture") || "-linux-gnu/") AS LibraryPath;

-- HookClass
INSERT OR IGNORE INTO HookClass (class) VALUES ("Test");

-- Whitelist
INSERT OR IGNORE INTO Whitelist (parent, path, value, class)
WITH local_const AS (SELECT (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable") AS Executable,
                            (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library") AS Library,
                            (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3") AS BLAKE3,
                            (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable") AS Writable,
                            (SELECT id FROM WhitelistClass WHERE class="Network/Range/CIDR") AS CIDR,
                            (SELECT id FROM WhitelistClass WHERE class="Network/Range/Port") AS Port)
SELECT * FROM (VALUES ("ANY", "/bin/bash", "664d9dd14597b83aebf765d2d054fa40ad7a93ffeca43ee3bba596517db2c39b", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/bin/sh", "30751ae1ba8597ee7d9aa7e3852a58d9b21a14b88e423cbb0aa7d0512d059a6a", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/bin/bash", "664d9dd14597b83aebf765d2d054fa40ad7a93ffeca43ee3bba596517db2c39b", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/bin/sh", "30751ae1ba8597ee7d9aa7e3852a58d9b21a14b88e423cbb0aa7d0512d059a6a", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/sbin/apache2", "4aadc76a6af5d65197cb9cdf7d7a6945772539c48c0120919f38f77af29c0f53", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/bin/whoami", "5ff499d1ce89604780cd1b2d85be2a10b5076cf941950ab53a8ba092815efa7b", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/bin/bash", "/usr/sbin/apache2", (SELECT Executable FROM local_const)),
                      ("ANY", "/bin/sh", "/usr/sbin/apache2", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/usr/src/whitebeam/target/release/whitebeam", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/usr/bin/whoami", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/tmp/**", (SELECT Writable FROM local_const)),
                      ("ANY", "/usr/sbin/apache2", "172.16.0.0/12", (SELECT CIDR FROM local_const)),
                      ("ANY", "ANY", "/usr/src/whitebeam/target/release/libwhitebeam.so", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/bin/bash", (SELECT LibraryPath FROM global_const) || "libtinfo.so.6", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/src/whitebeam/target/release/whitebeam", (SELECT LibraryPath FROM global_const) || "libssl.so.1.1", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/src/whitebeam/target/release/whitebeam", (SELECT LibraryPath FROM global_const) || "libcrypto.so.1.1", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/src/whitebeam/target/release/whitebeam", "11998", (SELECT Port FROM local_const)));

-- NonceHistory
INSERT INTO NonceHistory (nonce, ts) VALUES (lower(hex(randomblob(24))), 1590000000),
                                            (lower(hex(randomblob(24))), strftime("%s", "now")),
                                            (lower(hex(randomblob(24))), strftime("%s", "now")),
                                            (lower(hex(randomblob(24))), strftime("%s", "now"));

COMMIT;
