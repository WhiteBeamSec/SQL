BEGIN;

/*
Title: Test
Description: Sample WhiteBeam data
Publisher: WhiteBeam Security, Inc.
Version: 0.3.0-dev
*/

-- Whitelist
INSERT INTO Whitelist (parent, path, value, class)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES ("ANY", "/bin/bash", "664d9dd14597b83aebf765d2d054fa40ad7a93ffeca43ee3bba596517db2c39b", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/sh", "30751ae1ba8597ee7d9aa7e3852a58d9b21a14b88e423cbb0aa7d0512d059a6a", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/bash", "664d9dd14597b83aebf765d2d054fa40ad7a93ffeca43ee3bba596517db2c39b", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/sh", "30751ae1ba8597ee7d9aa7e3852a58d9b21a14b88e423cbb0aa7d0512d059a6a", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/sbin/apache2", "4aadc76a6af5d65197cb9cdf7d7a6945772539c48c0120919f38f77af29c0f53", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/whoami", "5ff499d1ce89604780cd1b2d85be2a10b5076cf941950ab53a8ba092815efa7b", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/bash", "/usr/sbin/apache2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/sh", "/usr/sbin/apache2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/src/whitebeam/target/release/whitebeam", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/whoami", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/tmp/**", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable")),
                      ("ANY", "/usr/sbin/apache2", "172.16.0.0/12", (SELECT id FROM WhitelistClass WHERE class="Network/Range/CIDR")),
                      ("ANY", "ANY", "/usr/src/whitebeam/target/release/libwhitebeam.so", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/bash", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/src/whitebeam/target/release/whitebeam", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libssl.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/src/whitebeam/target/release/whitebeam", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libcrypto.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/src/whitebeam/target/release/whitebeam", "11998", (SELECT id FROM WhitelistClass WHERE class="Network/Range/Port")));

-- NonceHistory
INSERT INTO NonceHistory (nonce, ts) VALUES (lower(hex(randomblob(24))), 1590000000),
                                            (lower(hex(randomblob(24))), strftime("%s", "now")),
                                            (lower(hex(randomblob(24))), strftime("%s", "now")),
                                            (lower(hex(randomblob(24))), strftime("%s", "now"));

COMMIT;
