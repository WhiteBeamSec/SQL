BEGIN;

-- Log
INSERT INTO Log (class, desc, ts) VALUES ((SELECT id FROM LogClass WHERE class="Error"), "Fatal error in crypto.rs line 32: Unhandled exception", 1590000000),
                                         ((SELECT id FROM LogClass WHERE class="Error"), "Fatal error in crypto.rs line 51: Unhandled exception", strftime("%s", "now")),
                                         ((SELECT id FROM LogClass WHERE class="Auth"), "User root successfully authenticated to WhiteBeam", strftime("%s", "now")),
                                         ((SELECT id FROM LogClass WHERE class="Auth"), "User root failed to authenticate to WhiteBeam", strftime("%s", "now")),
                                         ((SELECT id FROM LogClass WHERE class="Auth"), "User nobody failed to authenticate to WhiteBeam", strftime("%s", "now")),
                                         ((SELECT id FROM LogClass WHERE class="General"), "Received request for public key from 172.16.0.2", strftime("%s", "now"));

-- Whitelist: Libraries will go here too
INSERT INTO Whitelist (path, value, class) VALUES ("/bin/bash", "900c28f35811948f08f1e9b0e357b18d3bd58c8f535c0f1fd66f16838c5b6fed", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ("/bin/sh", "81ead1a649fc4a85720ad69287c9c7557a787a6c590cbfffd9137b3d514164ee", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ("/usr/bin/bash", "900c28f35811948f08f1e9b0e357b18d3bd58c8f535c0f1fd66f16838c5b6fed", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ("/usr/bin/sh", "81ead1a649fc4a85720ad69287c9c7557a787a6c590cbfffd9137b3d514164ee", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ("/usr/sbin/apache2", "4aadc76a6af5d65197cb9cdf7d7a6945772539c48c0120919f38f77af29c0f53", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ("/usr/bin/whoami", "6d9bffe11b7c5520adb3f464a7d58c25d99ced49b881e163b7a8b09c94521897", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ("/bin/bash", "/usr/sbin/apache2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("/bin/sh", "/usr/sbin/apache2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/usr/bin/whoami", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/tmp/*", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Writable")), -- Realpath/canonicalized open() for wildcards?
                                                  ("/usr/sbin/apache2", "172.16.0.0/12", (SELECT id FROM WhitelistClass WHERE class="Network/Range/CIDR"));

-- NonceHistory
INSERT INTO NonceHistory (nonce, ts) VALUES (lower(hex(randomblob(24))), 1590000000),
                                            (lower(hex(randomblob(24))), strftime("%s", "now")),
                                            (lower(hex(randomblob(24))), strftime("%s", "now")),
                                            (lower(hex(randomblob(24))), strftime("%s", "now"));

COMMIT;
