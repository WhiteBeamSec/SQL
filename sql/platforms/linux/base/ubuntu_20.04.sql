-- Test Base whitelist for Ubuntu 20.04
INSERT INTO Whitelist (path, value, class) VALUES ("ANY", "/tmp/**", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable"));
