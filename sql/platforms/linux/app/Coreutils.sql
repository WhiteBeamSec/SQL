BEGIN;

/*
Title: Coreutils
Description: Application-specific whitelist for GNU coreutils
Publisher: WhiteBeam Security, Inc.
Version: 0.3.0-dev
*/

INSERT OR IGNORE INTO Whitelist (parent, path, value, class)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES ("ANY", "ANY", "/bin/basename", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/cat", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/clear_console", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/cp", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/df", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/dircolors", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/dirname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/env", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/free", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/grep", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/groups", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/id", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/lesspipe", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/locale-check", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/ls", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/mesg", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/ps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/rm", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/uname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/which", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/w.procps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/basename", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/cat", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/clear_console", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/cp", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/df", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/dircolors", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/dirname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/env", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/free", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/grep", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/groups", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/id", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/lesspipe", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/locale-check", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/ls", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/mesg", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/ps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/rm", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/uname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/which", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/w.procps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/clear_console", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/grep", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/clear_console", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/grep", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/basename", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/cat", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/clear_console", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/cp", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/df", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/dircolors", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/dirname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/env", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/free", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/grep", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/groups", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/id", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/lesspipe", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/locale-check", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/ls", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/mesg", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/ps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/rm", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/uname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/which", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/w.procps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/basename", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/cat", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/clear_console", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/cp", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/df", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/dircolors", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/dirname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/env", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/free", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/grep", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/groups", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/id", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/lesspipe", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/locale-check", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/ls", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/mesg", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/ps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/rm", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/uname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/which", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/w.procps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")));

COMMIT;