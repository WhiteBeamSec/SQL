BEGIN;

/*
Title: Coreutils
Description: Application-specific whitelist for GNU coreutils
Publisher: WhiteBeam Security, Inc.
Version: 0.2.6
*/

INSERT OR IGNORE INTO Whitelist (path, value, class)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES ("ANY", "/bin/basename", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/cat", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/clear_console", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/cp", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/df", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/dircolors", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/dirname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/env", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/free", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/grep", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/groups", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/id", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/lesspipe", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/locale-check", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/ls", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/mesg", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/ps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/rm", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/uname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/which", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/bin/w.procps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/basename", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/cat", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/clear_console", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/cp", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/df", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/dircolors", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/dirname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/env", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/free", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/grep", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/groups", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/id", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/lesspipe", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/locale-check", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/ls", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/mesg", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/ps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/rm", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/uname", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/which", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "/usr/bin/w.procps", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("/bin/clear_console", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/grep", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/clear_console", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/cp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/free", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/grep", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/id", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ls", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/ps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/usr/bin/w.procps", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("/bin/basename", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/cat", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/clear_console", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/cp", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/df", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/dircolors", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/dirname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/env", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/free", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/grep", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/groups", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/id", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/lesspipe", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/locale-check", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/ls", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/mesg", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/ps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/rm", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/uname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/which", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/bin/w.procps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libtinfo.so.6", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libacl.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libattr.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre.so.3", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libselinux.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpcre2-8.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libprocps.so.8", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libsystemd.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/librt.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblzma.so.5", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/liblz4.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcrypt.so.20", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgpg-error.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/basename", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/cat", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/clear_console", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/cp", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/df", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/dircolors", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/dirname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/env", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/free", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/grep", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/groups", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/id", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/lesspipe", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/locale-check", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/ls", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/mesg", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/ps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/rm", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/uname", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/which", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("/usr/bin/w.procps", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")));

COMMIT;