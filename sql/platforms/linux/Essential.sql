BEGIN;

/*
Title: Essential
Description: Minimum hooks, rules, and whitelist entries required to run and protect WhiteBeam
Publisher: WhiteBeam Security, Inc.
Version: 0.3.0-dev
*/

-- TODO Requiring race-free design:
-- Filesystem
--   freopen
--   freopen64
--   tmpfile
--   tmpfile64
--   mktemp
--   mkdtemp
--   mkstemp
--   mkostemp64
--   mkostemps64
--   mkstemp64
--   mkstemps64
-- TODO: Dynamically mangle/demangle C++ symbols

-- Whitelist
INSERT INTO Whitelist (parent, path, value, class)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES ("ANY", "ANY", "/bin/bash", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/bin/sh", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/bash", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/bin/sh", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/opt/WhiteBeam/whitebeam", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/usr/local/bin/whitebeam", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                      ("ANY", "ANY", "/lib/libwhitebeam.so", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "ANY", "/opt/WhiteBeam/libwhitebeam.so", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcc_s.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpthread.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libm.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/opt/WhiteBeam/whitebeam", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libssl.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/opt/WhiteBeam/whitebeam", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libcrypto.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/local/bin/whitebeam", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libssl.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/usr/local/bin/whitebeam", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libcrypto.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                      ("ANY", "/bin/bash", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/bin/sh", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/bash", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/bin/sh", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/opt/WhiteBeam/whitebeam", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/usr/local/bin/whitebeam", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/libwhitebeam.so", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/opt/WhiteBeam/libwhitebeam.so", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libgcc_s.so.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpthread.so.0", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libm.so.6", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libssl.so.1.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libcrypto.so.1.1", "ANY", (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                      ("ANY", "ANY", "/dev/pts/", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable")),
                      ("ANY", "/opt/WhiteBeam/whitebeam", "11998", (SELECT id FROM WhitelistClass WHERE class="Network/Range/Port")),
                      ("ANY", "/usr/local/bin/whitebeam", "11998", (SELECT id FROM WhitelistClass WHERE class="Network/Range/Port")));

-- Hook
-- TODO: Make sure this reflects the libraries present on a system
-- TODO: Enable all hooks for complete coverage.
--       For now, do not report security issues unless all Execution and Filesystem hooks are enabled (currently this comes at some stability costs).
INSERT INTO Hook (symbol, library, enabled, language, class)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES -- Execution
                      ("execl", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("execle", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("execlp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("execv", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("execve", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("execvp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("execvpe", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("fexecve", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("posix_spawn", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("posix_spawnp", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("dlopen", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("dlmopen", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      ("kill", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                      -- Filesystem
                      ("creat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("creat64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fdopen", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fopen", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fopen64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      --("freopen", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      --("freopen64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("open", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("open64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("openat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("openat64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("chmod", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fchmod", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fchmodat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("chown", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("lchown", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fchown", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("fchownat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("link", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("linkat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("symlink", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("symlinkat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("rename", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("renameat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("renameat2", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("mkdir", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("mkdirat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("rmdir", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("unlink", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("unlinkat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("truncate", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("truncate64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("ftruncate", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("ftruncate64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("mknod", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("mknodat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__open64_2", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__open64", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__openat64_2", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__openat_2", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__open_2", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__open", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__xmknod", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      ("__xmknodat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                      -- Network
                      ("accept", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")),
                      ("accept4", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")),
                      ("bind", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")),
                      ("connect", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")));

-- Argument
INSERT INTO Argument (name, position, hook, datatype)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES -- Execution
                      -- execl
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("arg", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl"), (SELECT id FROM Datatype WHERE datatype="StringVariadic")),
                      -- execle
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("arg", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle"), (SELECT id FROM Datatype WHERE datatype="StringVariadic")),
                      ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- execlp
                      ("file", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("arg", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp"), (SELECT id FROM Datatype WHERE datatype="StringVariadic")),
                      -- execv
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- execve
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execve"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- execvp
                      ("file", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- execvpe
                      ("file", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- fexecve
                      ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fexecve"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fexecve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fexecve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- posix_spawn
                      ("pid", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawn"), (SELECT id FROM Datatype WHERE datatype="IntegerSignedPointer")),
                      ("path", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawn"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("file_actions", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawn"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("attrp", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawn"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("argv", 4, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawn"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      ("envp", 5, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawn"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- posix_spawnp
                      ("pid", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawnp"), (SELECT id FROM Datatype WHERE datatype="IntegerSignedPointer")),
                      ("file", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawnp"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("file_actions", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawnp"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("attrp", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawnp"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("argv", 4, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawnp"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      ("envp", 5, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="posix_spawnp"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                      -- dlopen
                      ("filename", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- dlmopen
                      ("lmid", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                      ("filename", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- kill
                      ("pid", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="kill"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("sig", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="kill"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- Filesystem
                      -- creat
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- creat64
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- fdopen
                      ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fdopen"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fdopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- fopen
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- fopen64
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- freopen
                      --("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      --("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                      --("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      -- freopen64
                      --("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      --("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      --("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      -- open
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- open64
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- openat
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- openat64
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- chmod
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chmod"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chmod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- fchmod
                      ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmod"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- fchmodat
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("flags", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- chown
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("owner", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("group", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- lchown
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("owner", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("group", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- fchown
                      ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchown"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("owner", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("group", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- fchownat
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("owner", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("group", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("flags", 4, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- link
                      ("oldpath", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("newpath", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- linkat
                      ("olddirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("oldpath", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("newdirfd", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("newpath", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 4, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- symlink
                      ("target", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlink"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("linkpath", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlink"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- symlinkat
                      ("target", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlinkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("newdirfd", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlinkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("linkpath", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlinkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- rename
                      ("oldpath", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("newpath", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- renameat
                      ("olddirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("oldpath", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("newdirfd", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("newpath", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- renameat2
                      ("olddirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("oldpath", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("newdirfd", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("newpath", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 4, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- mkdir
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdir"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdir"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- mkdirat
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdirat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdirat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdirat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- rmdir
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rmdir"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- unlink
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlink"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- unlinkat
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlinkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlinkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlinkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- truncate
                      ("path", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                      -- truncate64
                      ("path", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate64"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                      -- ftruncate
                      ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="ftruncate"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="ftruncate"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                      -- ftruncate64
                      ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="ftruncate64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="ftruncate64"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                      -- mknod
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknod"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("dev", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknod"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                      -- mknodat
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("dev", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                      -- __open64_2
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- __open64
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- __openat64_2
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- __openat_2
                      ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- __open_2
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- __open
                      ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                      -- __xmknod
                      ("ver", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("dev", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                      -- __xmknodat
                      ("ver", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("dirfd", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("pathname", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      ("dev", 4, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                      -- Network
                      -- accept
                      ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedPointer")),
                      -- accept4
                      ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedPointer")),
                      ("flags", 3, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- bind
                      ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="bind"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="bind"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="bind"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                      -- connect
                      ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="connect"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="connect"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="connect"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")));

-- ActionArgument
INSERT INTO ActionArgument (value, next)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES -- AddInt
                      -- ModifyInt
                      ("0", NULL), ("0", last_insert_rowid()), -- LM_ID_BASE
                      ("1", NULL), ("2", last_insert_rowid()), -- RTLD_LAZY
                      -- RedirectFunction
                      ("execve", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("dlmopen", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2", last_insert_rowid()),
                      ("ftruncate", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("ftruncate64", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("fdopen", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("symlinkat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("mkdirat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("unlinkat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("linkat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("renameat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("fchownat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("fchmodat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("openat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("openat64", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("mknodat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("__openat_2", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("__openat64_2", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()),
                      ("__xmknodat", NULL), ("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", last_insert_rowid()));

-- Rule
INSERT INTO Rule (arg, positional, action, actionarg)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES -- Execution
                      -- Canonicalize path for exec*p* and dl*open
                      -- TODO: Should the path in all exec* hooks be canonicalized here to reduce the size of the whitelist?
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath"), NULL),
                      -- Check if the target is a whitelisted executable (TOCTOU protected by Filesystem hooks)
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute"), NULL),
                      -- Check if the executable hash is whitelisted (TOCTOU protected by Filesystem hooks)
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash"), NULL),
                      -- Convert execl* variadic parameters into an array
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      -- Add environment parameter if it's not present
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment"), NULL),
                      -- Add flags to dlopen
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      -- Modify flags of dlopen and dlmopen
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), FALSE, (SELECT id FROM Action WHERE name="ModifyInt"), (SELECT id FROM ActionArgument WHERE value="2" AND next=(SELECT id FROM ActionArgument WHERE value="1" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen") AND name="lmid"), TRUE, (SELECT id FROM Action WHERE name="ModifyInt"), (SELECT id FROM ActionArgument WHERE value="0" AND next=(SELECT id FROM ActionArgument WHERE value="0" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlmopen") AND name="flags"), TRUE, (SELECT id FROM Action WHERE name="ModifyInt"), (SELECT id FROM ActionArgument WHERE value="2" AND next=(SELECT id FROM ActionArgument WHERE value="1" AND next IS NULL))),
                      -- Filter environment parameter
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execve") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment"), NULL),
                      -- Redirect exec* to execve
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      -- Redirect dlopen to dlmopen
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libdl.so.2") AND next=(SELECT id FROM ActionArgument WHERE value="dlmopen" AND next IS NULL))),
                      -- Disallow killing the WhiteBeam service (TODO: pidfd_send_signal support for Linux >=5.1)
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="kill") AND name="pid"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanTerminate"), NULL),
                      -- Filesystem
                      -- Open file descriptor for the target path
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate64") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor"), NULL),
                      -- Open directory file descriptor
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link") AND name="newpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename") AND name="oldpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename") AND name="newpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdir") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlink") AND name="linkpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknod") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath"), NULL),
                      -- Combine directory components in *at* functions to prevent directory traversal race conditions
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdirat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlinkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlinkat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory"), NULL),
                      -- Check if the target directory is whitelisted (if this is a write operation)
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link") AND name="newpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename") AND name="newpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlink") AND name="linkpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate64") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmod") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchown") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fdopen") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="ftruncate") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="ftruncate64") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchmodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fchownat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="linkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdirat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlinkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlinkat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite"), NULL),
                      -- Convert variadic parameters into regular parameters
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="openat64") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__openat64_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic"), NULL),
                      -- Add open flags
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddInt"), NULL),
                      -- Redirect to TOCTOU safe function (*at/f*)
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="symlink") AND name="target"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="symlinkat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="unlinkat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mkdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="mkdirat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="unlinkat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="linkat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="rename") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="renameat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="fchownat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="fchownat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="fchmodat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="openat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="openat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="openat64" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="openat64" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="mknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="mknodat" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate") AND name="path"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="ftruncate" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="truncate64") AND name="path"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="ftruncate64" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="fdopen" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="fopen64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="fdopen" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="__openat_2" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="__openat_2" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="__openat64_2" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="__openat64_2" AND next IS NULL))),
                      ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="__xmknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"), (SELECT id FROM ActionArgument WHERE value=("/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6") AND next=(SELECT id FROM ActionArgument WHERE value="__xmknodat" AND next IS NULL))));

COMMIT;
