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

CREATE TEMPORARY TABLE IF NOT EXISTS global_const
AS SELECT (SELECT id FROM HookLanguage WHERE language="C") AS C,
          (SELECT value FROM Setting WHERE param="SystemLibraryPath") AS LibraryPath,
          (SELECT IIF(((SELECT value FROM Setting WHERE param="SystemLibraryPath") LIKE "/lib64/%"), "/lib64/", "/lib/")) AS TrustedLibraryPath;

-- Whitelist
INSERT OR IGNORE INTO Whitelist (parent, path, value, class)
WITH local_const AS (SELECT (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable") AS Executable,
                            (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library") AS Library,
                            (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3") AS BLAKE3,
                            (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable") AS Writable,
                            (SELECT id FROM WhitelistClass WHERE class="Network/Range/Port") AS Port)
SELECT * FROM (VALUES ("ANY", "ANY", "/bin/bash", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/bin/sh", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/usr/bin/bash", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/usr/bin/sh", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/opt/WhiteBeam/whitebeam", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", "/usr/local/bin/whitebeam", (SELECT Executable FROM local_const)),
                      ("ANY", "ANY", (SELECT TrustedLibraryPath FROM global_const) || "libwhitebeam.so", (SELECT Library FROM local_const)),
                      ("ANY", "ANY", "/opt/WhiteBeam/libwhitebeam.so", (SELECT Library FROM local_const)),
                      ("ANY", "ANY", (SELECT LibraryPath FROM global_const) || "libc.so.6", (SELECT Library FROM local_const)),
                      ("ANY", "ANY", (SELECT LibraryPath FROM global_const) || "libgcc_s.so.1", (SELECT Library FROM local_const)),
                      ("ANY", "ANY", (SELECT LibraryPath FROM global_const) || "libpthread.so.0", (SELECT Library FROM local_const)),
                      ("ANY", "ANY", (SELECT LibraryPath FROM global_const) || "libm.so.6", (SELECT Library FROM local_const)),
                      ("ANY", "ANY", (SELECT LibraryPath FROM global_const) || "libdl.so.2", (SELECT Library FROM local_const)),
                      ("ANY", "/opt/WhiteBeam/whitebeam", (SELECT LibraryPath FROM global_const) || "libssl.so.1.1", (SELECT Library FROM local_const)),
                      ("ANY", "/opt/WhiteBeam/whitebeam", (SELECT LibraryPath FROM global_const) || "libcrypto.so.1.1", (SELECT Library FROM local_const)),
                      ("ANY", "/opt/WhiteBeam/whitebeam", (SELECT LibraryPath FROM global_const) || "libz.so.1", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/local/bin/whitebeam", (SELECT LibraryPath FROM global_const) || "libssl.so.1.1", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/local/bin/whitebeam", (SELECT LibraryPath FROM global_const) || "libcrypto.so.1.1", (SELECT Library FROM local_const)),
                      ("ANY", "/usr/local/bin/whitebeam", (SELECT LibraryPath FROM global_const) || "libz.so.1", (SELECT Library FROM local_const)),
                      ("ANY", "/bin/bash", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/bin/sh", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/bin/bash", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/bin/sh", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/opt/WhiteBeam/whitebeam", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/usr/local/bin/whitebeam", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT TrustedLibraryPath FROM global_const) || "libwhitebeam.so", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "/opt/WhiteBeam/libwhitebeam.so", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libc.so.6", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libgcc_s.so.1", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libpthread.so.0", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libm.so.6", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libdl.so.2", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libssl.so.1.1", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", (SELECT LibraryPath FROM global_const) || "libcrypto.so.1.1", "ANY", (SELECT BLAKE3 FROM local_const)),
                      ("ANY", "ANY", "/dev/pts/", (SELECT Writable FROM local_const)),
                      ("ANY", "/opt/WhiteBeam/whitebeam", "11998", (SELECT Port FROM local_const)),
                      ("ANY", "/usr/local/bin/whitebeam", "11998", (SELECT Port FROM local_const)));

-- Hook
-- TODO: Make sure this reflects the libraries present on a system
-- TODO: Enable all hooks for complete coverage.
--       For now, do not report security issues unless all Execution and Filesystem hooks are enabled (currently this comes at some stability costs).
INSERT INTO Hook (symbol, library, enabled, language, class)
WITH local_const AS (SELECT ((SELECT LibraryPath FROM global_const) || "libc.so.6") AS libc,
                            (SELECT id FROM HookClass WHERE class="Execution") AS Execution,
                            (SELECT id FROM HookClass WHERE class="Filesystem") AS Filesystem,
                            (SELECT id FROM HookClass WHERE class="Network") AS Network)
SELECT * FROM (VALUES -- Execution
                      ("execl", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("execle", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("execlp", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("execv", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("execve", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("execvp", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("execvpe", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("fexecve", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("posix_spawn", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("posix_spawnp", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      ("kill", (SELECT libc FROM local_const), TRUE, (SELECT C FROM global_const), (SELECT Execution FROM local_const)),
                      -- Filesystem
                      ("creat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("creat64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fdopen", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fopen", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fopen64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      --("freopen", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      --("freopen64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("open", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("open64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("openat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("openat64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("chmod", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fchmod", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fchmodat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("chown", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("lchown", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fchown", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("fchownat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("link", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("linkat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("symlink", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("symlinkat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("rename", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("renameat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("renameat2", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("mkdir", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("mkdirat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("rmdir", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("unlink", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("unlinkat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("truncate", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("truncate64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("ftruncate", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("ftruncate64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("mknod", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("mknodat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__open64_2", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__open64", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__openat64_2", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__openat_2", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__open_2", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__open", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__xmknod", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      ("__xmknodat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Filesystem FROM local_const)),
                      -- Network
                      ("accept", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Network FROM local_const)),
                      ("accept4", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Network FROM local_const)),
                      ("bind", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Network FROM local_const)),
                      ("connect", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Network FROM local_const)));

CREATE TEMPORARY VIEW LibcHook AS SELECT id, symbol FROM Hook WHERE library = (SELECT LibraryPath FROM global_const) || "libc.so.6";

-- Argument
INSERT INTO Argument (name, position, hook, datatype)
WITH local_const AS (SELECT (SELECT id FROM Datatype WHERE datatype="IntegerSigned") AS IntegerSigned,
                            (SELECT id FROM Datatype WHERE datatype="IntegerSignedPointer") AS IntegerSignedPointer,
                            (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned") AS IntegerUnsigned,
                            (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedPointer") AS IntegerUnsignedPointer,
                            (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic") AS IntegerUnsignedVariadic,
                            (SELECT id FROM Datatype WHERE datatype="LongSigned") AS LongSigned,
                            (SELECT id FROM Datatype WHERE datatype="LongUnsigned") AS LongUnsigned,
                            (SELECT id FROM Datatype WHERE datatype="String") AS String,
                            (SELECT id FROM Datatype WHERE datatype="StringArray") AS StringArray,
                            (SELECT id FROM Datatype WHERE datatype="StringVariadic") AS StringVariadic,
                            (SELECT id FROM Datatype WHERE datatype="StructPointer") AS StructPointer)
SELECT * FROM (VALUES -- Execution
                      -- execl
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="execl"), (SELECT String FROM local_const)),
                      ("arg", 1, (SELECT id FROM LibcHook WHERE symbol="execl"), (SELECT StringVariadic FROM local_const)),
                      -- execle
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="execle"), (SELECT String FROM local_const)),
                      ("arg", 1, (SELECT id FROM LibcHook WHERE symbol="execle"), (SELECT StringVariadic FROM local_const)),
                      ("envp", 2, (SELECT id FROM LibcHook WHERE symbol="execle"), (SELECT StringArray FROM local_const)),
                      -- execlp
                      ("file", 0, (SELECT id FROM LibcHook WHERE symbol="execlp"), (SELECT String FROM local_const)),
                      ("arg", 1, (SELECT id FROM LibcHook WHERE symbol="execlp"), (SELECT StringVariadic FROM local_const)),
                      -- execv
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="execv"), (SELECT String FROM local_const)),
                      ("argv", 1, (SELECT id FROM LibcHook WHERE symbol="execv"), (SELECT StringArray FROM local_const)),
                      -- execve
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="execve"), (SELECT String FROM local_const)),
                      ("argv", 1, (SELECT id FROM LibcHook WHERE symbol="execve"), (SELECT StringArray FROM local_const)),
                      ("envp", 2, (SELECT id FROM LibcHook WHERE symbol="execve"), (SELECT StringArray FROM local_const)),
                      -- execvp
                      ("file", 0, (SELECT id FROM LibcHook WHERE symbol="execvp"), (SELECT String FROM local_const)),
                      ("argv", 1, (SELECT id FROM LibcHook WHERE symbol="execvp"), (SELECT StringArray FROM local_const)),
                      -- execvpe
                      ("file", 0, (SELECT id FROM LibcHook WHERE symbol="execvpe"), (SELECT String FROM local_const)),
                      ("argv", 1, (SELECT id FROM LibcHook WHERE symbol="execvpe"), (SELECT StringArray FROM local_const)),
                      ("envp", 2, (SELECT id FROM LibcHook WHERE symbol="execvpe"), (SELECT StringArray FROM local_const)),
                      -- fexecve
                      ("fd", 0, (SELECT id FROM LibcHook WHERE symbol="fexecve"), (SELECT IntegerSigned FROM local_const)),
                      ("argv", 1, (SELECT id FROM LibcHook WHERE symbol="fexecve"), (SELECT StringArray FROM local_const)),
                      ("envp", 2, (SELECT id FROM LibcHook WHERE symbol="fexecve"), (SELECT StringArray FROM local_const)),
                      -- posix_spawn
                      ("pid", 0, (SELECT id FROM LibcHook WHERE symbol="posix_spawn"), (SELECT IntegerSignedPointer FROM local_const)),
                      ("path", 1, (SELECT id FROM LibcHook WHERE symbol="posix_spawn"), (SELECT String FROM local_const)),
                      ("file_actions", 2, (SELECT id FROM LibcHook WHERE symbol="posix_spawn"), (SELECT StructPointer FROM local_const)),
                      ("attrp", 3, (SELECT id FROM LibcHook WHERE symbol="posix_spawn"), (SELECT StructPointer FROM local_const)),
                      ("argv", 4, (SELECT id FROM LibcHook WHERE symbol="posix_spawn"), (SELECT StringArray FROM local_const)),
                      ("envp", 5, (SELECT id FROM LibcHook WHERE symbol="posix_spawn"), (SELECT StringArray FROM local_const)),
                      -- posix_spawnp
                      ("pid", 0, (SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), (SELECT IntegerSignedPointer FROM local_const)),
                      ("file", 1, (SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), (SELECT String FROM local_const)),
                      ("file_actions", 2, (SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), (SELECT StructPointer FROM local_const)),
                      ("attrp", 3, (SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), (SELECT StructPointer FROM local_const)),
                      ("argv", 4, (SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), (SELECT StringArray FROM local_const)),
                      ("envp", 5, (SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), (SELECT StringArray FROM local_const)),
                      -- kill
                      ("pid", 0, (SELECT id FROM LibcHook WHERE symbol="kill"), (SELECT IntegerSigned FROM local_const)),
                      ("sig", 1, (SELECT id FROM LibcHook WHERE symbol="kill"), (SELECT IntegerSigned FROM local_const)),
                      -- Filesystem
                      -- creat
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="creat"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="creat"), (SELECT IntegerUnsigned FROM local_const)),
                      -- creat64
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="creat64"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="creat64"), (SELECT IntegerUnsigned FROM local_const)),
                      -- fdopen
                      ("fd", 0, (SELECT id FROM LibcHook WHERE symbol="fdopen"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="fdopen"), (SELECT String FROM local_const)),
                      -- fopen
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="fopen"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="fopen"), (SELECT String FROM local_const)),
                      -- fopen64
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="fopen64"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="fopen64"), (SELECT String FROM local_const)),
                      -- freopen
                      --("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="freopen"), (SELECT String FROM local_const)),
                      --("mode", 1, (SELECT id FROM LibcHook WHERE symbol="freopen"), (SELECT String FROM local_const)),
                      --("stream", 2, (SELECT id FROM LibcHook WHERE symbol="freopen"), (SELECT StructPointer FROM local_const)),
                      -- freopen64
                      --("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="freopen64"), (SELECT String FROM local_const)),
                      --("mode", 1, (SELECT id FROM LibcHook WHERE symbol="freopen64"), (SELECT String FROM local_const)),
                      --("stream", 2, (SELECT id FROM LibcHook WHERE symbol="freopen64"), (SELECT StructPointer FROM local_const)),
                      -- open
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="open"), (SELECT String FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibcHook WHERE symbol="open"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="open"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- open64
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="open64"), (SELECT String FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibcHook WHERE symbol="open64"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="open64"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- openat
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="openat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="openat"), (SELECT String FROM local_const)),
                      ("flags", 2, (SELECT id FROM LibcHook WHERE symbol="openat"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 3, (SELECT id FROM LibcHook WHERE symbol="openat"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- openat64
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="openat64"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="openat64"), (SELECT String FROM local_const)),
                      ("flags", 2, (SELECT id FROM LibcHook WHERE symbol="openat64"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 3, (SELECT id FROM LibcHook WHERE symbol="openat64"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- chmod
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="chmod"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="chmod"), (SELECT IntegerUnsigned FROM local_const)),
                      -- fchmod
                      ("fd", 0, (SELECT id FROM LibcHook WHERE symbol="fchmod"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="fchmod"), (SELECT IntegerUnsigned FROM local_const)),
                      -- fchmodat
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="fchmodat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="fchmodat"), (SELECT String FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="fchmodat"), (SELECT IntegerUnsigned FROM local_const)),
                      ("flags", 3, (SELECT id FROM LibcHook WHERE symbol="fchmodat"), (SELECT IntegerSigned FROM local_const)),
                      -- chown
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="chown"), (SELECT String FROM local_const)),
                      ("owner", 1, (SELECT id FROM LibcHook WHERE symbol="chown"), (SELECT IntegerUnsigned FROM local_const)),
                      ("group", 2, (SELECT id FROM LibcHook WHERE symbol="chown"), (SELECT IntegerUnsigned FROM local_const)),
                      -- lchown
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="lchown"), (SELECT String FROM local_const)),
                      ("owner", 1, (SELECT id FROM LibcHook WHERE symbol="lchown"), (SELECT IntegerUnsigned FROM local_const)),
                      ("group", 2, (SELECT id FROM LibcHook WHERE symbol="lchown"), (SELECT IntegerUnsigned FROM local_const)),
                      -- fchown
                      ("fd", 0, (SELECT id FROM LibcHook WHERE symbol="fchown"), (SELECT IntegerSigned FROM local_const)),
                      ("owner", 1, (SELECT id FROM LibcHook WHERE symbol="fchown"), (SELECT IntegerUnsigned FROM local_const)),
                      ("group", 2, (SELECT id FROM LibcHook WHERE symbol="fchown"), (SELECT IntegerUnsigned FROM local_const)),
                      -- fchownat
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="fchownat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="fchownat"), (SELECT String FROM local_const)),
                      ("owner", 2, (SELECT id FROM LibcHook WHERE symbol="fchownat"), (SELECT IntegerUnsigned FROM local_const)),
                      ("group", 3, (SELECT id FROM LibcHook WHERE symbol="fchownat"), (SELECT IntegerUnsigned FROM local_const)),
                      ("flags", 4, (SELECT id FROM LibcHook WHERE symbol="fchownat"), (SELECT IntegerSigned FROM local_const)),
                      -- link
                      ("oldpath", 0, (SELECT id FROM LibcHook WHERE symbol="link"), (SELECT String FROM local_const)),
                      ("newpath", 1, (SELECT id FROM LibcHook WHERE symbol="link"), (SELECT String FROM local_const)),
                      -- linkat
                      ("olddirfd", 0, (SELECT id FROM LibcHook WHERE symbol="linkat"), (SELECT IntegerSigned FROM local_const)),
                      ("oldpath", 1, (SELECT id FROM LibcHook WHERE symbol="linkat"), (SELECT String FROM local_const)),
                      ("newdirfd", 2, (SELECT id FROM LibcHook WHERE symbol="linkat"), (SELECT IntegerSigned FROM local_const)),
                      ("newpath", 3, (SELECT id FROM LibcHook WHERE symbol="linkat"), (SELECT String FROM local_const)),
                      ("flags", 4, (SELECT id FROM LibcHook WHERE symbol="linkat"), (SELECT IntegerSigned FROM local_const)),
                      -- symlink
                      ("target", 0, (SELECT id FROM LibcHook WHERE symbol="symlink"), (SELECT String FROM local_const)),
                      ("linkpath", 1, (SELECT id FROM LibcHook WHERE symbol="symlink"), (SELECT String FROM local_const)),
                      -- symlinkat
                      ("target", 0, (SELECT id FROM LibcHook WHERE symbol="symlinkat"), (SELECT String FROM local_const)),
                      ("newdirfd", 1, (SELECT id FROM LibcHook WHERE symbol="symlinkat"), (SELECT IntegerSigned FROM local_const)),
                      ("linkpath", 2, (SELECT id FROM LibcHook WHERE symbol="symlinkat"), (SELECT String FROM local_const)),
                      -- rename
                      ("oldpath", 0, (SELECT id FROM LibcHook WHERE symbol="rename"), (SELECT String FROM local_const)),
                      ("newpath", 1, (SELECT id FROM LibcHook WHERE symbol="rename"), (SELECT String FROM local_const)),
                      -- renameat
                      ("olddirfd", 0, (SELECT id FROM LibcHook WHERE symbol="renameat"), (SELECT IntegerSigned FROM local_const)),
                      ("oldpath", 1, (SELECT id FROM LibcHook WHERE symbol="renameat"), (SELECT String FROM local_const)),
                      ("newdirfd", 2, (SELECT id FROM LibcHook WHERE symbol="renameat"), (SELECT IntegerSigned FROM local_const)),
                      ("newpath", 3, (SELECT id FROM LibcHook WHERE symbol="renameat"), (SELECT String FROM local_const)),
                      -- renameat2
                      ("olddirfd", 0, (SELECT id FROM LibcHook WHERE symbol="renameat2"), (SELECT IntegerSigned FROM local_const)),
                      ("oldpath", 1, (SELECT id FROM LibcHook WHERE symbol="renameat2"), (SELECT String FROM local_const)),
                      ("newdirfd", 2, (SELECT id FROM LibcHook WHERE symbol="renameat2"), (SELECT IntegerSigned FROM local_const)),
                      ("newpath", 3, (SELECT id FROM LibcHook WHERE symbol="renameat2"), (SELECT String FROM local_const)),
                      ("flags", 4, (SELECT id FROM LibcHook WHERE symbol="renameat2"), (SELECT IntegerUnsigned FROM local_const)),
                      -- mkdir
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="mkdir"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="mkdir"), (SELECT IntegerUnsigned FROM local_const)),
                      -- mkdirat
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="mkdirat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="mkdirat"), (SELECT String FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="mkdirat"), (SELECT IntegerUnsigned FROM local_const)),
                      -- rmdir
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="rmdir"), (SELECT String FROM local_const)),
                      -- unlink
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="unlink"), (SELECT String FROM local_const)),
                      -- unlinkat
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="unlinkat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="unlinkat"), (SELECT String FROM local_const)),
                      ("flags", 2, (SELECT id FROM LibcHook WHERE symbol="unlinkat"), (SELECT IntegerSigned FROM local_const)),
                      -- truncate
                      ("path", 0, (SELECT id FROM LibcHook WHERE symbol="truncate"), (SELECT String FROM local_const)),
                      ("length", 1, (SELECT id FROM LibcHook WHERE symbol="truncate"), (SELECT LongSigned FROM local_const)),
                      -- truncate64
                      ("path", 0, (SELECT id FROM LibcHook WHERE symbol="truncate64"), (SELECT String FROM local_const)),
                      ("length", 1, (SELECT id FROM LibcHook WHERE symbol="truncate64"), (SELECT LongSigned FROM local_const)),
                      -- ftruncate
                      ("fd", 0, (SELECT id FROM LibcHook WHERE symbol="ftruncate"), (SELECT IntegerSigned FROM local_const)),
                      ("length", 1, (SELECT id FROM LibcHook WHERE symbol="ftruncate"), (SELECT LongSigned FROM local_const)),
                      -- ftruncate64
                      ("fd", 0, (SELECT id FROM LibcHook WHERE symbol="ftruncate64"), (SELECT IntegerSigned FROM local_const)),
                      ("length", 1, (SELECT id FROM LibcHook WHERE symbol="ftruncate64"), (SELECT LongSigned FROM local_const)),
                      -- mknod
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="mknod"), (SELECT String FROM local_const)),
                      ("mode", 1, (SELECT id FROM LibcHook WHERE symbol="mknod"), (SELECT IntegerUnsigned FROM local_const)),
                      ("dev", 2, (SELECT id FROM LibcHook WHERE symbol="mknod"), (SELECT LongUnsigned FROM local_const)),
                      -- mknodat
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="mknodat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="mknodat"), (SELECT String FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="mknodat"), (SELECT IntegerUnsigned FROM local_const)),
                      ("dev", 3, (SELECT id FROM LibcHook WHERE symbol="mknodat"), (SELECT LongUnsigned FROM local_const)),
                      -- __open64_2
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="__open64_2"), (SELECT String FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibcHook WHERE symbol="__open64_2"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="__open64_2"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- __open64
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="__open64"), (SELECT String FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibcHook WHERE symbol="__open64"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="__open64"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- __openat64_2
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="__openat64_2"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="__openat64_2"), (SELECT String FROM local_const)),
                      ("flags", 2, (SELECT id FROM LibcHook WHERE symbol="__openat64_2"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 3, (SELECT id FROM LibcHook WHERE symbol="__openat64_2"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- __openat_2
                      ("dirfd", 0, (SELECT id FROM LibcHook WHERE symbol="__openat_2"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="__openat_2"), (SELECT String FROM local_const)),
                      ("flags", 2, (SELECT id FROM LibcHook WHERE symbol="__openat_2"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 3, (SELECT id FROM LibcHook WHERE symbol="__openat_2"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- __open_2
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="__open_2"), (SELECT String FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibcHook WHERE symbol="__open_2"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="__open_2"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- __open
                      ("pathname", 0, (SELECT id FROM LibcHook WHERE symbol="__open"), (SELECT String FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibcHook WHERE symbol="__open"), (SELECT IntegerSigned FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="__open"), (SELECT IntegerUnsignedVariadic FROM local_const)),
                      -- __xmknod
                      ("ver", 0, (SELECT id FROM LibcHook WHERE symbol="__xmknod"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 1, (SELECT id FROM LibcHook WHERE symbol="__xmknod"), (SELECT String FROM local_const)),
                      ("mode", 2, (SELECT id FROM LibcHook WHERE symbol="__xmknod"), (SELECT IntegerUnsigned FROM local_const)),
                      ("dev", 3, (SELECT id FROM LibcHook WHERE symbol="__xmknod"), (SELECT LongUnsigned FROM local_const)),
                      -- __xmknodat
                      ("ver", 0, (SELECT id FROM LibcHook WHERE symbol="__xmknodat"), (SELECT IntegerSigned FROM local_const)),
                      ("dirfd", 1, (SELECT id FROM LibcHook WHERE symbol="__xmknodat"), (SELECT IntegerSigned FROM local_const)),
                      ("pathname", 2, (SELECT id FROM LibcHook WHERE symbol="__xmknodat"), (SELECT String FROM local_const)),
                      ("mode", 3, (SELECT id FROM LibcHook WHERE symbol="__xmknodat"), (SELECT IntegerUnsigned FROM local_const)),
                      ("dev", 4, (SELECT id FROM LibcHook WHERE symbol="__xmknodat"), (SELECT LongUnsigned FROM local_const)),
                      -- Network
                      -- accept
                      ("sockfd", 0, (SELECT id FROM LibcHook WHERE symbol="accept"), (SELECT IntegerSigned FROM local_const)),
                      ("addr", 1, (SELECT id FROM LibcHook WHERE symbol="accept"), (SELECT StructPointer FROM local_const)),
                      ("addrlen", 2, (SELECT id FROM LibcHook WHERE symbol="accept"), (SELECT IntegerUnsignedPointer FROM local_const)),
                      -- accept4
                      ("sockfd", 0, (SELECT id FROM LibcHook WHERE symbol="accept4"), (SELECT IntegerSigned FROM local_const)),
                      ("addr", 1, (SELECT id FROM LibcHook WHERE symbol="accept4"), (SELECT StructPointer FROM local_const)),
                      ("addrlen", 2, (SELECT id FROM LibcHook WHERE symbol="accept4"), (SELECT IntegerUnsignedPointer FROM local_const)),
                      ("flags", 3, (SELECT id FROM LibcHook WHERE symbol="accept4"), (SELECT IntegerSigned FROM local_const)),
                      -- bind
                      ("sockfd", 0, (SELECT id FROM LibcHook WHERE symbol="bind"), (SELECT IntegerSigned FROM local_const)),
                      ("addr", 1, (SELECT id FROM LibcHook WHERE symbol="bind"), (SELECT StructPointer FROM local_const)),
                      ("addrlen", 2, (SELECT id FROM LibcHook WHERE symbol="bind"), (SELECT IntegerUnsigned FROM local_const)),
                      -- connect
                      ("sockfd", 0, (SELECT id FROM LibcHook WHERE symbol="connect"), (SELECT IntegerSigned FROM local_const)),
                      ("addr", 1, (SELECT id FROM LibcHook WHERE symbol="connect"), (SELECT StructPointer FROM local_const)),
                      ("addrlen", 2, (SELECT id FROM LibcHook WHERE symbol="connect"), (SELECT IntegerUnsigned FROM local_const)));

-- ActionArgument
INSERT INTO ActionArgument (value, next)
WITH local_const AS (SELECT ((SELECT LibraryPath FROM global_const) || "libc.so.6") AS libc)
SELECT * FROM (VALUES -- AddInt
                      -- ModifyInt
                      ("0", NULL), -- LM_ID_BASE
                      -- RedirectFunction
                      ("execve", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("posix_spawn", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("ftruncate", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("ftruncate64", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("fdopen", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("symlinkat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("mkdirat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("unlinkat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("linkat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("renameat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("fchownat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("fchmodat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("openat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("openat64", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("mknodat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("__openat_2", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("__openat64_2", NULL), ((SELECT libc FROM local_const), last_insert_rowid()),
                      ("__xmknodat", NULL), ((SELECT libc FROM local_const), last_insert_rowid()));

-- Rule
INSERT INTO Rule (hook, position, action, actionarg)
WITH local_const AS (SELECT ((SELECT LibraryPath FROM global_const) || "libc.so.6") AS libc,
                            (SELECT id FROM Action WHERE name="AddEnvironment") AS AddEnvironment,
                            (SELECT id FROM Action WHERE name="AddInt") AS AddInt,
                            (SELECT id FROM Action WHERE name="CanonicalizePath") AS CanonicalizePath,
                            (SELECT id FROM Action WHERE name="CombineDirectory") AS CombineDirectory,
                            (SELECT id FROM Action WHERE name="ConsumeVariadic") AS ConsumeVariadic,
                            (SELECT id FROM Action WHERE name="FilterEnvironment") AS FilterEnvironment,
                            (SELECT id FROM Action WHERE name="ModifyInt") AS ModifyInt,
                            (SELECT id FROM Action WHERE name="OpenFileDescriptor") AS OpenFileDescriptor,
                            (SELECT id FROM Action WHERE name="RedirectFunction") AS RedirectFunction,
                            (SELECT id FROM Action WHERE name="SplitFilePath") AS SplitFilePath,
                            (SELECT id FROM Action WHERE name="VerifyCanExecute") AS VerifyCanExecute,
                            (SELECT id FROM Action WHERE name="VerifyCanTerminate") AS VerifyCanTerminate,
                            (SELECT id FROM Action WHERE name="VerifyCanWrite") AS VerifyCanWrite,
                            (SELECT id FROM Action WHERE name="VerifyFileHash") AS VerifyFileHash)
SELECT * FROM (VALUES -- Execution
                      -- Canonicalize path for exec*p* and posix_spawnp
                      -- TODO: Should the path in all exec* hooks be canonicalized here to reduce the size of the whitelist?
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), 0, (SELECT CanonicalizePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvp"), 0, (SELECT CanonicalizePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvpe"), 0, (SELECT CanonicalizePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), 1, (SELECT CanonicalizePath FROM local_const), NULL),
                      -- Check if the target is a whitelisted executable (TOCTOU prevented by Filesystem hooks)
                      ((SELECT id FROM LibcHook WHERE symbol="execl"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execle"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execv"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execve"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvp"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvpe"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fexecve"), 0, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawn"), 1, (SELECT VerifyCanExecute FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), 1, (SELECT VerifyCanExecute FROM local_const), NULL),
                      -- Check if the executable hash is whitelisted (TOCTOU prevented by Filesystem hooks)
                      ((SELECT id FROM LibcHook WHERE symbol="execl"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execle"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execv"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execve"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvp"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvpe"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fexecve"), 0, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawn"), 1, (SELECT VerifyFileHash FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), 1, (SELECT VerifyFileHash FROM local_const), NULL),
                      -- Convert execl* variadic parameters into an array
                      ((SELECT id FROM LibcHook WHERE symbol="execl"), 1, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execle"), 1, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), 1, (SELECT ConsumeVariadic FROM local_const), NULL),
                      -- Add environment parameter if it's not present
                      ((SELECT id FROM LibcHook WHERE symbol="execl"), 2, (SELECT AddEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), 2, (SELECT AddEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execv"), 2, (SELECT AddEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvp"), 2, (SELECT AddEnvironment FROM local_const), NULL),
                      -- Filter environment parameter
                      ((SELECT id FROM LibcHook WHERE symbol="execl"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execle"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execv"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execve"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvp"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="execvpe"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fexecve"), 2, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawn"), 5, (SELECT FilterEnvironment FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), 5, (SELECT FilterEnvironment FROM local_const), NULL),
                      -- Redirect exec* to execve
                      ((SELECT id FROM LibcHook WHERE symbol="execl"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="execle"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="execlp"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="execv"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="execvp"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="execvpe"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="execve" AND next IS NULL))),
                      -- Redirect posix_spawnp to posix_spawn
                      ((SELECT id FROM LibcHook WHERE symbol="posix_spawnp"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="posix_spawn" AND next IS NULL))),
                      -- Disallow killing the WhiteBeam service (TODO: pidfd_send_signal support for Linux >=5.1)
                      ((SELECT id FROM LibcHook WHERE symbol="kill"), 0, (SELECT VerifyCanTerminate FROM local_const), NULL),
                      -- Filesystem
                      -- Open file descriptor for the target path
                      ((SELECT id FROM LibcHook WHERE symbol="fopen"), 0, (SELECT OpenFileDescriptor FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fopen64"), 0, (SELECT OpenFileDescriptor FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="truncate"), 0, (SELECT OpenFileDescriptor FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="truncate64"), 0, (SELECT OpenFileDescriptor FROM local_const), NULL),
                      -- Open directory file descriptor
                      ((SELECT id FROM LibcHook WHERE symbol="chmod"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="chown"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="creat"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="creat64"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="lchown"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="link"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="link"), 1, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="open"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="open64"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rename"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rename"), 1, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mkdir"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rmdir"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="symlink"), 1, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="unlink"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mknod"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open_2"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64_2"), 0, (SELECT SplitFilePath FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__xmknod"), 1, (SELECT SplitFilePath FROM local_const), NULL),
                      -- Combine directory components in *at* functions to prevent directory traversal race conditions
                      ((SELECT id FROM LibcHook WHERE symbol="fchmodat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fchownat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="linkat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="linkat"), 2, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="openat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="openat64"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat"), 2, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat2"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat2"), 2, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mkdirat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="symlinkat"), 1, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="unlinkat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mknodat"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__openat_2"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__openat64_2"), 0, (SELECT CombineDirectory FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__xmknodat"), 1, (SELECT CombineDirectory FROM local_const), NULL),
                      -- Check if the target directory is whitelisted (if this is a write operation)
                      ((SELECT id FROM LibcHook WHERE symbol="chmod"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="chown"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="creat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="creat64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="lchown"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="link"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="link"), 2, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="open"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="open64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rename"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rename"), 2, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mkdir"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rmdir"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="symlink"), 1, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="unlink"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mknod"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open_2"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64_2"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__xmknod"), 1, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="truncate"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="truncate64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fopen"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fopen64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fchmod"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fchown"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fdopen"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="ftruncate"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="ftruncate64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fchmodat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="fchownat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="linkat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="linkat"), 2, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="openat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="openat64"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat"), 2, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat2"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="renameat2"), 2, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mkdirat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="symlinkat"), 1, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="unlinkat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="mknodat"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__openat_2"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__openat64_2"), 0, (SELECT VerifyCanWrite FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__xmknodat"), 1, (SELECT VerifyCanWrite FROM local_const), NULL),
                      -- Convert variadic parameters into regular parameters
                      ((SELECT id FROM LibcHook WHERE symbol="open"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="open64"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="openat"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="openat64"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open_2"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64_2"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__openat_2"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="__openat64_2"), 3, (SELECT ConsumeVariadic FROM local_const), NULL),
                      -- Add open flags
                      ((SELECT id FROM LibcHook WHERE symbol="chmod"), 3, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="chown"), 4, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="creat"), NULL, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="creat64"), NULL, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="lchown"), 4, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="link"), 4, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="rmdir"), 2, (SELECT AddInt FROM local_const), NULL),
                      ((SELECT id FROM LibcHook WHERE symbol="unlink"), 2, (SELECT AddInt FROM local_const), NULL),
                      -- Redirect to TOCTOU safe function (*at/f*)
                      ((SELECT id FROM LibcHook WHERE symbol="symlink"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="symlinkat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="unlink"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="unlinkat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="mkdir"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="mkdirat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="rmdir"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="unlinkat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="link"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="linkat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="rename"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="renameat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="chown"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="fchownat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="lchown"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="fchownat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="chmod"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="fchmodat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="creat"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="openat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="open"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="openat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="creat64"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="openat64" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="open64"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="openat64" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="mknod"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="mknodat" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="truncate"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="ftruncate" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="truncate64"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="ftruncate64" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="fopen"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="fdopen" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="fopen64"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="fdopen" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="__open"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="__openat_2" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="__open_2"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="__openat_2" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="__openat64_2" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="__open64_2"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="__openat64_2" AND next IS NULL))),
                      ((SELECT id FROM LibcHook WHERE symbol="__xmknod"), NULL, (SELECT RedirectFunction FROM local_const), (SELECT id FROM ActionArgument WHERE value=(SELECT libc FROM local_const) AND next=(SELECT id FROM ActionArgument WHERE value="__xmknodat" AND next IS NULL))));

COMMIT;
