BEGIN;

/*
Title: Essential
Description: Minimum hooks, rules, and whitelist entries required to run and protect WhiteBeam
Publisher: WhiteBeam Security, Inc.
Version: 0.2.2
*/

-- TODO Requiring race-free design:
-- Execution
--   posix_spawn
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

-- Whitelist
INSERT INTO Whitelist (path, value, class) VALUES ("ANY", "/bin/bash", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/bin/sh", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/usr/bin/bash", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/usr/bin/sh", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/opt/WhiteBeam/whitebeam", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/dev/pts/", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable")),
                                                  -- TODO: Restrict libraries below to specific applications
                                                  -- TODO: Architecture independent libraries
                                                  ("ANY", "libwhitebeam.so", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/libwhitebeam.so", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "libc.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/x86_64-linux-gnu/libc.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "libgcc_s.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/x86_64-linux-gnu/libgcc_s.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/x86_64-linux-gnu/librt.so.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "libpthread.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/x86_64-linux-gnu/libpthread.so.0", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "libm.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/x86_64-linux-gnu/libm.so.6", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "libdl.so.2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("ANY", "/lib/x86_64-linux-gnu/libdl.so.2", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("/opt/WhiteBeam/whitebeam", "libssl.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("/opt/WhiteBeam/whitebeam", "/lib/x86_64-linux-gnu/libssl.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("/opt/WhiteBeam/whitebeam", "libcrypto.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("/opt/WhiteBeam/whitebeam", "/lib/x86_64-linux-gnu/libcrypto.so.1.1", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ("/opt/WhiteBeam/whitebeam", "11998", (SELECT id FROM WhitelistClass WHERE class="Network/Range/Port"));

-- Hook
-- TODO: Make sure this reflects the libraries present on a system
INSERT INTO Hook (symbol, library, enabled, language, class) VALUES -- Execution
                                                                    ("execl", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("execle", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("execlp", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("execv", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("execve", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("execvp", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("execvpe", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("fexecve", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("dlopen", "/lib/x86_64-linux-gnu/libdl.so.2", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("dlmopen", "/lib/x86_64-linux-gnu/libdl.so.2", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    ("kill", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Execution")),
                                                                    -- Filesystem
                                                                    ("creat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("creat64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fdopen", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fopen", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fopen64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    --("freopen", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    --("freopen64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("open", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("open64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("openat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("openat64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("chmod", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchmod", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchmodat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("chown", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("lchown", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchown", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchownat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("link", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("linkat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("symlink", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("symlinkat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("rename", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("renameat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("renameat2", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("rmdir", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("unlink", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("unlinkat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("truncate", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("truncate64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("ftruncate", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("ftruncate64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("mknod", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("mknodat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__open64_2", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__open64", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__openat64_2", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__openat_2", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__open_2", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__open", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__xmknod", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("__xmknodat", "/lib/x86_64-linux-gnu/libc.so.6", 1, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    -- Network
                                                                    ("accept", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")),
                                                                    ("accept4", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")),
                                                                    ("bind", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network")),
                                                                    ("connect", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Network"));

-- Argument
INSERT INTO Argument (name, position, hook, datatype) VALUES -- Execution
                                                             -- execl
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("arg", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl"), (SELECT id FROM Datatype WHERE datatype="StringVariadic")),
                                                             -- execle
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("arg", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle"), (SELECT id FROM Datatype WHERE datatype="StringVariadic")),
                                                             ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             -- execlp
                                                             ("file", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("arg", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp"), (SELECT id FROM Datatype WHERE datatype="StringVariadic")),
                                                             -- execv
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             -- execve
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             -- execvp
                                                             ("file", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             -- execvpe
                                                             ("file", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             -- fexecve
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("argv", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             ("envp", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve"), (SELECT id FROM Datatype WHERE datatype="StringArray")),
                                                             -- dlopen
                                                             ("filename", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlopen"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- dlmopen
                                                             ("lmid", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlmopen"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                                                             ("filename", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlmopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlmopen"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- kill
                                                             ("pid", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="kill"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("sig", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="kill"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- Filesystem
                                                             -- creat
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- creat64
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- fdopen
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fdopen"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fdopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- fopen
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- fopen64
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- freopen
                                                             --("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             --("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             --("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             -- freopen64
                                                             --("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             --("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             --("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             -- open
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- open64
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- openat
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- openat64
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- chmod
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chmod"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chmod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- fchmod
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmod"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- fchmodat
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("flags", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- chown
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("owner", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("group", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- lchown
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("owner", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("group", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- fchown
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchown"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("owner", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("group", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchown"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- fchownat
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("owner", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("group", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("flags", 4, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- link
                                                             ("oldpath", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("newpath", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- linkat
                                                             ("olddirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("oldpath", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("newdirfd", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("newpath", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 4, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- symlink
                                                             ("target", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlink"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("linkpath", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlink"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- symlinkat
                                                             ("target", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlinkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("newdirfd", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlinkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("linkpath", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlinkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- rename
                                                             ("oldpath", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("newpath", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- renameat
                                                             ("olddirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("oldpath", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("newdirfd", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("newpath", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- renameat2
                                                             ("olddirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("oldpath", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("newdirfd", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("newpath", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 4, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- rmdir
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rmdir"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- unlink
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlink"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- unlinkat
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlinkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlinkat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlinkat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- truncate
                                                             ("path", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                                                             -- truncate64
                                                             ("path", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate64"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                                                             -- ftruncate
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                                                             -- ftruncate64
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate64"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
                                                             -- mknod
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknod"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("dev", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknod"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                                                             -- mknodat
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("dev", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknodat"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                                                             -- __open64_2
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- __open64
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- __openat64_2
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- __openat_2
                                                             ("dirfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- __open_2
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- __open
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedVariadic")),
                                                             -- __xmknod
                                                             ("ver", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("dev", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                                                             -- __xmknodat
                                                             ("ver", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("dirfd", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("pathname", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             ("dev", 4, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat"), (SELECT id FROM Datatype WHERE datatype="LongUnsigned")),
                                                             -- Network
                                                             -- accept
                                                             ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedPointer")),
                                                             -- accept4
                                                             ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsignedPointer")),
                                                             ("flags", 3, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="accept4"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- bind
                                                             ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="bind"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="bind"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="bind"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned")),
                                                             -- connect
                                                             ("sockfd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="connect"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("addr", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="connect"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             ("addrlen", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="connect"), (SELECT id FROM Datatype WHERE datatype="IntegerUnsigned"));

-- Rule
INSERT INTO Rule (arg, positional, action) VALUES -- Execution
                                                  -- Canonicalize path for exec*p* and dl*open
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlmopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  -- Open file descriptor for the target executable
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  -- Check if the target is a whitelisted executable (TOCTOU protected by Filesystem hooks)
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libdl.so.2" AND symbol="dlmopen") AND name="filename"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  -- Check if the executable hash is whitelisted (TOCTOU protected by Filesystem hooks)
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  -- Convert execl* variadic parameters into an array
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  -- Add environment parameter if it's not present
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  -- Filter environment parameter
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  -- Redirect to TOCTOU safe function (fexecve)
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- Disallow killing the WhiteBeam service (TODO: pidfd_send_signal support for Linux >=5.1)
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="kill") AND name="pid"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanTerminate")),
                                                  -- Filesystem
                                                  -- Open file descriptor for the target path
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate64") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="OpenFileDescriptor")),
                                                  -- Open directory file descriptor
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link") AND name="newpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename") AND name="oldpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename") AND name="newpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlink") AND name="linkpath"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknod") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="SplitFilePath")),
                                                  -- Combine directory components in *at* functions to prevent directory traversal race conditions
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlinkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlinkat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="CombineDirectory")),
                                                  -- Check if the target directory is whitelisted (if this is a write operation)
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link") AND name="newpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename") AND name="newpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlink") AND name="linkpath"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate64") AND name="path"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen64") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmod") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchown") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fdopen") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate64") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchmodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fchownat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="linkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="olddirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="renameat2") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlinkat") AND name="newdirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlinkat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknodat") AND name="dirfd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanWrite")),
                                                  -- Convert variadic parameters into regular parameters
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="openat64") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__openat64_2") AND name="mode"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  -- Add open flags
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddFlags")),
                                                  -- Redirect to TOCTOU safe function (*at/f*)
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="symlink") AND name="target"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="unlink") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rmdir") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="link") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="rename") AND name="oldpath"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="lchown") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="chmod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="creat64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="mknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate") AND name="path"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="truncate64") AND name="path"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fopen64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__open64_2") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="__xmknod") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"));

COMMIT;
