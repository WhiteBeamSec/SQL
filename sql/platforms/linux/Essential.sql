BEGIN;

/*
Title: Essential
Description: Minimum hooks, rules, and whitelist entries required to run and protect WhiteBeam
Publisher: WhiteBeam Security, Inc.
Version: 0.2 Alpha
*/

-- Whitelist: Libraries will go here too
INSERT INTO Whitelist (path, value, class) VALUES ("ANY", "/bin/bash", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/bin/sh", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/usr/bin/bash", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/usr/bin/sh", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ("ANY", "/opt/WhiteBeam/whitebeam", (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
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
                                                                    -- Filesystem
                                                                    ("creat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("creat64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fdopen", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fopen", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fopen64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("freopen", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("freopen64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("open", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("open64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("openat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("openat64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("open_by_handle_at", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("chmod", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchmod", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchmodat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("chown", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("lchown", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchown", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("fchownat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("link", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("linkat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("symlink", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("symlinkat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("rename", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("renameat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("renameat2", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("rmdir", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("unlink", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("unlinkat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("truncate", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("ftruncate", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
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
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             -- freopen64
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
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
                                                             -- open_by_handle_at
                                                             ("mount_fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open_by_handle_at"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("handle", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open_by_handle_at"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             ("flags", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="open_by_handle_at"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
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
                                                             -- ftruncate
                                                             ("fd", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             ("length", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="ftruncate"), (SELECT id FROM Datatype WHERE datatype="LongSigned")),
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
                                                  -- execl
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execl") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- execle
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execle") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- execlp
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="arg"), TRUE, (SELECT id FROM Action WHERE name="ConsumeVariadic")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execlp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- execv
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execv") AND name="pathname"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- execve
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="pathname"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execve") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  -- execvp
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="AddEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvp") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- execvpe
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="execvpe") AND name="file"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction")),
                                                  -- fexecve
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="CanonicalizePath")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyCanExecute")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), TRUE, (SELECT id FROM Action WHERE name="VerifyFileHash")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="envp"), TRUE, (SELECT id FROM Action WHERE name="FilterEnvironment")),
                                                  ((SELECT id FROM Argument WHERE hook=(SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="fexecve") AND name="fd"), FALSE, (SELECT id FROM Action WHERE name="RedirectFunction"));

COMMIT;
