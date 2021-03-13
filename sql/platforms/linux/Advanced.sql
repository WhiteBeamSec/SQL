BEGIN;

/*
Title: Advanced
Description: Hooks and rules to protect against advanced attacks
Publisher: WhiteBeam Security, Inc.
Version: 0.2 Alpha
*/

-- Hook
INSERT INTO Hook (symbol, library, enabled, language, class) VALUES -- Execution
                                                                    -- TODO: posix_spawn
                                                                    -- Filesystem
                                                                    -- TODO: mknod
                                                                    -- TODO: mknodat
                                                                    -- TODO: tmpfile
                                                                    -- TODO: mktemp
                                                                    -- TODO: mkdtemp
                                                                    -- TODO: mkstemp
                                                                    ("freopen", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    ("freopen64", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Filesystem")),
                                                                    -- TODO: Certificate
                                                                    -- Bruteforce
                                                                    ("pam_authenticate", "/lib/x86_64-linux-gnu/libpam.so.0", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Bruteforce")),
                                                                    -- MemoryProtection
                                                                    ("gets", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="MemoryProtection")),
                                                                    ("strcat", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="MemoryProtection")),
                                                                    ("strcpy", "/lib/x86_64-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="MemoryProtection"));

-- Argument
INSERT INTO Argument (name, position, hook, datatype) VALUES -- Execution
                                                             -- TODO: posix_spawn
                                                             -- Filesystem
                                                             -- TODO: mknod
                                                             -- TODO: mknodat
                                                             -- TODO: tmpfile
                                                             -- TODO: mktemp
                                                             -- TODO: mkdtemp
                                                             -- TODO: mkstemp
                                                             -- freopen
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             -- freopen64
                                                             ("pathname", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("mode", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("stream", 2, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="freopen64"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             -- TODO: Certificate
                                                             -- Bruteforce
                                                             -- pam_authenticate
                                                             ("pamh", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libpam.so.0" AND symbol="pam_authenticate"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                                                             ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libpam.so.0" AND symbol="pam_authenticate"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                                                             -- MemoryProtection
                                                             -- gets
                                                             ("s", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="gets"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- strcat
                                                             ("dest", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="strcat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("src", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="strcat"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             -- strcpy
                                                             ("dest", 0, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="strcpy"), (SELECT id FROM Datatype WHERE datatype="String")),
                                                             ("src", 1, (SELECT id FROM Hook WHERE library = "/lib/x86_64-linux-gnu/libc.so.6" AND symbol="strcpy"), (SELECT id FROM Datatype WHERE datatype="String"));

-- Rule
-- TODO: mktemp (-> mkstemp)

COMMIT;
