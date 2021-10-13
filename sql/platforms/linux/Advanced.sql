BEGIN;

/*
Title: Advanced
Description: Hooks and rules to protect against advanced attacks
Publisher: WhiteBeam Security, Inc.
Version: 0.2.6
*/

-- TODO: mkfifo*?
-- TODO 0.3.0: RedirectFunction all MemoryProtection functions to FORTIFY_SOURCE equivalents?

-- Hook
INSERT INTO Hook (symbol, library, enabled, language, class)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES -- TODO: Certificate
                      -- Bruteforce
                      ("pam_authenticate", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpam.so.0", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="Bruteforce")),
                      -- MemoryProtection
                      ("gets", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="MemoryProtection")),
                      ("strcat", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="MemoryProtection")),
                      ("strcpy", "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6", 0, (SELECT id FROM HookLanguage WHERE language="C"), (SELECT id FROM HookClass WHERE class="MemoryProtection")));

-- Argument
INSERT INTO Argument (name, position, hook, datatype)
WITH const (arch) AS (SELECT value FROM Setting WHERE param="SystemArchitecture")
SELECT * FROM (VALUES -- TODO: Certificate
                      -- Bruteforce
                      -- pam_authenticate
                      ("pamh", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpam.so.0" AND symbol="pam_authenticate"), (SELECT id FROM Datatype WHERE datatype="StructPointer")),
                      ("flags", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libpam.so.0" AND symbol="pam_authenticate"), (SELECT id FROM Datatype WHERE datatype="IntegerSigned")),
                      -- MemoryProtection
                      -- gets
                      ("s", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="gets"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- strcat
                      ("dest", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="strcat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("src", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="strcat"), (SELECT id FROM Datatype WHERE datatype="String")),
                      -- strcpy
                      ("dest", 0, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="strcpy"), (SELECT id FROM Datatype WHERE datatype="String")),
                      ("src", 1, (SELECT id FROM Hook WHERE library = "/lib/" || (SELECT const.arch FROM const) || "-linux-gnu/libc.so.6" AND symbol="strcpy"), (SELECT id FROM Datatype WHERE datatype="String")));

-- TODO: Rule

COMMIT;
