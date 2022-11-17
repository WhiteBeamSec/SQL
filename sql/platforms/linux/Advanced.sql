BEGIN;

/*
Title: Advanced
Description: Hooks and rules to protect against advanced attacks
Publisher: WhiteBeam Security, Inc.
Version: 0.3.0-dev
*/

-- TODO: mkfifo*?
-- TODO 0.4.0: RedirectFunction all MemoryProtection functions to FORTIFY_SOURCE equivalents?

CREATE TEMPORARY TABLE IF NOT EXISTS global_const
AS SELECT (SELECT id FROM HookLanguage WHERE language="C") AS C,
          (SELECT value FROM Setting WHERE param="SystemLibraryPath") AS LibraryPath;

-- Hook
INSERT INTO Hook (symbol, library, enabled, language, class)
WITH local_const AS (SELECT ((SELECT LibraryPath FROM global_const) || "libc.so.6") AS libc,
                            ((SELECT LibraryPath FROM global_const) || "libpam.so.0") AS libpam,
                            (SELECT id FROM HookClass WHERE class="Bruteforce") AS Bruteforce,
                            (SELECT id FROM HookClass WHERE class="MemoryProtection") AS MemoryProtection)
SELECT * FROM (VALUES -- TODO: Certificate
                      -- Bruteforce
                      ("pam_authenticate", (SELECT libpam FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT Bruteforce FROM local_const)),
                      -- MemoryProtection
                      ("gets", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT MemoryProtection FROM local_const)),
                      ("strcat", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT MemoryProtection FROM local_const)),
                      ("strcpy", (SELECT libc FROM local_const), FALSE, (SELECT C FROM global_const), (SELECT MemoryProtection FROM local_const)));

CREATE TEMPORARY VIEW LibcHook AS SELECT id, symbol FROM Hook WHERE library = (SELECT LibraryPath FROM global_const) || "libc.so.6";
CREATE TEMPORARY VIEW LibpamHook AS SELECT id, symbol FROM Hook WHERE library = (SELECT LibraryPath FROM global_const) || "libpam.so.0";

-- Argument
INSERT INTO Argument (name, position, hook, datatype)
WITH local_const AS (SELECT (SELECT id FROM Datatype WHERE datatype="IntegerSigned") AS IntegerSigned,
                            (SELECT id FROM Datatype WHERE datatype="String") AS String,
                            (SELECT id FROM Datatype WHERE datatype="StructPointer") AS StructPointer)
SELECT * FROM (VALUES -- TODO: Certificate
                      -- Bruteforce
                      -- pam_authenticate
                      ("pamh", 0, (SELECT id FROM LibpamHook WHERE symbol="pam_authenticate"), (SELECT StructPointer FROM local_const)),
                      ("flags", 1, (SELECT id FROM LibpamHook WHERE symbol="pam_authenticate"), (SELECT IntegerSigned FROM local_const)),
                      -- MemoryProtection
                      -- gets
                      ("s", 0, (SELECT id FROM LibcHook WHERE symbol="gets"), (SELECT String FROM local_const)),
                      -- strcat
                      ("dest", 0, (SELECT id FROM LibcHook WHERE symbol="strcat"), (SELECT String FROM local_const)),
                      ("src", 1, (SELECT id FROM LibcHook WHERE symbol="strcat"), (SELECT String FROM local_const)),
                      -- strcpy
                      ("dest", 0, (SELECT id FROM LibcHook WHERE symbol="strcpy"), (SELECT String FROM local_const)),
                      ("src", 1, (SELECT id FROM LibcHook WHERE symbol="strcpy"), (SELECT String FROM local_const)));

-- TODO: Rule

COMMIT;
