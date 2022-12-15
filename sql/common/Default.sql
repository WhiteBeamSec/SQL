BEGIN;

-- WhitelistClass
INSERT INTO WhitelistClass (class) VALUES ("Hash/SHA3-256"),
                                          ("Hash/SHA3-512"),
                                          ("Hash/BLAKE3"),
                                          ("Filesystem/Directory/Writable"),
                                          ("Filesystem/Path/Executable"),
                                          ("Filesystem/Path/Library"),
                                          ("Network/Range/Accept"),
                                          ("Network/Range/Bind"),
                                          ("Network/Range/Connect"),
                                          ("Certificate/DER"),
                                          ("Certificate/PEM");

-- LogFacility: id is equal to the facility
INSERT INTO LogFacility (id, facility) VALUES (0, "Kernel"),
                                              (1, "User"),
                                              (2, "Mail"),
                                              (3, "Daemon"),
                                              (4, "Auth"),
                                              (5, "Syslog"),
                                              (6, "LPR"),
                                              (7, "News"),
                                              (8, "UUCP"),
                                              (9, "Cron"),
                                              (10, "AuthPriv"),
                                              (11, "FTP"),
                                              (16, "Local0"),
                                              (17, "Local1"),
                                              (18, "Local2"),
                                              (19, "Local3"),
                                              (20, "Local4"),
                                              (21, "Local5"),
                                              (22, "Local6"),
                                              (23, "Local7");

-- LogSeverity: id is equal to the severity
INSERT INTO LogSeverity (severity) VALUES ("Emergency"),("Alert"),("Critical"),("Error"),("Warning"),("Notice"),("Info"),("Debug");

-- Setting
INSERT INTO Setting (param, value) VALUES ("ConsoleSecret", "undefined"),
                                          ("ConsoleSecretExpiry", "-1"),
                                          ("EncryptAlgorithm", "XCHACHA20POLY1305"),
                                          ("HashAlgorithm", "BLAKE3"),
                                          ("LogFacility", CAST((SELECT id FROM LogFacility WHERE facility="Local0") AS TEXT)),
                                          ("LogSeverity", CAST((SELECT id FROM LogSeverity WHERE severity="Notice") AS TEXT)),
                                          ("Prevention", "false"),
                                          ("RecoverySecret", "undefined"),
                                          ("Repository", "https://github.com/WhiteBeamSec/SQL/blob/master"),
                                          ("RotateNonceLimit", "3600"),
                                          ("SecretAlgorithm", "ARGON2ID"),
                                          ("ServerIP", "undefined"),
                                          ("ServerPublicKey", "undefined"),
                                          ("ServerType", "undefined"),
                                          ("ServicePort", "11998"),
                                          ("SettingsModified", "-1"), -- TODO: Still needed?
                                          ("SystemArchitecture", "undefined"),
                                          ("SystemLibraryPath", "undefined");

-- Action
INSERT INTO Action (name) VALUES ("AddEnvironment"),
                                 ("AddInt"),
                                 ("CanonicalizePath"),
                                 ("CombineDirectory"),
                                 ("ConsumeVariadic"),
                                 ("FilterEnvironment"),
                                 ("ModifyInt"),
                                 ("ModifyString"),
                                 ("OpenFileDescriptor"),
                                 ("PopulateTemplate"),
                                 ("PrintArguments"),
                                 ("RedirectFunction"),
                                 ("SplitFilePath"),
                                 ("VerifyCanConnect"),
                                 ("VerifyCanExecute"),
                                 ("VerifyCanTerminate"),
                                 ("VerifyCanWrite"),
                                 ("VerifyFileHash");

-- HookClass
INSERT INTO HookClass (class) VALUES ("Execution"),("Filesystem"),("Network"),("Certificate"),("Bruteforce"),("MemoryProtection"),("Patch");

-- HookLanguage
INSERT INTO HookLanguage (language) VALUES ("C"),("C++"),("Java"),("PHP"),("Python"),("Ruby");

-- Datatype: 32/64 bit determined with usize
INSERT INTO Datatype (datatype, pointer, signed, variadic, array) VALUES ("String", 1, 0, 0, 0),
                                                                         ("StringArray", 1, 0, 0, 1),
                                                                         ("StringVariadic", 1, 0, 1, 0),
                                                                         ("IntegerSigned", 0, 1, 0, 0),
                                                                         ("IntegerSignedPointer", 1, 1, 0, 0),
                                                                         ("IntegerUnsigned", 0, 0, 0, 0),
                                                                         ("IntegerUnsignedPointer", 1, 0, 0, 0),
                                                                         ("IntegerUnsignedVariadic", 0, 0, 1, 0),
                                                                         ("LongSigned", 0, 1, 0, 0),
                                                                         ("LongUnsigned", 0, 0, 0, 0),
                                                                         ("Struct", 0, 0, 0, 0),
                                                                         ("StructPointer", 1, 0, 0, 0);

COMMIT;
