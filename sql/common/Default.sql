BEGIN;

-- WhitelistClass
INSERT INTO WhitelistClass (class) VALUES ("Hash/SHA3-256"),
                                          ("Hash/SHA3-512"),
                                          ("Hash/BLAKE3"),
                                          ("Filesystem/Path/Readable"),
                                          ("Filesystem/Path/Writable"),
                                          ("Filesystem/Path/Executable"),
                                          ("Network/Range/CIDR"),
                                          ("Network/Range/Port"),
                                          ("Certificate/DER"),
                                          ("Certificate/PEM");

-- LogClass: id is equal to the verbosity
INSERT INTO LogClass (class) VALUES ("None"),("Error"),("Auth"),("General");

-- Setting
INSERT INTO Setting (param, value) VALUES ("ConsoleSecret", "undefined"),
                                          ("ConsoleSecretExpiry", "-1"),
                                          ("HashAlgorithm", "BLAKE3"),
                                          ("LogVerbosity", CAST((SELECT id FROM LogClass WHERE class="General") AS TEXT)),
                                          ("Prevention", "false"),
                                          ("RecoverySecret", "undefined"),
                                          ("Repository", "https://github.com/WhiteBeamSec/SQL/blob/master"),
                                          ("RotateLogLimit", "10000"),
                                          ("RotateNonceLimit", "3600"),
                                          ("SecretAlgorithm", "ARGON2ID"),
                                          ("ServerIP", "undefined"),
                                          ("ServerPublicKey", "undefined"),
                                          ("ServerType", "undefined"),
                                          ("ServicePort", "11998"),
                                          ("SettingsModified", "-1"),
                                          ("TransportAlgorithm", "XCHACHA20POLY1305");

-- Action
INSERT INTO Action (name) VALUES ("AddEnvironment"),
                                 ("CanonicalizePath"),
                                 ("ConsumeVariadic"),
                                 ("FilterEnvironment"),
                                 ("RedirectFunction"),
                                 ("VerifyCanExecute"),
                                 ("VerifyFileHash");

-- HookClass
INSERT INTO HookClass (class) VALUES ("Execution"),("Filesystem"),("Network"),("Certificate"),("Bruteforce"),("MemoryProtection");

-- HookLanguage
INSERT INTO HookLanguage (language) VALUES ("C"),("Java"),("PHP"),("Python"),("Ruby");

-- Datatype: 32/64 bit determined with usize
INSERT INTO Datatype (datatype, pointer, signed, variadic, array) VALUES ("String", 1, 0, 0, 0),
                                                                         ("StringArray", 1, 0, 0, 1),
                                                                         ("StringVariadic", 1, 0, 1, 0),
                                                                         ("IntegerSigned", 0, 1, 0, 0),
                                                                         ("IntegerUnsigned", 0, 0, 0, 0),
                                                                         ("IntegerUnsignedPointer", 1, 0, 0, 0),
                                                                         ("IntegerUnsignedVariadic", 0, 0, 1, 0),
                                                                         ("Struct", 0, 0, 0, 0),
                                                                         ("StructPointer", 1, 0, 0, 0);

COMMIT;
