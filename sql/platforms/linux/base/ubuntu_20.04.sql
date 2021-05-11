INSERT INTO Whitelist (path, value, class) VALUES ('ANY','/bin/cat', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/bin/grep', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/bin/lesspipe', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/bin/ls', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/bin/uname', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/00-header', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/10-help-text', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/50-motd-news', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/85-fwupd', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/90-updates-available', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/91-release-upgrade', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/92-unattended-upgrades', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/95-hwe-eol', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/97-overlayroot', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/98-fsck-at-reboot', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/etc/update-motd.d/98-reboot-required', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/home/ubuntu/**', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable")),
                                                  ('ANY','libaudit.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libcap-ng.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libcap.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libcom_err.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libcrypto.so.1.0.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libcrypto.so.1.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libcrypt.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libgcrypt.so.20', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libgpg-error.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libgssapi_krb5.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libk5crypto.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libkeyutils.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libkrb5.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libkrb5support.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','liblz4.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','liblzma.so.5', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libnsl.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libnss_compat.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libnss_files.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libnss_systemd.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libpam_misc.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libpam.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libpcre.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libprocps.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libprocps.so.8', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libresolv.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libssl.so.1.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libsystemd.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libtinfo.so.5', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libutil.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libwrap.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libaudit.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libcap-ng.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libcap.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libcom_err.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libcrypto.so.1.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libcrypt.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libgcrypt.so.20', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libgpg-error.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libgssapi_krb5.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libk5crypto.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libkeyutils.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libkrb5.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libkrb5support.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/liblz4.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/liblzma.so.5', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libnsl.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libnss_compat.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libnss_files.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libnss_systemd.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libpam_misc.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libpam.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libpcre.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libprocps.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libprocps.so.8', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libresolv.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libssl.so.1.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libsystemd.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libtinfo.so.5', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libutil.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libwrap.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/libz.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_cap.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_deny.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_env.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_keyinit.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_limits.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_loginuid.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_mail.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_motd.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_nologin.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_permit.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_selinux.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_systemd.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_umask.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/lib/x86_64-linux-gnu/security/pam_unix.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','libz.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/opt/WhiteBeam/libwhitebeam.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_cap.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_deny.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_env.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_keyinit.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_limits.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_loginuid.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_mail.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_motd.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_nologin.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_permit.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_selinux.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_systemd.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_umask.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','pam_unix.so', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/run/**', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable")),
                                                  ('ANY','/usr/bin/basename', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/cat', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/clear_console', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/dircolors', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/dirname', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/env', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/grep', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/groups', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/id', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/lesspipe', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/locale-check', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/ls', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/mesg', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/run-parts', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/uname', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/which', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/bin/w.procps', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libk5crypto.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libkrb5.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libkrb5support.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/liblz4.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/lib/x86_64-linux-gnu/libssl.so.1.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('ANY','/usr/share/landscape/landscape-sysinfo.wrapper', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Executable")),
                                                  ('/bin/bash', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/bin/bash','libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/bash','/lib/x86_64-linux-gnu/libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/cat', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/bin/grep', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/bin/grep','libpcre.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/grep','/lib/x86_64-linux-gnu/libpcre.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/lesspipe', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/bin/ls', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/bin/ls','libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/ls','libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/ls','/lib/x86_64-linux-gnu/libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/ls','/lib/x86_64-linux-gnu/libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/bin/sh', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/bin/uname', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/00-header', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/10-help-text', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/50-motd-news', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/85-fwupd', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/90-updates-available', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/91-release-upgrade', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/92-unattended-upgrades', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/95-hwe-eol', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/97-overlayroot', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/98-fsck-at-reboot', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/etc/update-motd.d/98-reboot-required', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/opt/WhiteBeam/whitebeam', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/basename', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/bash', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/bash','libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/bash','/lib/x86_64-linux-gnu/libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/cat', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/clear_console', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/clear_console','libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/clear_console','/lib/x86_64-linux-gnu/libtinfo.so.6', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/dircolors', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/dirname', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/env', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/grep', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/grep','libpcre.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/grep','/lib/x86_64-linux-gnu/libpcre.so.3', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/groups', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/id', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/id','libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/id','libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/id','/lib/x86_64-linux-gnu/libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/id','/lib/x86_64-linux-gnu/libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/lesspipe', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/locale-check', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/ls', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/ls','libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/ls','libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/ls','/lib/x86_64-linux-gnu/libpcre2-8.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/ls','/lib/x86_64-linux-gnu/libselinux.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/mesg', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/run-parts', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/sh', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/uname', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/which', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/w.procps', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3")),
                                                  ('/usr/bin/w.procps','libgcrypt.so.20', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','libgpg-error.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','liblz4.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','liblzma.so.5', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','libprocps.so.8', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','libsystemd.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','/lib/x86_64-linux-gnu/libgcrypt.so.20', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','/lib/x86_64-linux-gnu/libgpg-error.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','/lib/x86_64-linux-gnu/liblz4.so.1', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','/lib/x86_64-linux-gnu/liblzma.so.5', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','/lib/x86_64-linux-gnu/libprocps.so.8', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/bin/w.procps','/lib/x86_64-linux-gnu/libsystemd.so.0', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Path/Library")),
                                                  ('/usr/sbin/sshd','/var/log/', (SELECT id FROM WhitelistClass WHERE class="Filesystem/Directory/Writable")),
                                                  ('/usr/share/landscape/landscape-sysinfo.wrapper', 'ANY', (SELECT id FROM WhitelistClass WHERE class="Hash/BLAKE3"));