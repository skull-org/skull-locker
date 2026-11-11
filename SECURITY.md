# Security policy

skull-locker protects people's files, so a security problem in it matters more than any other bug.

**Please do not open a public issue for a vulnerability.** Report it privately through GitHub's
[private vulnerability reporting](https://github.com/skull-org/skull-locker/security/advisories/new),
or by email to founder@adris.tech.

Please include what you found, how to reproduce it, and which version (`pip show skull-locker`). We will confirm
receipt within 3 working days, tell you what we will do, and credit you in the fix unless you prefer not to be named.

## Scope

In scope: anything that lets someone read a locked file without the password or recovery key, change one without
being detected, make the original disappear without a complete locked copy, or make unlocking write outside the
chosen folder.

Out of scope: malware already on the user's computer, weak passwords chosen by the user, and copies of the original
kept by other software (backups, cloud history). These are listed in the README as things the tool does not protect
against.
