# AIX security baseline audit: the high-impact misconfigurations to catch

AIX and VIOS are extraordinarily stable, and that stability breeds silence. Systems run for years without a reboot, the person who built them has retired, and nobody is quite sure what is exposed. An audit is how you replace assumption with evidence.

This is a focused, honest walkthrough of the **security baseline** checks that matter most — the low-effort misconfigurations that turn a minor foothold into a serious incident. Written the way an administrator actually works, with the real commands. At the end we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — collects the same evidence in one pass.

**Honesty note.** This is a security baseline audit, not a full security assessment or penetration test. It catches the common, high-impact misconfigurations any administrator can verify by hand or with a read-only tool. It does not test application logic, find zero-days, or simulate an attacker's full toolkit. When evidence is missing or unreadable, the answer is "not assessed" — not a hopeful "looks fine."

## 1. Password hashing algorithm — what is the system actually using?

Check the password hashing algorithm configured for user accounts. Older AIX installations may default to `crypt` or even DES, both of which are considered broken by modern standards. Run `lsuser -a pwd_algorithm all` (AIX 7.2+) or inspect the algorithm attribute on individual accounts. On AIX 7.2, supported algorithms include `blowfish`, `sha256`, and `sha512`. On earlier releases, you may only have `crypt` available.

**Why it matters:** DES and `crypt` hashes are trivially cracked with modern hardware. An attacker who obtains the password file can enumerate credentials in minutes, not months. The hashing algorithm is the single biggest multiplier of password-strength risk on the box.

**What good looks like:** `sha512` (or `blowfish` where available) configured as the system default, no accounts with empty passwords, and a minimum age policy in place so credentials cannot be cycled and reused instantly. If the system is on an older AIX level that only supports `crypt`, flag it as a known limitation and plan an upgrade path — do not pretend it is acceptable.

## 2. NFS exports — who can see your filesystems?

Review NFS exports carefully. A world-readable export (`/` with `ro,root=*,`) gives any host on the network read access to your entire filesystem tree. Run `exportfs -v` to see what is currently exported and with which options, then cross-check against `/etc/exports` for persistence. Look for exports that use `*` as the host specifier, `no_root_squash`, or write access to sensitive mounts like `/` or `/home`.

**Why it matters:** an over-broad NFS export is a free pass for lateral movement. Anyone who can reach the NFS port and mount your filesystem gets the same access as the export options allow. This is the single most common source of "I didn't know that was exposed" in AIX incident post-mortems.

**What good looks like:** NFS exports scoped to specific hostnames or subnets, `root_squash` enabled on all writable mounts, no world-readable exports of sensitive filesystems, and `/etc/exports` matching `exportfs -v` (no stale entries). If NFS is not needed, the exports should be empty and the daemons stopped.

## 3. Remote access and privileged accounts — who can log in and as whom?

Check which accounts have remote login enabled (`lsuser -a rlogin`), which are in the `system` group or have `admin` role (`lsuser -a roles`), and whether `root` remote login is permitted (`lsconf`, `/etc/security/login.cfg`). Look for non-operator accounts with `shell` set to `/bin/ksh`. Check `lsgroup` for `system` and `wheel` — are there accounts that should not be there?

Check SSH if in use: review `/etc/ssh/sshd_config` for `PermitRootLogin` and key-based auth.

**Why it matters:** every remote-access-enabled account is an additional attack surface. An unused admin account with rlogin enabled, or a developer account that was never removed after a project ended, is exactly the credential an attacker looks for during post-exploitation enumeration.

**What good looks like:** remote login restricted to known operator and administrator accounts, no unexpected accounts in `system` or `wheel`, `root` remote login disabled (or restricted to specific sources), and SSH configured for key-based authentication with root login explicitly controlled.

## How these low-effort findings turn a foothold into an incident

The pattern is almost always the same: an attacker gains initial access through a vector you cannot fully control — a vendor jump box, a compromised credential from a third party, a physical USB stick left in a lobby. What turns that foothold into an incident is what happens next on your systems.

- Weak password hashing (`crypt` or DES) means the attacker can crack credentials they harvest and move laterally with admin accounts you did not know existed.
- Over-broad NFS exports let them read filesystems they should never see — customer data, internal documentation, other people's keys.
- Unexpected privileged remote access gives a clean path to escalate and pivot — no vulnerability exploit needed.

None of these require a penetration test to find. They are configuration drift accumulated over years, verifiable in a single sitting.

## NOT_ASSESSED over guessing

A few practical notes on honesty:

- If you cannot run commands as root, some checks will be `NOT_ASSESSED` because the evidence is unreadable. An honest "not assessed" is better than a confident wrong answer.
- If NFS is not installed (`lslpp -l | grep nfs`), the export check does not apply. Do not force a conclusion where the subsystem does not exist.
- If the AIX level predates the `pwd_algorithm` attribute (pre-7.2), report the limitation and recommend an upgrade path. Do not infer security posture from silence.

## Doing this quickly and consistently: AIXray

Running these checks by hand across a single system is fast. Across a fleet, inconsistency creeps in — you check NFS carefully on one LPAR and skip it on the next.

This is exactly the gap [AIXray](https://powertruesystems.com/aixray) addresses. It collects evidence for password hashing, NFS export scope, remote access configuration, and privileged account inventory in one read-only pass, and reports findings in HTML or JSON. It does not remediate or change anything on the host, sends no assessment data off the box, and is a single inspectable ksh88 script that runs under `/bin/sh` — no install, no agent, no dependencies.

Because it is open source (Apache-2.0), you can read the source before you run it. The check manifests at [GitHub](https://github.com/PowerTrueSYS/aixray-public) document exactly which commands each check runs. Download it, review it, copy it to the host, and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` in the current directory — open it in a browser or save as PDF.

## If you'd rather have it fixed and watched

Running the audit tells you where you stand. Acting on it is the next question. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers — if your report surfaces things you'd rather not carry alone, we can help you remediate and keep systems monitored over time. That is entirely optional. The tool is free and yours to use forever, whether or not we ever talk. Run the audit, keep the evidence, and decide from there.
