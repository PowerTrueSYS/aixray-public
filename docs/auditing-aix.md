# How to audit an IBM AIX / VIOS system — a complete, honest checklist

If you run IBM Power, you already know the quiet problem: AIX and VIOS are extraordinarily stable, and that stability breeds silence. Systems run for years without a reboot, the person who built them has retired, and nobody is quite sure what is current, what is exposed, and what would actually happen in a failure. An audit is how you replace assumption with evidence.

This is a practical, vendor-honest checklist for auditing an AIX or VIOS system end to end — what to check, why it matters, and what "good" looks like. It is written the way an administrator actually works, with the real commands. At the end of each section we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — collects the same evidence in one pass, so you can choose to do it by hand or let the tool do the gathering.

**Two ground rules for any honest audit.** First, an audit reports what is *measurably true right now*; it does not prove a system is secure, compliant, or recoverable. A `PASS` on a check is a statement about that one piece of evidence, not a guarantee. Second, when evidence is missing or unreadable, the honest answer is "not assessed" — not a hopeful "looks fine." Keep both rules in mind and your audit will be worth trusting.

## 1. Lifecycle and support currency — is this system still supported?

Start here, because everything downstream depends on it. Confirm the AIX version and technology level (`oslevel -s`), and check whether that release is still in IBM support or has passed end-of-service. Then look below the OS: adapter and device microcode (`lsmcode -A`, `lscfg -vp`) and firmware levels drift out of support quietly, and out-of-support microcode is a common root cause of storage and adapter faults.

**Why it matters:** an unsupported OS or firmware level means no security fixes and no vendor recourse when something breaks. It is the single most consequential fact about a system's risk.

**What good looks like:** a supported AIX 7.2 or 7.3 technology level within IBM's service window, and adapter/firmware levels that are current or on a known upgrade path.

## 2. Patch currency — how exposed are you to known issues?

Inventory installed software and filesets (`lslpp -L`), then compare against IBM's Fix Level Recommendation Tool (FLRTVC) data to see which known-vulnerable filesets and missing interim fixes (ifixes) apply. Note whether prior ifixes are still installed and consistent (`emgr -l`) — a superseded or partially-applied ifix is its own failure mode.

**Why it matters:** patch gaps are the most exploitable and most quantifiable risk on the box. Unlike vague "hardening," FLRTVC gives you a concrete, prioritized list.

**What good looks like:** no outstanding high-severity FLRTVC hits, ifixes cleanly applied and current, and a known cadence for reviewing new advisories.

## 3. Storage and capacity — will it run out of room or lose a disk quietly?

This is where most real-world AIX incidents actually originate, so give it weight. Check volume group capacity and free PPs (`lsvg`), logical volume layout, and filesystem fill levels (`df -g`) — a full `/`, `/var`, or `/tmp` takes systems down. Verify paging space sizing and layout, the size and health of the boot logical volume (`hd5`), and look for legacy JFS where JFS2 is expected, leftover `multibos` residue, and filesystem slack that signals drift.

**Why it matters:** capacity problems are slow-moving and completely preventable, yet they cause outages precisely because nobody was watching the trend.

**What good looks like:** headroom in every volume group and filesystem, paging space sized to the workload and not fragmented across mismatched disks, and no legacy artifacts left over from past migrations.

## 4. Resilience — what happens when a disk or path fails?

Stability is not the same as resilience. Verify multipath I/O: are all expected MPIO paths present and enabled, is health-check (`hcheck_interval`) configured (`lsmpio`, `lspath`)? Check that mirrored logical volumes are actually mirrored across *different* physical disks — mirror copies that landed on the same disk protect against nothing (`lslv -m`). Confirm Fibre Channel adapters are error-free and that any alt-disk or clone rootvg is genuinely bootable and current.

**Why it matters:** these are the protections you bought and may never have verified. A degraded MPIO path or a same-disk mirror is a failure you have already suffered — you just haven't noticed yet.

**What good looks like:** redundant, enabled MPIO paths with health-checking on; mirror copies on separate disks; clean FC error counters; and a recoverable alt-disk you could actually boot.

## 5. Error and stability history — what has this system been trying to tell you?

The AIX error report is a gift most people ignore. Review recent hardware and software errors (`errpt`, `errpt -a`), decode the significant entries, and check that the error daemon (`errdemon`) is running and that error notification methods are actually configured. Look at crash and dump history: has the system taken a dump, is the dump device sized correctly (`sysdumpdev -l`), is there evidence of past panics?

**Why it matters:** recurring hardware errors and prior crashes are the leading indicators of the next outage. Error history is the cheapest predictive signal you have.

**What good looks like:** a running `errdemon` with notification wired up, no unexplained recurring hardware signatures, and a correctly sized dump device with an understood crash history.

## 6. Security configuration — is the baseline sane?

You do not need a penetration test to catch the common, high-impact misconfigurations. Check the password hashing algorithm (is it a modern algorithm, not crypt/DES?) and password policy. Review NFS exports for over-broad or world-readable exports (`exportfs`, `/etc/exports`). Look at remote access and privileged accounts. This is baseline hygiene, not a full security assessment — and it is honest to say so.

**Why it matters:** weak password hashing and loose NFS exports are exactly the low-effort findings that turn a minor foothold into a serious incident.

**What good looks like:** strong password hashing, a defensible password policy, NFS exports scoped to specific hosts, and no surprising privileged access.

## 7. Configuration hygiene — is the system coherent?

Audit the network configuration and interface inventory, name resolution, and NTP/time sync. Check mount options for filesystems (are critical filesystems mounted with the intended options?). This dimension catches the drift that accumulates over years of well-meant one-off changes.

**Why it matters:** incoherent configuration is where subtle, hard-to-diagnose problems live, and it is what makes the next admin afraid to touch the box.

**What good looks like:** a documented, consistent network and mount configuration with time sync working and no orphaned or contradictory settings.

## 8. Monitoring and backup readiness — would you even know?

Finally, verify the system can tell you when something goes wrong and that you could recover it. Is a monitoring agent present and running? Is remote syslog forwarding configured so logs survive the host? Is performance history being collected (`topas` recording / `nmon`), so you can see trends rather than guess? And is there evidence of a backup job — `mksysb` or equivalent — actually running on a schedule?

**Why it matters:** a system with no monitoring and no verified backup is not "low-risk because it's quiet" — it is a blind spot. The absence of evidence is itself the finding.

**What good looks like:** a live monitoring agent, remote syslog in place, performance history being recorded, and a backup job that runs on a schedule. Remember the honest caveat: **a backup record is not a restore test.** Seeing a backup ran tells you the job fired, not that you can recover from it. Prove the restore separately.

## A note on the HMC

If you manage Power through a Hardware Management Console, the HMC deserves its own pass: HMC firmware currency, user accounts and roles, certificate validity, connectivity to managed systems, and console backups. This is worth doing manually as part of a full estate audit. Be clear-eyed about scope, though — AIXray v0.1.0 assesses the AIX and VIOS partitions, not the HMC appliance itself. Treat the HMC review as a complementary, manual step.

## Doing all of this in one honest pass: AIXray

Working through the checklist above by hand across a fleet is a real day of typing, and the biggest risk is inconsistency — you check paging carefully on one LPAR and skip it on the next. This is exactly the gap [AIXray](https://powertruesystems.com/aixray) was built to close.

AIXray is a free, open-source (Apache-2.0) assessment that collects the evidence for every dimension above — lifecycle and patch currency, storage and capacity, resilience, error history, security configuration, configuration hygiene, and monitoring and backup readiness — in one read-only pass, and produces an HTML or JSON report you keep.

What makes it safe to run on a production system you care about:

- **Read-only on system configuration.** It reads state and reports; it does not remediate or change the host. The only writes are the report you asked for and a temporary FLRTVC scratch directory that is removed on exit.
- **Zero network egress during assessment.** It carries its reference data locally and sends nothing off the box while it runs. You can inspect the command surface before you run it.
- **One inspectable file, no install.** It is a single ksh88-compatible shell script that runs under the AIX `/bin/sh` you already have — no bash, no Python, no package installation, no agent left behind.
- **It refuses to guess.** When evidence is missing, unreadable, or ambiguous, AIXray reports `NOT_ASSESSED` rather than quietly converting it to a `PASS`. An audit tool that invents reassurance is worse than no tool; AIXray is honest about what it could and could not see.

Because it is open source, you do not have to take any of that on faith — the source, the per-check manifests, and the SHA-256 hashes are all public on [GitHub](https://github.com/PowerTrueSYS/aixray-public), so a cautious admin can read exactly what runs before it runs.

Download it, review it, copy it to your AIX or VIOS host, and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` in the current directory — open it in a browser, or save it as PDF to hand to your team.

## If you'd rather have it fixed and watched

Running the audit tells you where you stand. Acting on it is the next question. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers — so if your report surfaces things you'd rather not carry alone, we can help you remediate them and keep the systems monitored over time. That is entirely optional. The tool is free and yours to use forever, whether or not we ever talk. Run the audit, keep the evidence, and decide from there.
