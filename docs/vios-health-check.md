# VIOS health check: what to verify before and after a change

If you run IBM Power, you know the quiet problem: AIX and VIOS are extraordinarily stable, and that stability breeds silence. Systems run for years without a reboot, the builder has retired, and nobody knows what is current or what would happen in a failure. A health check replaces assumption with evidence — the most important discipline when a change is coming.

This is a practical, vendor-honest guide to what to verify on a VIOS partition and what "good" looks like. It is written the way an administrator actually works, with the real commands (padmin/ioscli). At the end we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — collects the same evidence in one pass.

**Two ground rules for any honest health check.** First, a health check reports what is *measurably true right now*; it does not prove a system is secure, compliant, or recoverable. A `PASS` is a statement about that one piece of evidence, not a guarantee. Second, when evidence is missing or unreadable, the honest answer is "not assessed" — not a hopeful "looks fine."

**The golden rule of change:** capture state before the change, apply the change, re-verify after. Without a before snapshot, you cannot distinguish pre-existing drift from the change's effect.

## 1. VIOS level and currency — is this partition still supported?

Confirm the VIOS level with `ioslevel`. Check the VIO server fileset (`lslpp -l | grep VIO`) and cross-reference with IBM's support matrix. Then check the POWER firmware level on the CEC and the HMC level — VIOS and hypervisor have well-known compatibility constraints.

**Why it matters:** unsupported means no security fixes, no vendor recourse, higher probability of issues already patched elsewhere.

**What good looks like:** supported VIOS release, current (or on-upgrade-path) hypervisor and HMC.

## 2. SEA / network virtualization health and failover — is the virtual network resilient?

The Shared Ethernet Adapter (SEA) bridges virtual and physical networks. Verify the SEA configuration (`lsmap -net -all`), confirm the internal and external VLAN settings, and check the state of the backing ent adapters. Most critically: is a backup SEA configured and in the correct state? (`lsmap -net -all` shows the primary/backup pairing and state.) Test the failover path if you can — a backup SEA never tested is a failure you have already suffered.

**Why it matters:** the SEA is a single point of failure. Primary down, backup never activated — every LPAR loses network, often silently.

**What good looks like:** correct VLAN tagging, active backup SEA ready, no unexpected resets.

## 3. Virtual SCSI / NPIV storage mappings — are the disks wired correctly?

Check virtual SCSI mappings (`lsmap -vscsi -all`): do the VSCSI slots match the expected virtual targets? Are the backing devices the right RASDs and in `active` state? For NPIV (virtual Fibre Channel), review `lsmap -npiv -all`: each virtual FC client adapter maps to a physical FC port with correct backing WWPNs. Look for orphaned mappings — defined slots with no backing device, or backing devices removed from the system without updating the VIOS.

**Why it matters:** storage misconfigs are the most destructive VIOS incidents. Wrong backing device means data corruption. Orphaned mapping means unusable capacity.

**What good looks like:** VSCSI slots mapped correctly in `active` state, clean NPIV pairings, no orphaned slots.

## 4. MPIO paths on the VIOS — are all expected paths present and healthy?

On the VIOS, multipath I/O is just as important as on the AIX LPARs it serves. List paths with `lsdev -class fc -stat` and `lspath` to see which FC adapters see which backing devices. Check that all expected paths are `Available`, MPIO policies are consistent, and `hcheck_interval` is set with health checks running clean.

**Why it matters:** MPIO is the safety net for storage failures. If only one path is up, the affected LPARs lose storage when that adapter dies.

**What good looks like:** multiple Available paths, consistent MPIO policies, health-check enabled, zero unexpected transitions.

## 5. Error log review — what has this partition been trying to tell you?

The VIOS error log is the cheapest predictive signal you have. Review recent errors with `errpt` (and `errpt -a` for detail). Recurring hardware errors on FC adapters, Ethernet, or disks are leading indicators. Check that the error daemon is running, and look for VIOS-specific signatures: backing devices going unavailable, SEA failover events.

**Why it matters:** VIOS error history covers the virtualization layer and physical hardware. Errors on one FC adapter affect every sharing LPAR.

**What good looks like:** running error daemon, no recurring hardware signatures, SEA failovers only from planned testing.

## 6. Disk and space headroom — is there room to grow?

Check the VIOS rootvg capacity (`lsvg rootvg`), free PPs, and filesystem fill levels (`df -g`) — particularly `/var/adm/ras` which fills fast with error logs and console output. Verify backing physical volumes for the SEA and virtual mappings have adequate space.

**Why it matters:** a full `/var/adm/ras` or exhausted rootvg on a VIOS is a silent killer — when the VIOS cannot write its logs or expand its boot LV, you lose visibility and recoverability simultaneously.

**What good looks like:** meaningful headroom in rootvg and all VIOS filesystems, no near-full volumes.

## 7. Pre-change vs. post-change verification — do it by design, not by memory

Before any change — firmware update, SEA reconfiguration, vhost reassignment — capture the output. Save `ioslevel`, `lsmap -all`, `lsmap -npiv -all`, `lspath`, `errpt -a`, `lsvg rootvg`, and `df -g` to a dated file. Apply the change. Then re-run and diff. You will catch regressions automated monitoring misses: a backup SEA that didn't come up, a path still degraded, a VLAN tag shifted one slot.

**Why it matters:** human memory is not a verification mechanism. Dated, command-level evidence is the only thing you will have two months from now.

**What good looks like:** a dated "before" capture, a post-change re-run within 24 hours, and a diff showing either no unexpected changes or documented, expected ones. The goal is not a perfect diff — it is a *knowable* diff.

## What "good" looks like across dimensions

On a healthy VIOS:

- Supported VIOS level with current hypervisor/HMC pairing.
- Active SEA backup; clean storage mappings, no orphans.
- Redundant MPIO paths, consistently policy'd.
- No recurring hardware error signatures.
- Comfortable headroom across all VIOS filesystems.
- A before/after capture for every change.

If even one dimension is uncertain, "not assessed." On a VIOS, a misleading `PASS` can take down every LPAR it serves.

## Doing all of this in one honest pass: AIXray

Working through the dimensions above by hand risks inconsistency — checking SEA failover on one VIOS and skipping it on the next. This is the gap [AIXray](https://powertruesystems.com/aixray) closes.

AIXray is a free, open-source (Apache-2.0) assessment that gathers evidence for every VIOS dimension above — SEA health, virtual SCSI and NPIV mappings, MPIO paths, error log review, disk headroom, VIOS currency — in one read-only pass, producing an HTML or JSON report you keep.

What makes it safe on a production VIOS:

- **Read-only.** It reads state and reports; it does not remediate or change the host.
- **Zero network egress during assessment.** Reference data runs locally; nothing leaves the box.
- **One inspectable file, no install.** A single ksh88-compatible script under the AIX `/bin/sh` you already have — no bash, no Python, no agent left behind.
- **It refuses to guess.** When evidence is missing or ambiguous, AIXray reports `NOT_ASSESSED` rather than converting it to a `PASS`. An assessment tool that invents reassurance is worse than no tool.

Because it is open source, the source, the per-check manifests, and the SHA-256 hashes are all public on [GitHub](https://github.com/PowerTrueSYS/aixray-public), so a cautious administrator can read exactly what runs before it runs.

Download it, review it, copy it to the VIOS host, and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` in the current directory — open it in a browser or save as PDF.

## If you'd rather have it fixed and watched

AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers. If your report surfaces things you'd rather not carry alone, we can help you remediate and keep the systems monitored over time. That is entirely optional. The tool is free and yours to use forever, whether or not we ever talk.
