# AIX storage and capacity audit: MPIO, mirroring, paging, and full filesystems

When AIX systems go down unexpectedly, storage and capacity problems are among the most common causes — and the most preventable. AIX is stable enough that it runs for years without a reboot, which means storage configuration drifts silently: filesystems fill, mirrors end up on the same disk, paging space gets fragmented, and volume groups reach capacity without anyone noticing. An audit replaces "it's been fine for years" with "what would happen right now if a disk failed?"

This is a focused guide to auditing AIX storage and capacity — the checks, the real commands, and the evidence. At the end we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — collects the same evidence in one pass.

**Two ground rules for any honest audit.** First, an audit reports what is *measurably true right now*; it does not prove a system is recoverable. Second, when evidence is missing or unreadable, the honest answer is "not assessed" — not a hopeful "looks fine."

## 1. Volume group capacity — is there room to grow?

Every AIX system is organised into volume groups (VGs), each with a fixed number of physical partitions (PPs). When a VG fills, you cannot extend filesystems. List your VGs (`lsvg -o`) and check free PPs on each (`lsvg <vg>`). Fewer than 10–15% free PPs is a time bomb. Also check attached physical volumes (`lsvg -p <vg>`) — a single-disk VG has no redundancy.

**Why it matters:** running out of PPs blocks every filesystem in that VG. The next log write fails until someone frees space, requiring a maintenance window nobody has.

**What good looks like:** every VG has meaningful headroom (at least 10–15% free PPs), and you know which disks you would add before it fills.

## 2. Logical volume layout — is the structure coherent?

Check how logical volumes are distributed. Which LVs are mirrored (`lsvg -l <vg>`), their copy counts, and how data is placed across physical disks (`lslv -m <lv>`)? A mirrored LV with both copies on the same disk is not a mirror — it is a single point of failure with the performance penalty and zero protection. Look for oversized LVs locking up unused space.

**Why it matters:** mirrored storage that does not span disks protects against nothing. The system reports "mirrored" and the admin assumes protection — until the single disk holding both copies fails.

**What good looks like:** mirrored LVs have copies on physically separate disks, LV sizing matches actual usage, and the layout is readable.

## 3. Filesystem fill levels — will a full root take the system down?

Filesystem fill is the single most common capacity-related cause of unplanned AIX outages. Run `df -g` to see all filesystems in gigabytes. Pay particular attention to `/`, `/var`, and `/tmp` — when any reaches 100%, the system becomes unstable. `/var` fills are insidious because logs accumulate slowly. Also verify inode usage (`df -g` shows both blocks and inodes) — a filesystem can fill on either.

**Why it matters:** a full root or `/var` is not a "performance issue" — it is an outage. Many system processes refuse to start or write when root is full, cascading failure across unrelated services.

**What good looks like:** no critical filesystem above 80% utilization, and inode usage well below capacity on all mounts.

## 4. Paging space sizing and layout — will the system run out of swap?

When physical memory is exhausted, AIX moves pages to paging space. If paging is undersized or exhausted, the system can panic. Check paging with `lsps -a`. Verify total paging space is sized appropriately — a common rule of thumb is at least equal to physical memory for systems that might hibernate, smaller ratios for always-up production systems. Also check layout: is a paging space spread across multiple disks in the same VG? Fragmented paging degrades I/O under pressure.

**Why it matters:** paging exhaustion causes the system to lock up or panic. An undersized paging space turns a memory spike into a crash.

**What good looks like:** paging sized to workload requirements, distributed across disks in a balanced VG (not a single-disk VG), and no active paging on a filesystem close to full.

## 5. Boot LV (hd5) health — can this system boot if it crashes?

The boot logical volume (`hd5`, usually in `rootvg`) holds the IPL code, boot image, and system boot files. If `hd5` is corrupted, undersized, or on a failing disk, the system cannot boot. Verify with `lsvg rootvg`, check the LV (`lslv -m hd5`), and confirm the boot list (`bootlist -m normal -o`). Also verify `hd5` is large enough for the current AIX level — an upgrade requiring more boot space can fail partway through, leaving the system unbootable.

**Why it matters:** a system that cannot boot is a system that cannot recover. The boot LV is the single most critical piece of storage configuration on any AIX box.

**What good looks like:** `hd5` is present, properly configured, correctly sized for the installed AIX version, and the boot list points to a healthy disk.

## 6. Legacy JFS vs JFS2 and multibos residue

AIX migrated from JFS to JFS2 years ago. Systems that have been around long enough may still have JFS mounted. Check with `lsfs -q`. Also look for `multibos` residue — older AIX used multibos to maintain multiple BOS environments on the same disk. Leftover LVs and mounts clutter `rootvg` and waste space (`lsvg -l rootvg`).

**Why it matters:** legacy JFS lacks features JFS2 provides. Multibos residue wastes VG capacity and creates confusion during recovery.

**What good looks like:** all filesystems using JFS2, no leftover JFS mounts, and a clean `rootvg` without orphaned multibos LVs.

## 7. MPIO paths, health-check, and FC error counters

Multipath I/O (MPIO) provides redundant paths between the AIX system and storage. Verify all expected MPIO paths are present and `enabled` (`lspath`). Then check whether AIX's built-in health check is configured (`lsattr -El hdiskN -a hcheck_interval -a hcheck_mode 2>/dev/null`). The `hcheck_interval` setting causes AIX to probe each path periodically — when a path fails, AIX switches to a surviving path without the I/O failing. Without health checking, a path failure goes undetected until it matters. Also check Fibre Channel adapter error counters (`fcstat <adapter>`); accumulating errors indicate a degrading link.

**Why it matters:** MPIO paths without health checking are a false sense of security. The paths exist, but AIX does not proactively monitor them.

**What good looks like:** all expected MPIO paths present and enabled, `hcheck_interval` configured (typically 30–120 seconds), `hcheck_mode` set to `simple` or `tpg` (not `disabled`), and FC error counters stable or zero.

## 8. Mirror copy placement — are the copies actually redundant?

Checking MPIO paths is not the same as checking data redundancy. If you have mirrored LVs, verify each copy is on a *different* physical disk. Use `lslv -m <lv>`. If both copies reside on the same physical volume, the mirror provides zero protection — it is an expensive illusion. Check across all mirrored LVs, and confirm that disks holding mirror copies are connected through different HBAs when possible.

**Why it matters:** same-disk mirror copies are one of the most common misconfigurations in AIX environments. This is the difference between "we have a mirror" and "we have protection."

**What good looks like:** every mirrored LV has copies on different physical disks, preferably on different storage paths.

## 9. Alt-disk bootability — can you recover from a root disk failure?

If your system has an alt-disk (a full clone of `rootvg` on a separate disk), verify it is bootable and current. Check its status (`alt_rootvg_op -q -d <disk>`) and whether it is marked bootable (`bootinfo -B <disk>`). An alt-disk created six months ago and never updated is false confidence, not a recovery asset. Compare its AIX level against the current system (`oslevel -s`).

**Why it matters:** an outdated alt-disk is worse than no alt-disk at all. The difference between "I have an alt-disk" and "I can boot an alt-disk that works" is significant.

**What good looks like:** an alt-disk present, bootable, and within one technology level of the current system.

## Doing all of this in one honest pass: AIXray

Working through these checks by hand across a fleet is a real day of typing, and the biggest risk is inconsistency — you check mirror placement carefully on one LPAR and skip it on the next. This is exactly the gap [AIXray](https://powertruesystems.com/aixray) was built to close.

AIXray is a free, open-source (Apache-2.0) assessment that collects the evidence for every storage and capacity dimension above — volume group capacity, filesystem fill, paging, boot LV health, mirror placement, MPIO paths, health-check configuration, FC error counters, JFS legacy, multibos residue, and alt-disk bootability — in one read-only pass, producing an HTML or JSON report you keep.

What makes it safe to run on a production system:

- **Read-only on system configuration.** It reads state and reports; it does not remediate or change the host. The only writes are the report and a temporary FLRTVC scratch directory removed on exit.
- **Zero network egress during assessment.** It carries reference data locally and sends nothing off the box while it runs. You can inspect the command surface before you run it.
- **One inspectable file, no install.** It is a single ksh88-compatible shell script that runs under the AIX `/bin/sh` you already have — no bash, no Python, no package installation.
- **It refuses to guess.** When evidence is missing, unreadable, or ambiguous, AIXray reports `NOT_ASSESSED` rather than quietly converting it to a `PASS`. An audit tool that invents reassurance is worse than no tool.

Because it is open source, you do not have to take any of that on faith — the source, the per-check manifests, and the SHA-256 hashes are all public on [GitHub](https://github.com/PowerTrueSYS/aixray-public), so a cautious admin can read exactly what runs before it runs.

Download it, review it, copy it to your AIX or VIOS host, and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` in the current directory — open it in a browser, or save it as PDF.

## If you'd rather have it fixed and watched

Running the audit tells you where you stand. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers — so if your report surfaces things you'd rather not carry alone, we can help you remediate them and keep the systems monitored over time. That is entirely optional. The tool is free and yours to use forever, whether or not we ever talk. Run the audit, keep the evidence, and decide from there.
