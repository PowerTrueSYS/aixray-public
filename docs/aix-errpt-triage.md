# Reading the AIX error report (errpt): a triage guide

If you run IBM Power, you already know the quiet problem: AIX and VIOS are extraordinarily stable, and that stability breeds silence. Systems run for years without a reboot, the person who built them has retired, and nobody is quite sure what would happen in a failure. The AIX error report (`errpt`) is a gift most people ignore — and it is often the cheapest predictive signal you have.

This is a practical, vendor-honest guide to reading the AIX error report with real commands and real error IDs. At the end we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — gathers the same evidence in one pass.

**A ground rule.** An error report shows what a system has *already seen*; it does not predict the future with certainty. When evidence is missing or unreadable, "not assessed" is the honest answer — not "looks fine."

## What errpt is and why it matters

`errpt` is AIX's permanent error log — a fixed-size circular file maintained by the `errdemon` daemon. Every hardware fault, software exception, I/O failure, and environmental event (power, thermal, fan) the kernel or drivers can observe gets recorded here with a timestamp, error ID, severity, and resource identifier.

The reason this matters most to operators is that **recurring errors are leading indicators**. A disk that logs a recoverable I/O error today may be unrecoverable next week. A Fibre Channel adapter that flips warnings is usually one path from dropping. The hardware and firmware tell you about the next outage before it happens; `errpt` is where they put it in writing.

**What good looks like:** a regular review cadence, recurring signatures tracked to root cause, and the error daemon plus notification wired so permanent hardware errors page a human.

## The summary view: `errpt`

The plain `errpt` command (no flags) shows a compact summary:

```
ID                       TIMESTAMP  T P RESOURCE_ID  DESCRIPTION
PERM_E3C00             0715143230  C O ENET_1         Ethernet link down
RECC_2A1B              0714091045  P O hdisk3         Retry count exceeded
```

Key columns: **Error ID** (the permanent diagnostic label you grep for), **Type** (`P` permanent, `O` one-time, `T` temporary), **Class** (`H` hardware, `S` software), **Resource ID** (`hdisk3`, `en0`), and **Description** (a short label). Permanent hardware errors (`P H`) are the ones that demand attention.

## The detail view: `errpt -a`

`errpt -a` gives you the full record in ODM format. The fields that matter: **LABEL** (the diagnostic label, e.g. `SC_DISK_ERR1`), **CLASS** (`H` hardware, `S` software), **TYPE** (`PERM`, `ONE_TIME`, `TEMP`), **DESC** (a detailed description), and **SYMDATA** (driver-specific diagnostic data such as SCSI sense codes). Use `errpt -a` to go from "something happened" to "here is exactly what happened and on which resource."

## Decoding significant hardware entries

The permanent hardware error log (`errpt -d H -T PERM`) is where the real story lives. The AIX error ID scheme encodes subsystems — `SC` is SCSI/storage, `FCS` is Fibre Channel, `EPOW` is environmental/power, `LVM_SA` is LVM storage availability, `SCAN_ERROR` is processor or memory scan events, `DMPCHK` is dump device check, and `FWDMP` is firmware-assisted dump.

**Storage — `SC_DISK_ERR1` through `SC_DISK_ERR4`, `DISK_ERR1` through `DISK_ERR4`**: Disk errors, permanent hardware faults, bad blocks. More than one `SC_DISK_ERR` on the same disk in a week means replace it.

**SCSI adapter — `SCSI_ERR1`, `SCSI_ERR10`**: Adapter-level hardware faults or cabling. `SCSI_ERR10` on a SAN path can cascade into LVM failures.

**Fibre Channel — `FCS_ERR10`**: SAN link degrading — prelude to I/O hang.

**RAID array — `SCSI_ARRAY_ERR6`, `SCSI_ARRAY_ERR7`**: A member disk or array is degraded. Check the controller.

**LVM — `LVM_SA_QUORCLOSE`, `LVM_SA_STALEPP`, `LVM_SA_PVMISS`, `LVM_IO_FAIL`**: Consequences of a failed disk or path. `LVM_SA_QUORCLOSE` (volume group lost quorum, forced offline) is worst case. Look *backwards* to the root cause.

**Environmental — `EPOW_SUS`, `EPOW_RES_CHRP`**: Power, thermal, fan events. Platform-level — call IBM service.

**Processor/memory — `SCAN_ERROR_CHRP`**: Correctable ECC errors exceeding threshold. A degrading DIMM or CPU; recurring events mean replacement is imminent.

**Firmware — `FIRMWARE_EVENT`**: Service processor logged a service event. Check the HMC.

**Dump device — `DMPCHK_SMALL`, `FWDMP_IFAIL`**: Dump device undersized or firmware-assisted init failed. A panic with these means no usable dump.

Software errors (`errpt -d S -T PERM`) are less predictive but worth reviewing — recurring LVM events, NFS failures, and auth anomalies often point to configuration drift.

## Recurring signatures as leading indicators

A single permanent error on a resource is a warning. The same error — or a very similar one — on the same resource within days or weeks is a leading indicator. The pattern matters:

- **Same error ID, same resource, recurring**: Hardware is actively failing. Replace or contact support.
- **Different error IDs, same resource**: A disk may log `SC_DISK_ERR1` today and `SC_DISK_ERR3` next week — same root cause.
- **Different resources, same error type**: Multiple storage errors across disks in one hour often point to a shared upstream component — an HBA, a switch, or a power rail.

Practical approach: run `errpt -d H -T PERM -s <MMDDhhmmYY>` with a 30-day cutoff and look for duplicates. Same resource more than once? Investigate before the next reboot.

## Confirming errdemon and error notification

All of the above is useless if `errdemon` is not running. When `errdemon` is down, the error log is frozen — no new error is recorded, and every other check is blind. The error log is a fixed-size circular file (default 1 MB); once full it overwrites the oldest entries. A manual cap below the default makes a chatty box lose history faster than expected.

Confirm `errdemon` is running:

```sh
ps -e -o comm | grep errdemon
```

If not, start it:

```sh
/usr/lib/errdemon
```

Check the log size:

```sh
/usr/lib/errdemon -l
```

Default is 1,048,576 bytes (1 MB). If lower, raise it:

```sh
/usr/lib/errdemon -s 1048576
```

Verify that error notification is configured — errors that only sit in a log file help no one:

```sh
odmget errnotify
```

AIX ships with default `errnotify` stanzas using the `diagela` utility. If all are default, errors log locally and tell no one. Custom methods — email, page, SNMP trap — mean errors can reach a human on permanent hardware events.

## Crash and dump history

Error history tells you about near-misses. Crash history tells you about the ones that were not. Without a dump, root-cause analysis of a kernel panic is guesswork.

Check the current dump device:

```sh
sysdumpdev -l
```

If the primary device is `/dev/sysdumpnull` or not set, the system cannot capture a dump on panic. Configure and enable a dump device sized for your LPAR with `sysdumpdev -e`.

Check for recent crash evidence:

```sh
find /var/adm/ras -name 'vmcore*' -mtime -30 -print
```

Dump files in `/var/adm/ras` from the last 30 days mean the system panicked recently. Was the cause fixed? If you have `kdb`, inspect the core; otherwise send it to IBM support with the associated error log.

Check the dump history for older panics:

```sh
sysdumpdev -L
```

Past dump events show when they happened, how large they were, and where they landed. Multiple dumps in a short period signal instability worth investigating.

## Doing this in one honest pass: AIXray

Running through the checklist by hand is a real morning of typing, and the biggest risk is inconsistency: you check dump sizing carefully on one LPAR and skip it on the next. This is exactly the gap [AIXray](https://powertruesystems.com/aixray) was built to close.

AIXray is a free, open-source (Apache-2.0) assessment that collects error-log evidence in one read-only pass: `errdemon` health (`ck-errdemon-health`), recent permanent hardware errors (`ck-errpt-hw`), recurring signatures (`ck-errpt-signatures`), error notification beyond defaults (`ck-errnotify-methods`), crash dump evidence (`ck-crash-evidence`), and dump device config (`ck-sysdump`). All in one pass.

Because it is open source, you can inspect exactly what runs before you run it — the source, per-check manifests, and SHA-256 hashes are all public on [GitHub](https://github.com/PowerTrueSYS/aixray-public).

Copy it to your AIX or VIOS host and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` — open it in a browser, or save as PDF.

## If you'd rather have it fixed and watched

Running the triage tells you where you stand. Acting on it is the next question. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers — so if your report surfaces things you'd rather not carry alone, we can help. That is entirely optional. The tool is free and yours to use forever, whether or not we ever talk.
