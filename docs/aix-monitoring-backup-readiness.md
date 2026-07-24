# AIX monitoring and backup readiness: would you even know, and could you recover?

A quiet, long-running AIX system feels like a good system. But silence is not readiness. When a disk degrades, a filesystem fills up, or an application eats memory in a loop, you need to know — and you need to be able to recover. Monitoring and backup readiness answer two questions: "would you notice something went wrong?" and "could you recover?" Most shops answer "not reliably" to both, and do not know it until it matters.

This is an honest, practical guide to the four dimensions that separate a system that survives from one that surprises you. For each, we cover what to check, why it matters, and what "good" looks like. At the end, we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — gathers the same evidence in one pass.

**Two ground rules.** First, readiness is about *evidence*, not aspiration. A running process is evidence; a ticket titled "we should set that up" is not. Second, when evidence is missing, the answer is "not assessed" — not a hopeful "probably fine."

## 1. Monitoring agent — is anything watching?

The first question is simple: is a monitoring agent present, configured, and running? Look for common agents (Nagios NRPE, Datadog, Prometheus, IBM Tivoli/Instana) and check their process state (`ps -ef`), startup entry (`/etc/inittab` or cron), and heartbeat logs. A configuration file that exists but is not running is a false sense of security.

**Why it matters:** without a monitoring agent, you are blind to CPU saturation, memory pressure, disk I/O, and crashes until someone complains. Monitoring replaces reactive firefighting with proactive awareness.

**What good looks like:** a monitoring agent running, reporting metrics on a known cadence, with alerts wired to a watched channel.

**NOT_ASSESSED:** no monitoring agent found, or the process is not running and no startup entry exists.

## 2. Remote syslog forwarding — do your logs survive the host?

If the host dies or the filesystem corrupts, local logs are gone. Remote syslog forwarding (rsyslog/syslog-ng to a central server) keeps a copy of the truth alive. Check `/etc/syslog.conf` or `/etc/rsyslog.conf` for forwarding directives, and confirm the target is reachable.

**Why it matters:** syslog survives the host. It is the difference between "we have no idea what happened" and "we have the log trail." After a crash or filesystem failure, logs on a separate box are your primary forensic resource.

**What good looks like:** active remote syslog forwarding to a dedicated log server, with the forwarding path verified and rotation configured.

**NOT_ASSESSED:** no remote syslog forwarding configured, or the configuration points to a host that is not reachable.

## 3. Performance history — are you tracking trends, or guessing?

Topas recording (`topas -r`) and nmon are the two native AIX performance tools. Scheduled recording gives you historical data on CPU, memory, disk I/O, and network — not just a single snapshot at the moment of breakage. Check cron for periodic jobs, look for recorded data files (`/var/adm/ras/topasdata`, nmon output), and verify the interval and retention cover your workload.

**Why it matters:** a single snapshot tells you what is happening *now*; history tells you what is *heading towards* a problem. Without performance data, capacity planning is a guess.

**What good looks like:** scheduled recording with a retention window that covers several business cycles and a way to view the data when a problem appears.

**NOT_ASSESSED:** no performance recording found, or the recording exists but has no recent data.

## 4. Backup jobs — are they running, and can they restore?

Check for `mksysb` jobs, `backup` commands, or equivalent backup software on a schedule. Verify *recent* evidence of a backup completing (log entries, filesystem changes, or the tool's own status reports). Confirm the destination has capacity and media is stored off the host.

**Why it matters:** a backup job that never runs is a false promise. You need evidence of successful backups stored somewhere the host itself cannot destroy.

**The honest caveat: a backup record is not a restore test.** Seeing a backup ran tells you the job fired, not that you can recover. A backup can succeed while being corrupt, incomplete, or built from a broken snapshot. The only way to know it is useful is to restore from it — on a test system, on a schedule. A backup record tells you effort was made. A restore test tells you recovery works.

**What good looks like:** scheduled backup (mksysb or equivalent) with recent, verified completions, stored off the host, and a documented restore test.

**NOT_ASSESSED:** no backup job found, or no evidence of a recent successful completion.

## Putting it together

These four dimensions are independent. You can have a monitoring agent and no backup. You can have backups that never run and no performance history. The most honest question about an AIX system is not "is it up?" but "if it goes down tomorrow, would we be able to fix it?"

## Doing it all in one pass: AIXray

Checking monitoring agents, syslog forwarding, performance history, and backup evidence by hand is tedious and easy to gloss over — exactly where real gaps hide. [AIXray](https://powertruesystems.com/aixray) collects the evidence for monitoring and backup readiness in one read-only pass, alongside the other audit dimensions.

What makes it safe to run on a production system you care about:

- **Read-only on system configuration.** It reads state and reports; it does not remediate or change the host. The only writes are the report you asked for and a temporary FLRTVC scratch directory that is removed on exit.
- **Zero network egress during assessment.** It carries its reference data locally and sends nothing off the box while it runs. You can inspect the command surface before you run it.
- **One inspectable file, no install.** It is a single ksh88-compatible shell script that runs under the AIX `/bin/sh` you already have — no bash, no Python, no package installation, no agent left behind.
- **It refuses to guess.** When evidence is missing, unreadable, or ambiguous, AIXray reports `NOT_ASSESSED` rather than quietly converting it to a `PASS`. A monitoring check that invents reassurance is worse than no check at all.

It is open source (Apache-2.0). The source, per-check manifests, and SHA-256 hashes are public on [GitHub](https://github.com/PowerTrueSYS/aixray-public).

Download it, review it, copy it to your AIX or VIOS host, and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` in the current directory — open it in a browser, or save it as PDF to hand to your team.

## If you'd rather have it fixed and watched

Closing gaps — installing an agent, wiring syslog, scheduling performance recording, building a restore cycle — is the work. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers. If your assessment surfaces things you would rather not carry alone, we can help. That is entirely optional. The tool is free and yours forever. Run the assessment, keep the evidence, and decide from there.
