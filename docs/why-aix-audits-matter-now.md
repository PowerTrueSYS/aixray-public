# The quiet risk in your Power estate: the people who tend AIX are retiring

If you manage IBM Power systems, you have probably noticed the silence. Your AIX and VIOS partitions are old, stable, and barely making noise. They were built well enough to be forgotten — and that is the problem.

Stability is not the same thing as resilience. A system that has not required a reboot in three years may also be one where nobody remembers what would happen if it did. The people who designed these configurations, tuned the storage, set up the mirrors, and wired the error traps are moving on. They are not retiring from engineering — they are retiring from an era of computing that most of the industry has already moved past. And when they leave, they take institutional knowledge that was never written down.

This is not a crisis. It is a condition. And the antidote is not panic. It is evidence.

## What stability buys you — and what it costs

AIX is, by design, an extraordinarily stable operating system. The toolchain is conservative, the release cadence deliberate, the interface contracts durable. You can install a system and let it run for years without intervention. That is a feature, not a bug.

But stability breeds a kind of organizational silence. When nothing breaks, nobody feels the need to look closely. Configuration drift accumulates quietly — a filesystem remounted with different options after an emergency, a network interface that was never cleaned up, a volume group with unallocated physical partitions that nobody noticed. None of these are emergencies. They are just the accumulated weight of a hundred well-meant one-off changes, none of which would have mattered in isolation but which, together, make the next admin afraid to touch anything.

The person who understands why things are the way they are — the one who can explain the storage layout or the multipath configuration or the reason a particular ifix was applied and when — is often the only person who can explain it. When that person leaves, the silence becomes structural.

## The replacement problem

The harder truth: even if you wanted to, you probably cannot replace the people who left.

AIX and Power engineering is a narrow field. The community of administrators who have deep, hands-on experience with these systems is not growing. Senior people retire. Younger engineers go where the job postings and the career trajectories point, and those trajectories are increasingly elsewhere. The gap is not dramatic enough to trigger alarms — it is a slow, steady thinning. By the time you notice the gap, the knowledge is already gone.

This does not mean your systems are failing. It means they are running on knowledge that is no longer shared, documented, or even fully remembered by anyone who still works there.

## Why audits are the honest answer

An audit is not a compliance checkbox. At its best, an audit replaces institutional memory with evidence. It answers, concretely and right now, what a system is configured to do and what is measurably true about its posture. Not what you hope it is. Not what it looked like six months ago when the person who built it was last here. Right now.

Running an audit does three things:

1. **It creates a baseline you can compare against later.** A single point in time is only useful if you can measure change from it.
2. **It surfaces what your monitoring does not.** Most monitoring tools alert you when something crosses a threshold. They do not tell you whether the things below the threshold are configured correctly, or whether your backup is actually restorable, or whether your multipath paths are evenly distributed across physical disks.
3. **It forces the conversation you have been avoiding.** When you sit down with the results and your team, you do not need to blame anyone or defend any decision. The evidence is the evidence. The question is simply, "Given what we see, what do we want to do about it?"

You do not need a tool to tell you to audit. You need a tool that makes the audit honest — one that reports what is actually there rather than what you would like it to be.

## How AIXray fits in

[AIXray](https://powertruesystems.com/aixray) is a free, open-source (Apache-2.0) assessment tool built specifically for this problem. It runs as a single shell script on AIX 7.2 or 7.3 or VIOS, reads system state without changing anything, and produces an HTML or JSON report you keep.

It covers the same ground a careful administrator would check by hand — lifecycle and support currency, patch gaps against IBM's FLRTVC data, storage and capacity, multipath and mirror health, error history, security configuration, configuration hygiene, and monitoring readiness. It does this in one read-only pass so you do not have to remember which dimension you checked last time.

A few things make it practical to run on production systems:

- **Read-only.** It reports; it does not remediate. The only writes are the report you asked for and a temporary FLRTVC scratch directory removed on exit.
- **No network egress during assessment.** Reference data ships locally. Nothing leaves the box while it runs.
- **One inspectable file, no installation.** It is a single ksh88-compatible script. No Python, no bash, no package manager. You can read it before you run it.
- **It refuses to guess.** When evidence is missing, unreadable, or ambiguous, AIXray reports `NOT_ASSESSED` rather than quietly converting it into a reassuring `PASS`.

Because it is open source, the source, the per-check manifests, and the SHA-256 hashes are all public on [GitHub](https://github.com/PowerTrueSYS/aixray-public). A cautious administrator can read exactly what runs before it runs.

[Download AIXray](https://powertruesystems.com/aixray/) and run it. You will get a report in the current directory. Open it. Share it with your team. Keep it. Run it again in six months. The value is in the comparison.

## If you would rather not do it alone

An audit tells you where you stand. Acting on it is the next question. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers. If your report surfaces things you would rather not carry alone — if you need help prioritizing the findings, building a remediation plan, or standing up ongoing monitoring — that is available. It is entirely optional. The tool is free and yours to use forever, whether or not we ever talk.

Run the audit. Keep the evidence. Decide from there.
