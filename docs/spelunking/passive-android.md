# Passive Android environment spelunker

Status: MVP implementation

The passive spelunker is a host-side Python program that observes an attached
Android target through ADB without changing guest state.

It is intentionally small. It is not a general remote-execution framework.

## Contract

`tools/android_spelunk.py` executes only a hard-coded allowlist of read-only
observations covering:

- device reachability and serial identity;
- Android properties;
- kernel identity;
- process identity;
- CPU and memory exposure;
- mounted filesystems;
- Android framework features;
- one ART/runtime property;
- SELinux observability;
- cgroup observability.

Each observation records:

- probe ID and family;
- exact ADB argument vector;
- return code;
- stdout/stderr;
- elapsed time;
- classification;
- capability level.

The top-level record states `mode=passive` and
`mutation_authorized=false`.

## Classification

Initial classifications are:

- `PRESENT`
- `ABSENT`
- `INACCESSIBLE`
- `UNKNOWN`

`UNEXPECTED` is reserved in the schema/summary for validators that compare an
observation to an expected environment contract.

Capability levels used by this passive probe:

- 0 — absent/unusable from this observer;
- 1 — detectable but no useful content returned, or access blocked;
- 2 — readable/observable.

Higher levels (functional/controllable/performant) belong to active qualification
and are intentionally not inferred by the passive probe.

## Safety boundary

The probe does not:

- install or uninstall packages;
- start applications or activities;
- change Android settings or properties;
- grant/revoke permissions;
- write files to the device;
- reboot or restart services.

A later active spelunker is a separate capability and authority boundary.
