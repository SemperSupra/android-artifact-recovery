# Evidence summary and confidence semantics

AAR keeps artifact identity, recovered representations, rebuild evidence,
behavioral evidence, UNKNOWNs, and execution requirements separate.

The summary is not a score. It is a compact evidence projection.

Confidence is deliberately coarse and scope-qualified:

- **high** — direct deterministic or observed evidence for the exact narrow claim;
- **unknown** — insufficient evidence for that claim.

A high-confidence statement that a specific exported project failed a specific
Gradle command does not imply high confidence about semantic recovery. Likewise,
a behavioral match applies only to the declared vector and observables.

Missing stages remain explicit UNKNOWN entries rather than disappearing from the
record.
