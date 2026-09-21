# Component-attribution adversarial goldens

These goldens exist to qualify attribution primitives, especially their false
positive behavior.

Native variants are built from a known C component as:

- exact copy;
- same source rebuilt at a different optimization level;
- stripped build;
- one-function patched derivative;
- false friend exposing the same public function names with unrelated logic.

DEX variants are built from a small Java component as:

- exact copy;
- package-shaded implementation with the same logic;
- one-method patched derivative;
- false friend with the same class/method API but unrelated behavior.

The first qualification only establishes artifact relationships and identities.
It does not claim that the cheap matcher can recognize rebuilt, stripped,
shaded, or patched variants. Those variants become the controlled interview set
for FID/BSim/DEX structural matchers.

False-positive attribution is treated as more consequential than an attribution
miss: a miss costs recovery work, while a false match can hide custom code.
