# Evidence model

Inginv does not collapse permissions, code paths, runtime state and observed actions into one claim.

## Evidence states

| State | Meaning |
|---|---|
| `STATIC_CONFIRMED` | The behavior or artifact is directly present in code/resources. |
| `RUNTIME_CONFIRMED` | The state or action is directly visible in device/runtime evidence. |
| `CORRELATED` | Independent static and runtime evidence support the same claim. |
| `INFERRED` | Plausible from architecture or adjacent evidence, but not directly demonstrated. |
| `UNVERIFIED` | Evidence is missing, conflicting or too weak. |

## Required fields for a finding

Every retained finding should include:

- stable finding ID;
- evidence state;
- severity and confidence;
- source artifact fingerprint;
- exact class/method/resource or runtime command output;
- consequence;
- explicit statement of what the evidence does **not** prove;
- smallest remediation direction.

## Example

`DevicePolicyManager.wipeData()` present behind a remote task handler is `STATIC_CONFIRMED` capability. A live device reporting the package as Device Owner is `RUNTIME_CONFIRMED` authority. Together they are `CORRELATED` evidence that the installed agent has the authority and implementation necessary to perform a policy wipe. They do **not** prove that a wipe command was ever issued.
