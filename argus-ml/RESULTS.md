# ArgusEDR — Learned Injection Detector: Method & Results

A GRU-based classifier that detects process-injection from the behavioral
telemetry of the ArgusEDR agent. It is a *learned second opinion* that runs
alongside the agent's rule-based (Diamond FSM) correlator.

---

## 1. Motivation

ArgusEDR flags injection with a fixed rule chain
(allocate → write → make-executable → thread). Rules are precise but brittle:
a JIT runtime (.NET, V8) legitimately allocates memory and makes it executable,
and an attacker can reorder or vary the steps. The question this project asks:

> Can a sequence model learn the *shape* of an injection from the same API
> telemetry the agent already collects, and does it generalize to injection
> techniques it has never seen?

---

## 2. Data source: the EDR hooks

The agent injects `argus_hook.dll` (user-mode, Microsoft Detours) into a
monitored process and reports every call to six Win32 APIs over a named pipe as
NDJSON:

`VirtualAlloc`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtect`,
`CreateThread`, `CreateRemoteThread`.

Each event carries: the API name, the calling PID and the **target PID** (equal
for in-process, different for cross-process), the region size, and the memory
protection flags. A *trace* is the ordered sequence of these events for one
monitored process.

---

## 3. Model

A small **GRU** reads the per-process event sequence and outputs a single
probability `P(injection)`.

**Per-event feature vector (11 dims):**

| Feature | Meaning |
|---|---|
| API one-hot (6) | which of the six APIs |
| `cross_process` | `target_pid != pid` — the strongest injection cue |
| `exec_protect` | the protection grants EXECUTE |
| `write_protect` | the protection grants WRITE |
| `log10(size)` | allocation / write size |
| `log10(Δt)` | time since the previous event |

Raw addresses are deliberately dropped (no signal, would invite overfitting).
Architecture: linear projection → 1-layer GRU (hidden 48) → last hidden state →
linear → sigmoid. Trained with BCE loss, Adam, early model selection on
validation detection-rate penalized by false-positive-rate.

**Why a sequence model and not a flat classifier?** Injection *is* a sequence —
the order and timing of allocate / write / protect / thread carry the signal,
and the same APIs appear in benign code in a different order and context.

---

## 4. Dataset

All data was collected on a live Windows machine by running the EDR's own test
harnesses with the hook attached, and extracting the resulting telemetry.

**Injection (41 traces, 3 techniques):**

| Technique | Traces | Behavioral signature at the hook level |
|---|---|---|
| `remote_thread` (test_target) | 23 | `VirtualAllocEx`(RW) → `WriteProcessMemory` → `VirtualProtect`(exec), **in-process** |
| `shellcode_runner` | 7 | `VirtualAlloc`(RWX) → `CreateThread` into private exec memory, **in-process** |
| `process_hollowing` | 11 | `VirtualAllocEx`(RWX) + many `WriteProcessMemory`, **cross-process** (`target_pid ≠ pid`) |

**Benign (14 traces):** a purpose-built control process that mimics a JIT
runtime — in-process `VirtualAlloc`(RW) then `VirtualProtect` to executable —
but performs **no `WriteProcessMemory` and no cross-process operation**. This is
the hard "false-positive" case the rule engine must also handle.

Total: **55 traces.**

---

## 5. Results

### 5.1 Trained on all techniques

| Metric | Value |
|---|---|
| Detection rate (recall) | **97.6 %** (40/41) |
| False-positive rate | **0 %** (0/14 benign) |
| Precision | **1.00** |
| ROC AUC | **1.00** |

Per-technique detection: `process_hollowing` 100 %, `shellcode_runner` 100 %,
`remote_thread` 95.7 %. AUC 1.0 means the single miss is a threshold artifact —
the model *ranks* every injection above every benign process.

### 5.2 Leave-one-technique-out (generalization)

Each technique is removed **entirely** from training, then the model is tested
on it — measuring detection of a *novel* technique the model never saw.

| Held-out technique | Detection |
|---|---|
| `process_hollowing` | **100 %** (11/11) ✅ |
| `shellcode_runner` | **100 %** (7/7) ✅ |
| `remote_thread` | **0 %** (0/23) ❌ |

---

## 6. The key finding

The detector learns a **general notion of "aggressive" injection**, but has a
**blind spot for subtle in-process self-injection**.

- **It generalizes to hollowing and shellcode even when unseen**, because those
  techniques share strong, transferable signals: cross-process operations
  (`target_pid ≠ pid`) and directly-allocated RWX executable memory. A model
  that has learned these from one technique recognizes them in another.

- **It fails to generalize to `remote_thread`**, because at the hook level that
  technique is almost identical to the benign JIT control: an in-process RW
  allocation followed by a protect-to-executable. The *only* distinguishing
  event is an **in-process `WriteProcessMemory`**. If the model never sees a
  `remote_thread` example, it has no reason to treat that subtle cue as
  malicious, so it classifies it as benign.

**In one sentence:** the model generalizes across injection techniques that
*look* dangerous (cross-process, RWX), but not to self-injection that mimics
legitimate runtime behavior and is separated from it by a single API call.

This is a more informative result than uniform 100 % accuracy: it maps exactly
*which* techniques are detectable-by-generalization and *why*.

---

## 7. Limitations

- **Small dataset** (55 traces). Metrics are strong but the honest evidence of
  generalization is the leave-one-technique-out test, not the aggregate numbers.
- **Benign is synthetic.** The control process approximates JIT behavior; it was
  not possible to inject the hook into a real .NET host (PowerShell) because the
  DLL fails to initialize under the loader lock in a complex managed process.
  A real-JIT benign set would harden the false-positive claim.
- **`remote_thread` ≈ benign** at the hook level, which is exactly why it is the
  interesting failure case — but it also means the in-process class is thin.
- User-mode hooks only; techniques using direct syscalls would bypass the sensor
  entirely (a property of the EDR, inherited by the detector).

---

## 8. Future work

- More techniques (module stomping, reflective loading) to further probe the
  generalization boundary.
- Real benign JIT telemetry (.NET / Node / JVM) for a trustworthy FP rate.
- Richer / shared features and a per-event attention mechanism.
- Deploy inline: score each process in the FastAPI dashboard next to the FSM
  verdict, using the raw per-process event stream.

---

## 9. Interview talking points (Q → A)

**Q: What did you actually build?**
A GRU that reads the sequence of hooked Win32 API calls the EDR observes for a
process and outputs the probability that the process was injected. It's a
behavioral detector on top of the EDR's own telemetry.

**Q: Why a recurrent model and not features + a classifier?**
Injection is a temporal pattern — allocate, write, make-executable, create
thread. Order, timing and the cross-process relationship carry the signal, and
the same primitives appear in benign JIT in a different sequence. A GRU models
the sequence directly; a bag-of-features would throw the order away.

**Q: What features, and why?**
One-hot of the six APIs, plus `cross_process` (target PID ≠ caller PID),
executable/writable protection bits, log size, and inter-event time. These
capture the injection chain and, crucially, whether the operation crosses into
another process. I dropped raw addresses on purpose — no signal, pure overfit
risk.

**Q: What's the headline result?**
97.6 % detection at 0 % false positives, AUC 1.0, on three injection techniques
plus a benign control.

**Q: Isn't AUC 1.0 suspicious on a small set?**
Yes, which is why the real test is leave-one-technique-out. There the story is
nuanced: the model generalizes to *unseen* hollowing (100 %) and shellcode
(100 %), but gets 0 % on unseen `remote_thread`.

**Q: Why does `remote_thread` fail to generalize?**
Because at the API level it is nearly indistinguishable from the benign JIT
control — in-process RW allocation then protect-to-executable. The only
malicious tell is an in-process `WriteProcessMemory`, and the model only learns
that cue if `remote_thread` is in the training set. Hollowing and shellcode, by
contrast, carry cross-process writes and RWX allocations that transfer between
techniques.

**Q: How did you get labeled data?**
I ran the EDR's existing attack test harnesses with the hook attached and
captured the telemetry, labeling each run by technique. The benign class is a
control process I wrote that reproduces JIT-like memory behavior without the
injection primitives.

**Q: How would you deploy it?**
In-process in the agent: accumulate the raw event sequence per monitored PID and
score it, surfacing the ML probability alongside the rule-based FSM severity —
a second opinion that catches reordered / novel variants the rules miss.

**Q: What would you do with more time?**
Collect real JIT benign telemetry to validate the FP rate, add more techniques
to widen the generalization test, and move to syscall-level sensing so
direct-syscall evasion doesn't blind the detector.
