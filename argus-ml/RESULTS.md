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

**Per-event feature vector (10 dims):**

| Feature | Meaning |
|---|---|
| API one-hot (6) | which of the six APIs |
| `cross_process` | `target_pid != pid` — the strongest injection cue |
| `exec_protect` | the protection grants EXECUTE |
| `write_protect` | the protection grants WRITE |
| `log10(size)` | allocation / write size |

Raw addresses are deliberately dropped (no signal, would invite overfitting).
An inter-event timing feature (`log10(Δt)`) was part of the first version and
was **removed** after the live demo exposed it as a shortcut — see §6.
Architecture: linear projection → 1-layer GRU (hidden 48) → last hidden state →
linear → sigmoid. Trained with BCE loss, Adam, early model selection on
validation detection-rate penalized by false-positive-rate.

**Why a sequence model and not a flat classifier?** Injection *is* a sequence —
the order of allocate / write / protect / thread carries the signal,
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

Every number is the mean over **5 training seeds** (`python seeds_eval.py --data "data/*.ndjson"`),
because a single run on 55 traces can be lucky. Model: 10 features, no timing.

### 5.1 Trained on all techniques

| Metric | Value |
|---|---|
| Detection rate (recall) | **100 %** (41/41, every seed) |
| False-positive rate | **0 %** (0/14 benign) |
| Precision | **1.00** |
| ROC AUC | **1.00** |

Per-technique detection: `process_hollowing`, `shellcode_runner` and
`remote_thread` all 100 %. The numbers are identical with the timestamps removed
from the traces, as they are in the live agent log — the model has no timing
input any more (§6). These are training-set numbers on a small dataset; the
honest test of generalization is §5.2.

### 5.2 Leave-one-technique-out (generalization)

Each technique is removed **entirely** from training, then the model is tested
on it — measuring detection of a *novel* technique the model never saw.

| Held-out technique | Detection (5 seeds) |
|---|---|
| `process_hollowing` | **100 %** — every seed ✅ |
| `shellcode_runner` | **100 %** — every seed ✅ |
| `remote_thread` | **0 %** — every seed ❌ |

---

## 6. The timing shortcut (found in the live demo)

The first version also used the time between events. It scored 97.6 % on the
full set. The problem surfaced only when the model ran live:

1. In the ArgusEDR dashboard, the Copilot's **EXPLAIN** report on `test_target.exe`
   showed the rules at **CRITICAL** and the GRU at **P(injection) = 0.35 → benign**.
2. The agent log has **no timestamps**, so every time gap the model saw was 0.
3. The lab traces did have timestamps, but `collect.py` records *arrival* time,
   and `test_target` **waits for Enter between steps** — about 20 s per step.
   The benign control has no such pauses.
4. So the model had partly learned *"long pauses between allocate → write →
   protect = injection"*: the **pace of the test harness**, not the behaviour.
   Scoring the training traces with timestamps removed reproduced the live
   number exactly: `remote_thread` mean P(injection) fell from **0.99 to 0.35**.

Fix: drop the timing feature (`schema.USE_TIMING = False`) and retrain.
Same protocol, same 5 seeds, before vs after:

| | With timing (before) | Without timing (now) |
|---|---|---|
| Detection, traces as captured | 98.1 % | **100 %** |
| Detection, **timestamps removed** (= live agent log) | 55.1 % (`remote_thread` 20 %) | **100 %** |
| Leave-out `process_hollowing` | 80 % (4 of 5 seeds) | **100 %** (5 of 5) |
| Leave-out `shellcode_runner` | 20 % (1 of 5 seeds) | **100 %** (5 of 5) |
| Leave-out `remote_thread` | 19 % (1 of 5 seeds) | 0 % (0 of 5) |
| Benign mean P(injection) | 0.18 | 0.32 (still below 0.5) |

Two lessons:
- **A feature that describes how the data was collected leaks into the model.**
  Nothing in the lab metrics showed it; only a deployment-like input did.
- **The earlier single-seed leave-out result was partly luck.** With timing, the
  "generalizes to unseen shellcode" claim held in 1 seed of 5. Without timing it
  holds in all 5. Reporting over several seeds is now the default.

The price: benign traces now score closer to the threshold (mean 0.32 vs 0.18),
so the false-positive margin is narrower. A real-JIT benign set (§8) matters more.

---

## 7. The key finding

The detector learns a **general notion of "aggressive" injection**, but has a
**blind spot for subtle in-process self-injection** — in every one of the five seeds.

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

## 8. Limitations

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
- **No real timing.** Timing may well be a genuine signal, but only once the
  hook DLL stamps real event times; arrival time in a lab measures the lab (§6).

---

## 9. Future work

- More techniques (module stomping, reflective loading) to further probe the
  generalization boundary.
- Real benign JIT telemetry (.NET / Node / JVM) for a trustworthy FP rate.
- Richer / shared features and a per-event attention mechanism.
- Stamp real event times in the hook DLL, then re-test timing as a feature.
- Deploy inline. Partly done: the dashboard's **EXPLAIN** button
  (`argus-copilot`) runs this model per process on demand, next to the FSM
  verdict. Next: score continuously as events arrive.

---

## 10. Interview talking points (Q → A)

**Q: What did you actually build?**
A GRU that reads the sequence of hooked Win32 API calls the EDR observes for a
process and outputs the probability that the process was injected. It's a
behavioral detector on top of the EDR's own telemetry.

**Q: Why a recurrent model and not features + a classifier?**
Injection is a sequential pattern — allocate, write, make-executable, create
thread. Order and the cross-process relationship carry the signal, and
the same primitives appear in benign JIT in a different sequence. A GRU models
the sequence directly; a bag-of-features would throw the order away.

**Q: What features, and why?**
One-hot of the six APIs, plus `cross_process` (target PID ≠ caller PID),
executable/writable protection bits and log size. These capture the injection
chain and, crucially, whether the operation crosses into another process. I
dropped raw addresses on purpose — no signal, pure overfit risk — and later
dropped inter-event time, because it turned out to be a shortcut (next answers).

**Q: What's the headline result?**
100 % detection at 0 % false positives on three injection techniques plus a
benign control, averaged over 5 seeds — but the result I'd lead with is the
leave-one-technique-out test and the timing shortcut I found.

**Q: Isn't AUC 1.0 suspicious on a small set?**
Yes, which is why the real test is leave-one-technique-out. There the story is
nuanced: the model generalizes to *unseen* hollowing and shellcode (100 % in
every seed), but gets 0 % on unseen `remote_thread`.

**Q: Did you find any problems with your own model?**
Yes — in the live demo. The LLM agent I built over the EDR showed the GRU
saying "benign" (0.35) where the rules said CRITICAL. I traced it: the lab
timestamps were arrival times, and my test program waits for Enter between
steps, so the model had learned the harness's pauses. The live log has no
timestamps, so the cue vanished. Stripping timestamps from the training traces
reproduced 0.35 exactly. I removed the feature and retrained: detection without
timestamps went from 55 % to 100 %, and the generalization results became stable
across seeds instead of depending on luck.

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
