# ArgusEDR — ML injection detector

A learned second opinion alongside the Diamond FSM. The FSM escalates severity
by fixed rules; this model reads a process's **full sequence** of hooked API
events and outputs a probability that the process was the victim of an
injection. The goal is to separate real injection from legitimate in-process
behaviour (JIT engines like PowerShell / node / Java allocate, write, and make
memory executable too) — the exact case the FSM has to hard-code around.

This directory is **defensive only**: feature extraction, a model, training and
evaluation. No attack code. The malicious samples used for training come from
running your *existing* Argus attack tests on Windows (see below), not from any
generated attack code.

## Files

| File | What it does |
|------|--------------|
| `schema.py` | Trace format + event → feature vector (11 features). Single source of truth. |
| `dataset.py` | Load NDJSON traces, batch variable-length sequences with padding. |
| `model.py` | Small GRU classifier (`InjectionGRU`). |
| `train.py` | Training loop, train/val split, saves best model. |
| `evaluate.py` | Metrics + **leave-one-technique-out** generalisation test. |
| `collect.py` | **Run on Windows** — records real labelled traces from the agent log. |
| `_smoke_test.py` | Mechanical pipeline self-test on abstract random data (no attack content). |
| `seeds_eval.py` | The evaluation behind RESULTS: full-set + leave-one-technique-out over several seeds, with and without timestamps. |

## Feature vector (per event)

`[ one-hot of the 6 hooked APIs | cross_process | exec_protect | write_protect | log10(size) ]`

Addresses are intentionally dropped (no signal, invites overfitting).
Inter-event timing is intentionally **off** (`schema.USE_TIMING = False`): the
lab timestamps measured the test harness's pace, and the model learned it as a
shortcut — see [RESULTS §6](RESULTS.md#6-the-timing-shortcut-found-in-the-live-demo).
`cross_process` = `target_pid != pid` — the strongest injection cue.

---

## Step 1 — collect data (on Windows)

Build the project as usual, then collect traces. Each capture writes one NDJSON
file. **`collect.py` needs only Python** (no torch), so it runs on the same
machine as the agent.

### Injection traces (one technique at a time)

Three elevated consoles, in `build\bin\Release`:

```powershell
# Console A — agent, logging to a file
.\argus_agent.exe > argus_agent.log 2>&1

# Console B — recorder (label the run by its technique)
python collect.py --agent-log argus_agent.log --label injection ^
    --technique process_hollowing --out data\hollowing_01.ndjson

# Console C — run the matching attack test and inject the hook into it
.\test_ProcessHollowing.exe        # note its PID
.\injector.exe <PID> argus_hook.dll
.\injector.exe <PID> argus_pesieve.dll
```

Let the test run to completion, then Ctrl-C console B (or let it idle-timeout).
**Repeat each test many times** to get many traces — a simple loop is enough,
natural run-to-run variation gives the model something to learn from:

```powershell
for ($i=1; $i -le 30; $i++) { .\test_ProcessHollowing.exe; <inject + trigger> }
```

Do this for each existing test, using a distinct `--technique` tag per file:

| Test binary | `--technique` |
|-------------|---------------|
| `test_target` (alloc→write→protect→thread) | `remote_thread` |
| `test_ProcessHollowing` | `process_hollowing` |
| `test_ModuleStomping`, `test_ModuleStomping2` | `module_stomping` |
| `shellcode_runner` | `shellcode_runner` |

### Benign traces (including the hard JIT case)

Same agent + recorder, but inject the hook into an ordinary running process and
use it normally for a minute:

```powershell
# Console B
python collect.py --agent-log argus_agent.log --label benign ^
    --out data\benign_powershell_01.ndjson
# Console C — inject into a real process and exercise it
.\injector.exe <PID-of-powershell/node/java/chrome> argus_hook.dll
```

Cover several benign apps, and make sure to include JIT runtimes
(**PowerShell, node, Java**) — those are the ones the FSM has to treat
carefully, so they are the most valuable benign data.

### How much

Aim for a few dozen traces per technique and a comparable number of benign
traces, with JIT well represented. Keep the two classes roughly balanced.

> **Timing caveat:** raw events carry no timestamp, so `collect.py` stamps
> *arrival* time. It is saved in the traces but not used as a feature — in the
> lab it measured how long the harness waited between steps, not the behaviour.
> If `hooks.c` later adds a real `t_ms` to the event JSON, `collect.py` uses it
> and timing can be re-enabled in `schema.py`.

---

## Step 2 — train (anywhere with PyTorch)

```bash
pip install torch        # CPU build is fine
python train.py --data "data/*.ndjson" --epochs 40 --out model.pt
```

Prints per-epoch validation detection rate / false-positive rate and saves the
best checkpoint.

## Step 3 — evaluate

```bash
python evaluate.py --data "data/*.ndjson" --model model.pt
```

Reports detection rate, **false-positive rate on benign/JIT**, precision, AUC,
and a per-technique breakdown.

### The test that matters for the write-up

Leave-one-technique-out — train with one technique entirely removed, then test
on it. This shows the model generalises to injection it never saw, rather than
memorising the handful of tests:

```python
from dataset import load_many
from evaluate import leave_one_technique_out
import glob, json
traces = load_many(glob.glob("data/*.ndjson"))
print(json.dumps(leave_one_technique_out(traces, epochs=40), indent=2))
```

## Step 4 — (later) wire into the dashboard

The dashboard (`dashboard/server.py`) already receives every hook event. The
model can run there: accumulate events per `target_pid`, and when a process
reaches a decision point, run the sequence through the model and show the ML
score next to the FSM severity. One requirement — the dashboard must keep the
**raw** events per process (api / pids / size / protect), not just the
per-event API counts it currently aggregates.

## Verify the pipeline locally (no data needed)

```bash
python _smoke_test.py   # trains on abstract random data; prints PIPELINE OK
```

## Related

- **ArgusEDR**, the EDR this model reads telemetry from (C++, team project): [github.com/lotem-g30/EDR](https://github.com/lotem-g30/EDR)
- **[`argus-copilot/`](../argus-copilot)**, the LLM incident-analyst agent in this repo. It uses
  this model as one of its tools (`score_injection_model`) and reports the GRU score
  next to the rule-based verdict.
