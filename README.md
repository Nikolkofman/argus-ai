# Argus AI: ArgusEDR with ML and LLM layers

ArgusEDR is a Windows EDR in C++ with a live dashboard. It uses Win32 API hooks,
named-pipe IPC, PE-Sieve, YARA, ETW, and a rule-based correlator. This repo puts
the original EDR together with my follow-up work: two AI layers that read the
EDR's own telemetry.

```
 edr/ (C++, ArgusEDR)              argus-ml/ (PyTorch)              argus-copilot/ (LLM agent)
 ───────────────────────────       ─────────────────────────        ──────────────────────────
 Win32 hooks → named-pipe IPC      GRU over the same hook events    tool-use agent: timeline ·
 PE-Sieve · YARA · ETW             → P(injection)                   findings · ATT&CK · GRU score
 Diamond FSM rules                 learned second opinion           incident report + Q&A
 precise, explainable, brittle     generalises to unseen variants   explains, maps, recommends
```

The rules decide, the model gives a second opinion, and the agent explains both,
including when they disagree.

| Folder | What it is | Start here |
|---|---|---|
| [`edr/`](edr) | The original ArgusEDR: agent, hook DLL, PE-Sieve/YARA scanning, the Diamond FSM correlator, and the dashboard. Imported with its full git history. | [README](edr/README.md) |
| [`argus-ml/`](argus-ml) | A GRU that flags process injection from sequences of hooked API calls. It trains on traces collected from the EDR's own attack tests. | [README](argus-ml/README.md) · [GUIDE](argus-ml/GUIDE.md) · [RESULTS](argus-ml/RESULTS.md) |
| [`argus-copilot/`](argus-copilot) | An LLM incident analyst. It investigates a flagged process with tools, maps it to MITRE ATT&CK, and writes a report. It also ships a CLI, a FastAPI service, a dashboard "Explain" button, evals and tests. | [README](argus-copilot/README.md) |

## Quick start

```bash
# LLM agent, offline mock backend: no install, no API key
cd argus-copilot
python -m argus_copilot analyze data/remote_thread.ndjson --mock -v
python evals/run_evals.py

# The EDR dashboard with the EXPLAIN button (Windows, after building edr/)
edr\start_dashboard.bat        # as Administrator → RUN DEMO → EXPLAIN on a process

# ML pipeline self-test (needs torch)
cd ../argus-ml
pip install -r requirements.txt
python _smoke_test.py
```

The two parts connect automatically. `argus-copilot` finds the sibling
`argus-ml/` folder and its trained `model.pt`, which is included together with
the collected traces in `argus-ml/data/`. When torch is installed, the agent
gets the GRU as a fourth tool.

## CI

`.github/workflows/ci.yml` runs on every push:
- the Copilot's unit tests and evals, offline;
- the ML pipeline smoke test.

## Credits

`edr/` is the original ArgusEDR team project, imported from
[its repository](https://github.com/lotem-g30/EDR) with its commit history, so
every contributor's work stays attributed. See [`edr/README.md`](edr/README.md)
for the team. `argus-ml/` and `argus-copilot/` are my own follow-up work.

## License

`argus-ml/` and `argus-copilot/`: MIT © Nikol Kofman. `edr/` keeps the terms of
its original repository.
