# Argus AI: ML and LLM layers for the ArgusEDR endpoint detection system

My follow-up project to [ArgusEDR](https://github.com/lotem-g30/EDR), a team-built
Windows EDR in C++ (Win32 API hooks, named-pipe IPC, PE-Sieve, YARA, ETW, and a
rule-based correlator). This repo adds two AI layers on top of the EDR's own
telemetry:

```
 ArgusEDR (C++, team project)      argus-ml/ (PyTorch)              argus-copilot/ (LLM agent)
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
| [`argus-ml/`](argus-ml) | A GRU that flags process injection from sequences of hooked API calls. It trains on traces collected from the EDR's own attack tests. | [README](argus-ml/README.md) · [GUIDE](argus-ml/GUIDE.md) · [RESULTS](argus-ml/RESULTS.md) |
| [`argus-copilot/`](argus-copilot) | An LLM incident analyst. It investigates a flagged process with tools, maps it to MITRE ATT&CK, and writes a report. It also ships a CLI, a FastAPI service, a dashboard "Explain" button, evals and tests. | [README](argus-copilot/README.md) |

## Quick start

```bash
# LLM agent, offline mock backend: no install, no API key
cd argus-copilot
python -m argus_copilot analyze data/remote_thread.ndjson --mock -v
python evals/run_evals.py

# ML pipeline self-test (needs torch)
cd ../argus-ml
pip install -r requirements.txt
python _smoke_test.py
```

The two parts connect automatically. `argus-copilot` finds the sibling
`argus-ml/` folder, and once a trained `model.pt` is there it offers the GRU to
the agent as a fourth tool.

## CI

`.github/workflows/ci.yml` runs on every push:
- the Copilot's unit tests and evals, offline;
- the ML pipeline smoke test.

## Credits

ArgusEDR, the base system, is a team project. See
[its repository](https://github.com/lotem-g30/EDR) for the team and credits.
`argus-ml` and `argus-copilot` are my own follow-up work.

## License

MIT © Nikol Kofman (this repository). ArgusEDR has its own repository and license.
