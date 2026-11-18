# Dashboard integration — EXPLAIN button

**In this repo it is already wired.** `edr/dashboard/server.py` has a short,
optional block that includes `explain_route.router`, and `edr/dashboard/index.html`
adds an **EXPLAIN** button to every process card plus a side panel for the report.
Start the dashboard as usual (`edr\start_dashboard.bat`, as Administrator),
click **RUN DEMO**, then **EXPLAIN** on a process.

- Without `ANTHROPIC_API_KEY` the panel shows the offline mock report.
- With a key set before starting the dashboard, Claude writes the report.
- With torch installed and `argus-ml/model.pt` present, the GRU score is included.
- `GET /api/explain/status` shows the active backend, the log path and ML status.

## Other setups

1. Make `argus-copilot/` and this folder importable (or `pip install -e "argus-copilot[api]"`).
2. In the FastAPI app:

   ```python
   import explain_route
   explain_route.configure(lambda: Path("path/to/argus_agent.log"))  # or set ARGUS_AGENT_LOG
   app.include_router(explain_route.router)
   ```

3. Add a button that POSTs to `/api/explain/{pid}`. `explain_button.html` is a
   standalone version of the button and panel.

The route is a plain `def`, so FastAPI runs it in a worker thread and a slow
model call never blocks the dashboard's live WebSocket feed.
