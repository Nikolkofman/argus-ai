# Dashboard integration — "Explain" button

Adds an **Explain** button next to each process in the ArgusEDR FastAPI
dashboard. Clicking it opens a side panel with the Copilot's incident report
for that PID, built from the same `argus_agent.log` the dashboard already reads.

## 3 steps

1. **Install the Copilot** into the dashboard's Python environment:

   ```bash
   pip install -e "path/to/argus-copilot[api]"      # add [claude] to use the real model
   ```

2. **Add the route** — copy `explain_route.py` next to `dashboard/server.py`
   and add two lines to `server.py`:

   ```python
   from explain_route import router as explain_router
   app.include_router(explain_router)
   ```

   If the agent log is not at `build/bin/Release/argus_agent.log`, set
   `ARGUS_AGENT_LOG`.

3. **Add the button** — paste `explain_button.html` before `</body>` in the
   dashboard page, and where process rows are rendered:

   ```js
   row.appendChild(explainButton(pid));
   ```

Check it: `GET /api/explain/status` shows the active backend (mock or
Claude), the log path, and whether the GRU model is loaded.

Without `ANTHROPIC_API_KEY` the panel shows the offline mock report, so the demo
works with no key and no network.
