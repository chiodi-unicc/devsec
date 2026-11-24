---
title: Dashboard
nav_order: 7
---

# Dashboard

A local web page that shows scans as they run, their findings and the policy.
{: .fs-5 .fw-300 }

```sh
devsec ui
```

The dashboard starts in the background and opens in your browser at
`http://127.0.0.1:4321` (the next free port if that one is taken). An agent can open it
with the `devsec_ui` tool.

![The dashboard showing a failed scan: each pipeline step, reused from cache, and the flagged findings]({{ "/assets/dashboard-fail.png" | relative_url }})

It shows:

- **Runs**: every scan of the repository, newest first. A scan started from the CLI or
  by an agent appears and updates live.
- **Pipeline**: each step with its status, duration and, for skipped steps, the reason.
- **Findings**: new or all, filtered by verdict.
- **Policy**: the Rego in use and its result.

The dashboard reads `.devsec/` and has no state of its own. It only accepts connections
from the local machine.

## Options

```sh
devsec ui --port 5000     # preferred port
devsec ui --no-open       # don't open the browser
devsec ui --stop          # stop it
```

Running `devsec ui` again reuses the dashboard already serving the repository.
