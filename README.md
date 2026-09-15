# SPL Critic

> **Experimental. Not production software.** SPL Critic is a personal
> research and demonstration project built for a conference talk. It is
> published for education: to show one way an agent can judge Splunk
> searches from their structure and their measured history. It is not
> supported, not endorsed by any employer or vendor, has no warranty, no
> roadmap commitments, and no guarantee that any verdict, rewrite, or
> recommendation it produces is correct or safe to apply. Run it on a test
> instance. Read every rewrite before you use it. Do not point it at
> production data you are not allowed to send to a third-party model.

An AI second opinion for Splunk searches, packaged as a Splunk app.

SPL Critic is **agent-judged**. It gathers everything about a search that a
careful reviewer would want (the SPL, the dispatch window, the schedule, 30
days of scheduler and audit telemetry, the indexes that exist, dashboard
refresh cadence) and hands it to a language model with a knowledgebase brief
of coded anti-patterns. The model returns the verdict, the findings, the
rewrite, and a disposition (keep, fix, or retire). No rulebook ever presents
a verdict on its own: without a configured model the app says so instead of
guessing.

Version 0.5.0.

## What you get

- **Critique**: paste SPL, pick the dispatch window, get the agent's verdict
  with findings, a parser-validated rewrite, and (optionally) a deep analysis
  where the agent runs the search under guards and measures its own rewrite.
- **Auditor**: every saved search in the environment, with measured facts
  per row and the agent's verdict, ranked worst-first; portfolio findings
  (scheduler herd, cron stacking, scan budget, near-duplicates, vendor-default
  schedules, data model acceleration hygiene, dashboard refresh load); an
  executive health memo; exportable HTML and CSV; reopenable stored runs.
- **Knowledgebase**: the coded anti-pattern vocabulary the agent is briefed
  with, browsable in-app, extendable with environment-local rules.

## Install

1. Splunk Web: Apps → Manage Apps → Install app from file → pick
   `releases/spl_critic-0.5.0.spl` → restart when prompted.
2. Verify: `GET https://<host>:8089/services/spl_critic/health` returns the
   version.

Runs on Splunk Enterprise 9.x/10.x (the app's Python targets Splunk's
bundled Python 3.9). Single-instance and search-head deployments; KV Store
must be enabled (it is by default).

## Configure the model

SPL Critic talks to models through [OpenRouter](https://openrouter.ai). The
key lives in Splunk's encrypted credential store, never in a conf file.

```bash
# store the key and pick models (first is primary, the rest are fallbacks)
curl -k -u admin:<password> https://<host>:8089/services/spl_critic/config \
  -d '{{"openrouter_api_key": "<your key>",
       "models": "deepseek/deepseek-v4-pro,deepseek/deepseek-v4-flash"}}'

# environment-specific guidance appended to the agent's brief
curl -k -u admin:<password> https://<host>:8089/services/spl_critic/config \
  -d '{{"extra_guidance": "index=web is 5TB/day; never scan index=frozen_archive interactively."}}'
```

The Settings view in the app does the same over a form. Nothing is judged
until a model is configured: the Critique view shows "analysis unavailable"
and the Auditor gathers facts but leaves every row pending.

## Environment-local rules

Add coded patterns unique to your environment; they join the agent's
vocabulary and the agent decides whether they apply.

```bash
curl -k -u admin:<password> https://<host>:8089/services/spl_critic/rules \
  -d '{{"id": "LOCAL_FROZEN_ARCHIVE_SCAN", "severity": "high", "scope": "retrieval",
       "regex": "(?i)index=frozen_archive", "name": "Frozen archive scan",
       "cost_rationale": "40TB on slow storage", "canonical_rewrite": "Use index=hot_web"}}'
```

Custom rules are stored in `local/spl_critic_rules.conf` and can also be
managed by any conf deployment mechanism.

## Status and limits

- **Experiment, not product.** One person built this to explore an idea and
  demo it. Expect rough edges, breaking changes between versions, and gaps.
- **No guarantees.** The agent's output is model inference over the facts it
  is given. It can be wrong, incomplete, or confidently misleading. Nothing
  here replaces your own review, your change process, or Splunk's own tooling.
- **Sends SPL to a third-party model.** Redaction covers obvious secrets, not
  everything. Check your data-handling obligations before configuring a key.
- **Costs money.** Every judgment is a model call billed to your OpenRouter
  account. The cache makes repeats free; the first full portfolio pass is not.
- **Tested narrowly.** Developed against a single-instance Splunk Enterprise
  10.4 test box with synthetic data. Search head clusters, Splunk Cloud,
  older releases, and large portfolios are untested.
- **No support.** Issues and pull requests are welcome, answers are not
  promised. Use at your own risk.

## Privacy and safety

- SPL is redacted (encrypted-value prefixes and secret-looking keys) before
  it reaches the model; the redaction count is shown on every critique.
- Deep analysis executes searches only under guards: `| head 1000`, a
  bounded window, a hard timeout, and a refusal list for side-effecting
  commands (`delete`, `collect`, `outputlookup`, ...).
- Inference results are cached in KV Store so repeated critiques are free;
  the Settings view shows what was spent, on which model.

## Layout

- `app/spl_critic/` - the packaged app, exactly as released
- `releases/` - installable `.spl` archives
- `CHANGELOG.md` - release notes

## License

See `LICENSE`.
