# Quarantine Sentinel

A small, out-of-band poller that catches false positives in your
[Proxmox Mail Gateway](https://www.proxmox.com/en/proxmox-mail-gateway)
quarantine — without ever touching PMG's spam filtering itself.

It logs into PMG read-only, pulls quarantined mail for every user, and asks
an LLM "is this actually spam?" for anything it hasn't scored before. Mails
the model is confident are legitimate show up in a digest so a human can
release them.

## What it does

- Authenticates to a PMG node via ticket-based auth (PMG has no API tokens)
- Fetches quarantined messages for all users within a configurable lookback window
- Scores each new message against an LLM (Ollama, OpenAI, or Claude) to flag likely false positives
- Caches every verdict in a local SQLite database so a mail is never re-scored
- Prints a digest of probable false positives, with the LLM's reasoning and PMG's own spam score for context
- Never calls a mutating PMG endpoint — releasing a flagged mail is always a manual, human decision

## Quick start

Requires Python 3.11 or newer and [`uv`](https://docs.astral.sh/uv/).
Tested with Proxmox Mail Gateway 9.x.

Before running the poller, create a dedicated PMG account and assign it the
`Auditor` role, which provides the read access needed by the poller. See the
official PMG guide under
[User Management](https://pmg.proxmox.com/pmg-docs/pmg-admin-guide.html#_user_management)
for the available account types and roles. Do not reuse the `root` account.

```bash
# 1. Copy the example config and fill in your PMG credentials
cp config.toml.example config.toml

# 2. Set your LLM API key as an environment variable (don't put it in config.toml)
export ANTHROPIC_API_KEY=sk-ant-...
# or: export OPENAI_API_KEY=sk-...

# 3. Run it — uv installs the inline dependency (`anthropic`) automatically
uv run quarantine_sentinel.py
```

Using Ollama instead? No extra dependency needed — just set `backend = "ollama"`
in `config.toml` and run the same command. For OpenAI, run with `uv run --with openai quarantine_sentinel.py`.

```bash
# Custom config path
uv run quarantine_sentinel.py -c /path/to/config.toml

# Interactively add current quarantine recipients (e.g. shared mailboxes,
# mailing lists) to the local skip list
uv run update_rcpt_ignore.py
```

## Example output

The following digest uses fictional addresses and message data:

```text
========================================================================
  PMG Quarantine False-Positive Report — 2026-08-24 09:42 UTC
========================================================================
  Mails in scope : 4  (3 scored this run, 1 from cache)
  LLM            : claude / claude-haiku-4-5
  Threshold      : ham confidence >= 70%

  LIKELY FALSE POSITIVES  (2 mail(s) above threshold):

  * 96% HAM   id=QF9A7C21E4
    From:    invoices@northwind.example
    Subject: Invoice NW-2026-1842
    Score:   5.4
    Reason:  Expected transactional invoice with aligned SPF and DKIM.

  * 88% HAM   id=QF31B8D902
    From:    events@city-library.example
    Subject: Registration confirmation for security workshop
    Score:   6.1
    Reason:  Legitimate confirmation matching the recipient and event context.

  UNCERTAIN — ham, but below threshold  (1 mail(s)):

  ?  62% ham  id=QF7E0A114B  newsletter@sample-shop.example
           Your August account update
           Plausible newsletter, but authentication signals are incomplete.

  Confirmed spam (not listed): 1 mail(s)

  To release a mail (human decision required):
    # Via PMG web UI: Quarantine -> select mail -> Deliver
    # Via API (POST to https://pmg.example.com:8006):
    #   Path: /api2/extjs/quarantine/content
    #   Body: {"action": "deliver", "id": "<mail_id>"}
========================================================================
```

## Configuration

Everything lives in `config.toml` — see `config.toml.example` for a fully
commented template. Key settings:

| Setting | Purpose |
|---|---|
| `[pmg]` | PMG URL and credentials (a dedicated account is recommended) |
| `[llm]` | Backend (`ollama` / `openai` / `claude`), model, API key |
| `rcpt_ignore` | Recipient addresses skipped locally before any mail is fetched or scored |
| `lookback_days` | How far back to check quarantine |
| `confidence_threshold` | Minimum ham-confidence to surface a mail in the digest |
| `max_mails_per_run` | Cap on LLM calls per run (cached verdicts don't count against it) |
| `policy_file` | Your own scoring policy, replacing the shipped `default_policy.md` |

`config.toml` and the SQLite database are git-ignored — they contain
credentials and real mail metadata and should never be committed.

### Scoring policy

The system prompt is assembled from three parts:

```
[ security boundary + role ]   hard-wired in quarantine_sentinel.py
[ scoring policy           ]   default_policy.md, or your own policy_file
[ JSON output contract     ]   hard-wired in quarantine_sentinel.py
```

Only the middle part is yours to change — the spam and ham signals, how much
weight authentication failures carry, whether cold outreach counts as spam.
Copy `default_policy.md`, edit it, and point `policy_file` at your copy; a
configured file replaces the default rather than extending it. Relative paths
resolve against the config file's directory, so cron runs find them.

The other two parts are fixed, with different force:

- **Output contract** — enforced by `_parse_llm_json()`, which rejects anything
  that is not `{verdict ∈ {ham, spam}, confidence, reason}`. Its position at the
  end of the prompt is only a nudge; the parser is the actual guarantee.
- **Security boundary** — *not* enforced. It shares one system prompt, one
  instruction level, with your policy. A policy declaring text inside
  `EMAIL_DATA` to be instructions contradicts it, and the model decides which
  wins. The split only prevents deleting the boundary by accident while editing
  a copied policy file. Guard against oversight, not a security control.

Verdicts are cached per message and are **not** re-scored when the policy
changes. Each run prints which policy file it used; delete the database if you
want a clean slate after a rule change.

## Legal note

Using a cloud LLM backend (OpenAI, Anthropic) sends message metadata,
authentication and spam-filter context, the hosts that body links and images
point to, and a text-body excerpt limited by `body_max_chars` to a third
party. Of attachments, including attached e-mails, only name, type and size
are sent — never their content. Check GDPR / data protection requirements
with your legal team before pointing this at a mailbox with real user data.
Use an on-premises Ollama instance to keep LLM processing within your own
infrastructure.

Verdicts and selected message metadata are stored in the local SQLite database.
Protect this file accordingly and delete it according to your data-retention
policy when it is no longer needed.

## How it decides

Every backend gets the same system prompt (see *Scoring policy* above) and is
asked to return
`{"verdict": "ham"|"spam", "confidence": 0.0-1.0, "reason": "..."}`. The
model sees PMG's own spam-rule hits and authentication results as *context*,
not as a verdict — it has to explain why a high spam score is or isn't
actually justified.
