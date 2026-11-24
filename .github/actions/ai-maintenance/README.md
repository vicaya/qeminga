# AI maintenance

A nightly GitHub Actions workflow that hands a coding agent your maintenance
instructions, opens a pull request with the result, and follows up on the
review until it goes quiet. The agent and its API key come from an ordered
**key pool** covering several providers, so an exhausted key or provider
falls through to the next one.

| Provider name in the pool | Harness | Key |
|---|---|---|
| `claude` (alias `anthropic`) | [Claude Code](https://www.npmjs.com/package/@anthropic-ai/claude-code) `claude -p` | Anthropic API key |
| `gpt` (aliases `openai`, `codex`) | [OpenAI Codex CLI](https://www.npmjs.com/package/@openai/codex) `codex exec` | OpenAI API key |
| `gemini` (aliases `google`, `antigravity`, `agy`) | [Antigravity CLI](https://antigravity.google/docs/cli/reference/) `agy -p` | Gemini API key |
| anything else, e.g. `provider2` | `providers/provider2.sh`, which you write ([below](#adding-a-provider)) | its own |

## How it works

```
nightly (schedule)                      review round (workflow_dispatch, mode=review)
┌─────────────┐   ┌──────────┐           ┌─────────┐   ┌─────────────┐   ┌──────────┐
│ agent run   │──▶│ publish  │──▶ PR ──▶ │ watch   │──▶│ agent run   │──▶│ publish  │──▶ next watch …
│ keys, r/o   │   │ write,   │  dispatch │ polls   │   │ + feedback  │   │ push +   │   dispatch
│ token       │   │ no keys  │           │ the PR  │   │             │   │ reply    │
└─────────────┘   └──────────┘           └─────────┘   └─────────────┘   └──────────┘
                                          │ no feedback for 90 min, PR closed, or 5 rounds
                                          ▼
                                          done; the nightly schedule carries on
```

1. **Agent run** (`action.yml`, job `maintain`). Builds the prompt from
   [`preamble.md`](preamble.md) and the instructions, then tries the pool's
   keys in routing order. Each attempt installs the provider's CLI if needed
   and runs it on the checkout with that single key. If the attempt fails
   with an exhaustion error (quota, rate limit, billing, overload, or an
   invalid or revoked key), the working tree is reset and the next key is
   tried. Any other failure ends the run, unless `fallback-on` is `any`. The
   agent's changes, both its own commits and anything left uncommitted,
   leave the job as one patch artifact along with its final message.
2. **Publish** (`publish/`, job `publish`). Applies the patch, commits it,
   pushes a new `ai-maintenance/<date>-<run>` branch and opens a pull
   request whose description is the agent's final message.
3. **Watch** (`watch/`, job `watch`). The workflow re-dispatches itself in
   `review` mode and polls the pull request every 5 minutes for reviews,
   inline comments and conversation comments. Only comments from owners,
   members and collaborators count, plus any bots you list. When feedback
   arrives, the watch waits until 5 minutes pass with nothing newer, so a
   whole review is handled at once. The agent then addresses it, the fix is
   pushed to the PR branch, and the agent's message is posted as a reply.
   Each push starts a new watch, so the quiet period restarts.
4. **Back to nightly.** The loop ends after `AI_MAINTENANCE_QUIET_MINUTES`
   (default 90) without feedback, when the pull request is closed or merged,
   or after `AI_MAINTENANCE_MAX_REVIEW_ROUNDS` (default 5) rounds. By
   default the nightly run skips while a maintenance pull request is open
   (`AI_MAINTENANCE_MAX_OPEN_PRS`, default 1), so pull requests don't pile
   up.

Polling, rather than reacting to comment events, also sees comments that
other workflows post with their `GITHUB_TOKEN`, which trigger no workflow
(review bots, for example).

### Isolation

An agent with shell access runs as the job's own user, and on hosted
runners that user has `sudo`. It can therefore read every token the job
holds, whatever the scripts unset. The design keeps write access out of
that job:

- The **agent job** gets the API keys and a **read-only** `GITHUB_TOKEN`.
  The checkout keeps no credentials (`persist-credentials: false`, and
  `run.sh` strips any that remain). The agent's work leaves the job only as
  a patch, and it can't push, comment or merge. Its build cache is restored
  but never saved, so it can't poison other workflows' caches.
- The **publish job** has write access but no API keys, and runs no agent.
  It only applies the patch. It runs the action scripts from the workflow's
  own commit (`github.sha`), never the PR branch's, so an agent that edited
  those scripts gains nothing.
- Each attempt gets only its own key. The pool and the instructions are
  removed from the environment the agent inherits, and every key is masked
  in the job log. Keys are also scrubbed from uploaded logs and from the
  PR text. If the agent's changes contain a pool key, nothing is published.
- Review feedback is passed on only from trusted authors. Anyone else's
  comments (possible prompt injection in a public repository) are ignored.

The agent can still read the API keys and the read-only token, and can make
network requests. Use keys with spending limits, and keep other secrets out
of the agent job.

## Setup

1. Copy `.github/actions/ai-maintenance/` and
   `.github/workflows/ai-maintenance.yml` into the repository.
2. In `ai-maintenance.yml`, adapt the **Repository setup** steps of the
   `maintain` job to install what the agent needs to build and test (this
   repository installs its pinned Rust toolchain).
3. Add the secrets (Settings → Secrets and variables → Actions):

   | Secret | Required | Content |
   |---|---|---|
   | `AI_MAINTENANCE_PROMPT` | yes | The maintenance instructions, in Markdown. |
   | `AI_KEY_POOL` | yes | The key pool, as JSON (see [below](#key-pool)). |
   | `AI_MAINTENANCE_TOKEN` | recommended | A GitHub App token or fine-grained PAT with *Contents* and *Pull requests* read/write on this repository. Branches pushed and pull requests opened with the default `GITHUB_TOKEN` start no workflows, so **CI would not run on the maintenance pull request** without it. |

4. Allow the workflow to open pull requests: Settings → Actions → General →
   Workflow permissions → **Allow GitHub Actions to create and approve pull
   requests** (needed when `AI_MAINTENANCE_TOKEN` is unset).
5. Run it once by hand: Actions → *AI maintenance* → *Run workflow*. Turn on
   *dry-run* to run the agent without publishing anything.

### Key pool

```json
[
  {"claude": ["sk-ant-…1", "sk-ant-…2"]},
  {"gpt": ["sk-proj-…"]},
  {"gemini": ["AIza…"]},
  {"provider2": {"keys": ["…"], "model": "big-model", "effort": "high", "base_url": "https://gateway.example"}}
]
```

- Order is priority. With the default `ordered` routing, the run tries
  `claude` key 1, then `claude` key 2, then `gpt`, then `gemini`.
- An entry's value is a key, a list of keys, or an object with `keys` and
  options. `model` and `effort` set the model and reasoning effort for that
  entry (see [Model and effort](#model-and-effort)). `base_url` points the
  CLI at a gateway or compatible endpoint (`ANTHROPIC_BASE_URL`,
  `OPENAI_BASE_URL` or `GOOGLE_GEMINI_BASE_URL`). Adapters receive any
  other option too.
- A provider may appear more than once, e.g. primary Claude keys, then GPT,
  then backup Claude keys.
- A provider without an adapter is skipped with a note in the run summary,
  so the pool can name providers before their adapters exist.
- A plain object (`{"claude": [...], "gpt": [...]}`) also works and keeps
  its written order.

### Routing strategies

| `AI_MAINTENANCE_ROUTING` | Behaviour |
|---|---|
| `ordered` (default) | Pool order. Fall back to the next key of the same entry, then to the next entry. |
| `round-robin` | Same provider priority, but each entry's keys are rotated by the run number. This spreads nightly load across one provider's keys. |

A strategy is a branch of `ai_route` in [`lib.sh`](lib.sh). It maps the pool
to an ordered list of candidates, so weighted, cost-based or health-based
strategies fit there without touching the rest.

### Model and effort

Each attempt resolves its model and its reasoning effort separately, and the
first setting found wins:

1. the pool entry's `"model"` / `"effort"` (in the `AI_KEY_POOL` secret);
2. the agent step's `models:` / `effort:` inputs in the workflow, which
   come from a one-off *Run workflow* input, else the repository variables
   `AI_MAINTENANCE_MODELS` / `AI_MAINTENANCE_EFFORT`;
3. otherwise, the CLI's own default.

```yaml
# .github/workflows/ai-maintenance.yml, job maintain, step "agent"
- id: agent
  uses: ./_ai-maintenance/.github/actions/ai-maintenance
  with:
    # …
    models: ${{ inputs.models || vars.AI_MAINTENANCE_MODELS }}
    effort: ${{ inputs.effort || vars.AI_MAINTENANCE_EFFORT }}
```

`models` is a JSON object of provider → model, since model names differ by
provider. `effort` is one level for every provider (`low`, `medium`,
`high`, `xhigh`, `max`), or a JSON object of provider → level. Literal
values work as well:

```yaml
    models: '{"claude": "claude-opus-5-5"}'
    effort: '{"claude": "max", "gpt": "high", "gemini": "high"}'
```

Manual-run overrides are carried into the review rounds that run starts.
The attempts table in the run summary shows the model and effort each
attempt asked for.

| Provider | Model | Effort |
|---|---|---|
| `claude` | `--model` | `--effort` (low, medium, high, xhigh, max) |
| `gpt` | `-m` | `-c model_reasoning_effort=…`; `max` becomes `xhigh`, the highest Codex accepts |
| `gemini` | `--model` (`agy models` lists the slugs) | `--effort`. Levels depend on the model (`gemini-3.1-pro` offers only low and high). `agy` rejects any other level before making a request, and the adapter then retries once with the nearest level the model offers. |

For `claude` and `gpt`, a level the chosen model doesn't support fails the
attempt with an ordinary error, which doesn't fall back (unless
`fallback-on` is `any`). Pick levels the configured model supports.

### Variables

All optional (Settings → Secrets and variables → Actions → Variables):

| Variable | Default | Meaning |
|---|---|---|
| `AI_MAINTENANCE_ROUTING` | `ordered` | Routing strategy. |
| `AI_MAINTENANCE_FALLBACK_ON` | `exhausted` | `exhausted` falls back only on exhaustion errors. `any` also falls back after other failures, including timeouts. |
| `AI_MAINTENANCE_MODELS` | | JSON, e.g. `{"claude":"claude-opus-5-5"}`. Model names are whatever each CLI accepts (`agy models` lists Antigravity's). A pool entry's `model` wins. Empty means each CLI's default. |
| `AI_MAINTENANCE_EFFORT` | | `low`, `medium`, `high`, `xhigh` or `max` for every provider, or JSON per provider, e.g. `{"claude":"max","gpt":"high"}`. A pool entry's `effort` wins. Empty means each CLI's default. |
| `AI_MAINTENANCE_ATTEMPT_TIMEOUT` | `60m` | Time limit per attempt (`timeout(1)` duration). |
| `AI_MAINTENANCE_QUIET_MINUTES` | `90` | The review loop ends after this long without feedback. |
| `AI_MAINTENANCE_MAX_REVIEW_ROUNDS` | `5` | Most review rounds per pull request. |
| `AI_MAINTENANCE_TRUSTED_BOTS` | | Comma-separated bot logins whose reviews count, e.g. `copilot-pull-request-reviewer[bot]`. |
| `AI_MAINTENANCE_MAX_OPEN_PRS` | `1` | The nightly run skips while this many maintenance pull requests are open. `0` never skips. |
| `AI_MAINTENANCE_BRANCH_PREFIX` | `ai-maintenance/` | Branch prefix of maintenance pull requests. |
| `AI_MAINTENANCE_DRAFT` | `false` | Open pull requests as drafts. |
| `AI_MAINTENANCE_LABELS` | | Comma-separated labels for new pull requests. Labels that don't exist are skipped. |

CLI versions are pinned in `action.yml` (`claude-code-version`,
`codex-version`). The Antigravity CLI installs the build that Google's
installer manifest currently names, after checking its SHA-512. That CLI
also updates itself. To pin a build, set `AGY_DOWNLOAD_URL` and `AGY_SHA512`
in the job's environment.

## Adding a provider

Copy [`providers/TEMPLATE.sh.example`](providers/TEMPLATE.sh.example) to
`providers/<name>.sh` and implement two functions:

- `provider_install` installs the CLI. It must be idempotent and pin a
  version.
- `provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON EFFORT` runs the
  agent headless in the checkout, writes its final message to
  `FINAL_FILE`, and returns 0 only on success.

Optionally, set `PROVIDER_EXHAUSTED_REGEX` to extra error patterns that mean
"try the next key". If the CLI is a variant of one already listed, an alias
in `ai_canonical_provider` (`lib.sh`) is enough.

## Files

| File | Role |
|---|---|
| `action.yml`, `run.sh` | Agent run: pool, routing, attempts, fallback, the patch artifact. |
| `lib.sh` | Pool parsing, routing strategies, aliases, failure classification, scrubbing. |
| `providers/*.sh` | One adapter per provider. |
| `preamble.md` | The fixed part of the prompt (unattended-run rules, PR description format). |
| `watch/action.yml`, `watch.sh` | Polls a pull request for trusted review feedback. |
| `publish/action.yml`, `publish.sh` | Applies the patch; opens the pull request or pushes and replies. |
| `test/selftest.sh` | Offline self-test with fake adapters, a fake `gh` and a local remote. |

Run the self-test after changing anything here (it needs bash, git and jq):

```bash
.github/actions/ai-maintenance/test/selftest.sh
```

## Limits

- The agent job can read its API keys and its read-only token (see
  [Isolation](#isolation)).
- A review round fails if someone pushes to the PR branch while the agent
  is working, because the patch would no longer apply cleanly. The next
  round (or a human) picks it up.
- Changes under `.github/workflows/` can only be pushed with a token that
  has the `workflows` permission. With the default `GITHUB_TOKEN`, such a
  push is rejected.
- A watch occupies a runner for up to the quiet period (90 minutes) per
  round.
