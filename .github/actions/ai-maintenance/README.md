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

1. **Agent run** (`action.yml`, job `maintain`). Builds the agent's
   container image (your repository setup on top of `container-image`) and
   the prompt from [`preamble.md`](preamble.md) and the instructions, then
   tries the pool's keys in routing order. Each attempt installs the
   provider's CLI if needed (in a container without keys) and runs it in a
   fresh container,
   on a fresh copy of the checkout, with that single key. If the attempt
   fails with an exhaustion error (quota, rate limit, billing, overload, or
   an invalid or revoked key), the next key is tried. Any other failure ends
   the run, unless `fallback-on` is `any`. The agent's changes, both its own
   commits and anything left uncommitted, leave the job as one patch
   artifact along with its final message, once the patch has been checked
   for pool keys.
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
   Each push starts a new watch, so the quiet period restarts. Feedback is
   handed over in whole items up to 60,000 bytes per round; whatever does
   not fit is picked up by the next round, which starts after the last item
   handed over. A single item larger than that goes over in pieces, each
   round continuing where the last stopped.
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

The job that holds the API keys runs no agent code on the runner, and
nothing it downloads. Each attempt runs in its own container:

- **Only its own key.** The pool stays with `run.sh` on the runner. The
  container receives one key, through the environment, and nothing else:
  no other key, no token, none of the runner's files or processes, and so
  none of the credentials the runner holds for the job (the cache
  service's included). A failure or a hostile change in one attempt can't
  reach the keys of another.
- **A fresh start.** Every attempt gets a new container from the image built
  for the run and a new copy of the checkout. The CLIs and the action itself
  are mounted read-only, so nothing one attempt changes survives into the
  next.
- **Installs see nothing.** Each provider's CLI is installed (npm lifecycle
  scripts and downloads included) in a container of its own that sees only
  the tools directory: no key, no prompt, no other file of the run. Only
  the version pins the adapter names reach it.
- **No privileges.** The agent runs as an unprivileged user (never root,
  even on a root runner), without capabilities and with `no-new-privileges`.
  It can't install packages, so the image's setup installs everything the
  repository needs.
- **Nothing read on the runner's side.** The agent's tree, git
  configuration included, is only read inside a container: a second
  container without a key or network exports the patch. The runner reads
  only the plain files it expects the attempt to leave, never through a
  symlink, and uploads them under names it chooses. It then checks the
  patch by applying it to its own copy of the checkout and scanning the
  patch and every added or modified file's bytes for pool keys. A binary
  file can't smuggle a key past that scan, and a scan that fails refuses
  as well. A patch that touches `.github/workflows/` is refused (see
  [Limits](#limits)).
- **No workflow commands.** Everything a container prints is captured in
  files on the runner. When it is shown in the job log, the runner's
  workflow commands (`::add-mask::`, `::set-env::`, ...) are suspended
  with a one-time token that no container sees, so the agent can't issue
  any.
- **No cache.** The agent job restores and saves no cache, so nothing it
  builds can be restored by trusted CI.

Around the agent job:

- The **publish job** has write access but no API keys, and runs no agent.
  It only applies the patch. It runs the action scripts from the workflow's
  own commit (`github.sha`), never the PR branch's, so an agent that edited
  those scripts gains nothing. Before a review round's push it checks that
  the pull request is still open, still a maintenance pull request, and
  still at the commit the agent worked on; the push itself only succeeds
  while the branch is at that commit, so a closed pull request or a deleted
  branch is never updated or recreated.
- Every key and the instructions are masked in the job log, and withheld
  wherever the agent quotes them verbatim in the PR text or the uploaded
  logs. A paraphrase can't be detected: if the instructions themselves
  must stay unpublished, set `AI_MAINTENANCE_PRIVATE_INSTRUCTIONS` to
  `true`. The PR description and replies are then a fixed text, the
  agent's output stays off the job log, and no transcripts are uploaded.
- Review feedback is passed on only from trusted authors. Anyone else's
  comments (possible prompt injection in a public repository) are ignored.

The agent can still use its own key and make network requests. Use keys
with spending limits.

## Setup

1. Copy `.github/actions/ai-maintenance/` and
   `.github/workflows/ai-maintenance.yml` into the repository.
2. In `ai-maintenance.yml`, adapt the **Repository setup** of the agent
   step (`container-image`, `container-setup`) to install what the agent
   needs to build and test. The setup script runs as root while the image
   is built, in a throwaway copy of the checkout, and can leave variables
   for the agent in `/etc/ai-maintenance/env` (this repository installs its
   pinned Rust toolchain that way). The runner needs Docker, which
   GitHub-hosted Linux runners have. Keep `container-image` on the runner's
   C library (the default `ubuntu:24.04` matches `ubuntu-24.04` runners):
   the runner's Node.js and the provider CLIs are mounted into it. The
   checkout must be a plain clone (`actions/checkout` makes one), not a
   linked worktree.
3. Add the secrets (Settings → Secrets and variables → Actions):

   | Secret | Required | Content |
   |---|---|---|
   | `AI_MAINTENANCE_PROMPT` | yes | The maintenance instructions, in Markdown. |
   | `AI_KEY_POOL` | yes | The key pool, as JSON (see [below](#key-pool)). |
   | `AI_MAINTENANCE_TOKEN` | recommended | A GitHub App token or fine-grained PAT with *Contents* and *Pull requests* read/write on this repository, and nothing else: **not** *Workflows* (see [Limits](#limits)). Branches pushed and pull requests opened with the default `GITHUB_TOKEN` start no workflows, so **CI would not run on the maintenance pull request** without it. |

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
  {"provider2": {"keys": ["…"], "model": "big-model high", "base_url": "https://gateway.example"}}
]
```

- Order is priority. With the default `ordered` routing, the run tries
  `claude` key 1, then `claude` key 2, then `gpt`, then `gemini`.
- An entry's value is a key, a list of keys, or an object with `keys` and
  options. `model` sets that entry's model and, optionally, its reasoning
  effort (`"claude-opus-5-5 high"`; see [Model and effort](#model-and-effort)).
  `base_url` points the
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

A model setting is the model, optionally followed by a space and a
reasoning-effort level:

| Setting | Model | Effort |
|---|---|---|
| `"claude-opus-5-5 high"` | `claude-opus-5-5` | `high` |
| `"claude-opus-5-5"` | `claude-opus-5-5` | the CLI's default |
| `"high"` | the CLI's default | `high` |

The levels are `low`, `medium`, `high`, `xhigh` and `max`. Any other second
word, or more than two words, is a configuration error, reported before any
attempt runs.

Each attempt takes its setting from the first of:

1. the pool entry's `"model"` (in the `AI_KEY_POOL` secret);
2. the agent step's `models:` input in the workflow, which comes from a
   one-off *Run workflow* input, else the repository variable
   `AI_MAINTENANCE_MODELS`;
3. otherwise, the CLI's defaults.

```yaml
# .github/workflows/ai-maintenance.yml, job maintain, step "agent"
- id: agent
  uses: ./_ai-maintenance/.github/actions/ai-maintenance
  with:
    # …
    models: ${{ inputs.models || vars.AI_MAINTENANCE_MODELS }}
```

`models` is a JSON object of provider → setting, because model names differ
by provider. A literal value works as well:

```yaml
    models: '{"claude": "claude-opus-5-5 max", "gpt": "high", "gemini": "gemini-3.1-pro high"}'
```

A manual-run override is carried into the review rounds that run starts.
Provider names in `models` resolve through the same aliases as the pool
(`"openai"` is `gpt`); naming one provider twice is an error. Every
setting, in the map and in every pool entry, must be a string and is
checked before the first attempt.

The attempts table in the run summary shows the effort each attempt asked
for and, when its adapter changed it, the one it ran with
(`max (used high)`). The result, the PR footer and the commit message report
the effort the CLI ran with.

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
| `AI_MAINTENANCE_PRIVATE_INSTRUCTIONS` | `false` | `true` publishes none of the agent's own text: the PR description and replies are a fixed text, the agent's output stays off the job log and no transcripts are uploaded ([Isolation](#isolation)). |
| `AI_MAINTENANCE_MODELS` | | JSON of provider → `"<model> [effort]"`, e.g. `{"claude":"claude-opus-5-5 high","gemini":"high"}` ([Model and effort](#model-and-effort)). A pool entry's `model` wins. Empty means each CLI's defaults. |
| `AI_MAINTENANCE_ATTEMPT_TIMEOUT` | `60m` | Time limit per attempt (`timeout(1)` duration). |
| `AI_MAINTENANCE_QUIET_MINUTES` | `90` | The review loop ends after this long without feedback. |
| `AI_MAINTENANCE_MAX_REVIEW_ROUNDS` | `5` | Most review rounds per pull request. |
| `AI_MAINTENANCE_TRUSTED_BOTS` | | Comma-separated bot logins whose reviews count, e.g. `copilot-pull-request-reviewer[bot]`. |
| `AI_MAINTENANCE_MAX_OPEN_PRS` | `1` | The nightly run skips while this many maintenance pull requests (from this repository, on the branch prefix: the same rule the watch uses) are open. `0` never skips. |
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

- `provider_install` installs the CLI into `$AI_TOOLS_DIR`. It must be
  idempotent and pin a version.
- `provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON EFFORT` runs the
  agent headless in the checkout, writes its final message to
  `FINAL_FILE`, and returns 0 only on success.

Both run in containers of the sandbox image, as an unprivileged user.
`provider_install` runs in one with network access and the runner's
`node` and `npm`, but no key and no file of the run: only `$AI_TOOLS_DIR`
is mounted, writable, and attempts later see it read-only. Of the runner's
environment it gets only the variables listed in `PROVIDER_INSTALL_ENV`
(version pins). `provider_run` runs inside the attempt's container, where
`$AI_ATTEMPT_DIR` is the writable output directory and `node` is on
`PATH`. If the CLI runs with a different effort than the one requested,
call `ai_report_effort LEVEL` so the result reports it.

Optional settings in the adapter:

- `PROVIDER_EXHAUSTED_REGEX`: extra error patterns that mean "try the next
  key".
- `PROVIDER_INSTALL_ENV`: the runner variables `provider_install` reads.
- `PROVIDER_TRANSCRIPT`: the file in `$AI_ATTEMPT_DIR` holding the CLI's
  transcript, uploaded as `transcript.jsonl`. The uploaded logs hold only
  `attempt.log`, `install.log`, `final.md`, `error.txt` and that transcript.

If the CLI is a variant of one already listed, an alias in
`ai_canonical_provider` (`lib.sh`) is enough.

## Files

| File | Role |
|---|---|
| `action.yml`, `run.sh` | Agent run: pool, routing, the sandbox image, attempts, fallback, the checked patch artifact. |
| `install.sh`, `attempt.sh`, `export.sh` | Run inside the containers: a CLI install, without a key or the run's files; one attempt with its key; the patch export, without a key. |
| `gate.sh` | Pauses nightly runs while maintenance pull requests are open. |
| `lib.sh` | Pool and model parsing, routing strategies, aliases, failure classification, scrubbing, the leak scan. |
| `providers/*.sh` | One adapter per provider. |
| `preamble.md` | The fixed part of the prompt (unattended-run rules, PR description format). |
| `watch/action.yml`, `watch.sh` | Polls a pull request for trusted review feedback. |
| `publish/action.yml`, `publish.sh` | Applies the patch; opens the pull request or pushes and replies. |
| `test/selftest.sh` | Offline self-test with fake adapters, fake `gh` and `docker` commands and a local remote; `--docker` runs attempts in real containers; `--image` builds the repository's sandbox image and runs repository checks in it. |

Run the self-test after changing anything here (it needs bash, git and jq):

```bash
.github/actions/ai-maintenance/test/selftest.sh
```

With a Docker daemon, also run the container check. From inside an attempt,
it looks for the other attempts' keys in every file and process it can see,
and for the runner's files:

```bash
.github/actions/ai-maintenance/test/selftest.sh --docker
```

To check the repository setup, build the sandbox image from the workflow's
`container-setup` and run repository checks in an attempt there (several
minutes):

```bash
.github/actions/ai-maintenance/test/selftest.sh --image
```

## Limits

- An attempt can use its own API key and the network (see
  [Isolation](#isolation)). The agent job's runner needs Docker.
- A review round fails if someone pushes to the PR branch while the agent
  is working, because the patch would no longer apply cleanly. The next
  round (or a human) picks it up.
- Changes under `.github/workflows/` are never published: workflow files
  run with the repository's secrets as soon as they are pushed, so they
  take a separate, human-reviewed path. The agent run refuses a patch that
  touches them, the publish job checks again, and the publishing token
  should not have the *Workflows* permission, so GitHub rejects such a
  push as well. If maintenance should change a workflow, the agent can
  describe the change in its final message for a human to make.
- A watch occupies a runner for up to the quiet period (90 minutes) per
  round.
