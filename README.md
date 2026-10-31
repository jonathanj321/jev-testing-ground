# AI Agent Guardrail Research

Tools for evaluating AI agent security decisions and robustness to prompt injection.

## Setup: Jev evaluation harness

Requires Python 3.11+. From the repository root:

```sh
cd jev-harness
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Open `jev-harness/.env` (or `.env` if you are already inside that folder). Insert your OpenRouter API key and set:

```env
TYPESAFE_API_KEY=your_openrouter_api_key
TYPESAFE_BASE_URL=https://openrouter.ai/api
TYPESAFE_MODEL=~typesafe/jev-latest
```

Keep your key in `.env`, which is ignored by Git. The `TYPESAFE_API_KEY` variable holds your OpenRouter key because the harness uses the TypeSafe SDK. Existing environment variables take precedence over `.env`.

From `jev-harness/`, run:

```sh
python main.py
```

Results are saved in `jev-harness/outputs/`. To run the offline unit tests:

```sh
python -m pytest unit_tests -q
```

See the [harness README](jev-harness/README.md) for test case formats, image experiments, and output details. The harness evaluates proposed actions without executing them.

## Project folders

| Folder | Purpose | Status |
| --- | --- | --- |
| `jev-harness/` | Evaluate Jev on clean and prompt-injected text and image inputs. | Implemented |
| `mcp-testing/` | Future experiments involving Model Context Protocol (MCP) tools and agent guardrails. | Planned; folder and setup are not implemented yet |

MCP testing will have its own folder, dependencies, and setup instructions when added.
