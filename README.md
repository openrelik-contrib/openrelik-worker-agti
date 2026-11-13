## Description

OpenRelik worker that integrates with **Agentic Google Threat Intelligence
(AGTI)** and the **VirusTotal Crowdsourced YARA Hub** to enrich indicators of
compromise (IoCs), triage forensic scan findings, investigate file hashes, and
dynamically import community YARA rules.

This worker provides two tasks:

1.  **Enrich Findings with Agentic GTI** (`openrelik-worker-agti.tasks.lookup`):
    Queries Agentic Google Threat Intelligence (AGTI) to enrich IoCs, triage
    YARA/Capa/FLOSS scan results, or investigate file hashes (SHA-256, SHA-1,
    MD5), producing human-readable Markdown (`.md`) and structured JSON
    (`.json`) threat intelligence reports.
2.  **Import YARA Rules from VirusTotal**
    (`openrelik-worker-agti.tasks.yara_importer`): Expands threat scenario
    prompts or keywords via AGTI, queries the VirusTotal Crowdsourced YARA Hub
    (`/api/v3/yara_rules`), and writes deduplicated `<rule_name>.yar` files to
    the shared OpenRelik YARA directory while passing input files through to
    downstream scanners.

## Deploy

Add the below configuration to the OpenRelik `docker-compose.yml` file.

```yaml
openrelik-worker-agti:
    container_name: openrelik-worker-agti
    image: ghcr.io/openrelik-contrib/openrelik-worker-agti:latest
    restart: always
    environment:
      - REDIS_URL=redis://openrelik-redis:6379
      - OPENRELIK_PYDEBUG=0
      - GTI_API_KEY=${GTI_API_KEY}
    volumes:
      - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-agti"
    # ports:
      # - 5678:5678 # For debugging purposes.
```

## Test

```shell
uv sync --group test
uv run pytest -s --cov=.
```
