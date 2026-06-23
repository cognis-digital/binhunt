# binhunt — Advanced usage

## CI gate (fail the build on findings)
Global flags (`--format`, `--fail-on`) come **before** the subcommand. binhunt
writes to stdout — redirect to a file:
```yaml
- run: pip install cognis-binhunt
- run: binhunt --format sarif --fail-on high scan ./client.exe > binhunt.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: binhunt.sarif }
```

## Pipe into a SIEM / webhook
```bash
binhunt --format json scan ./client.exe | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "binhunt": { "command": "binhunt", "args": ["mcp"] } } }
```

## Run a language port instead of Python
Each port mirrors `binhunt scan <file>` and emits the same JSON shape + exit codes:
```bash
node ports/javascript/index.js ./client.exe       # Node
( cd ports/go   && go run . ../../client.exe )     # Go single binary
( cd ports/rust && cargo run -- ../../client.exe ) # Rust
```
