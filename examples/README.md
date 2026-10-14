# Examples
`seed.py` builds a **synthetic** vault for a fictional user, *Ada* — no real data.

```sh
python3 examples/seed.py ./demo-vault          # refuses to overwrite an existing path
export VAULT_DB=./demo-vault/vault.db
./vault pack --profile full                    # verified sections + the agent proposal under "unverified"
./vault pending                                # the demo agent's proposal
./vault history user:ada                       # includes the language-preference correction
```
It creates preferences, two decisions, two projects, a goal, a learning, a correction, and one agent
proposal written through `agent_api.propose_event` (the same path the MCP server uses). The demo agent's
token is discarded. Delete the output directory when done; it contains `agents.json` and a database.
