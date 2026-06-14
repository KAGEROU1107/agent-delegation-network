# ADN Phase Tracker

| Phase | Feature | Status | TEE Functions | Map |
|---|---|---|---|---|
| 0 | Agent Auth SDK — User Delegation | ✅ LIVE (T3N testnet) | (SDK-native DelegationCredential) | — |
| 1 | Core ADN + T3N Auth + TEE Contract | ✅ LIVE (T3N testnet, proof committed) | process-data, validate-quality, delegate-task | — |
| 2 | Blind Multi-Agent Auction | ✅ Contract live — TEE-invoked via bridge | submit-bid, resolve-auction | auction-bids |
| 3 | Agent Reputation Ledger | ✅ Contract live — TEE-invoked via bridge | record-completion, get-reputation | reputation-ledger |
| 4 | Privacy-Preserving Personalization | ✅ Contract live — TEE-invoked via bridge | send-personalized-outreach | — |
| 5 | Temporal Agent Delegation | ✅ Contract live — TEE-invoked via bridge | issue-time-grant, check-grant | time-grants |
| 6 | Cross-Tenant Verified Computation | ✅ Contract live — TEE-invoked via bridge | (uses existing process-data) | — |
| 7 | Agentic KYC Pipeline | ✅ Contract live — TEE-invoked via bridge | kyc-submit-step, kyc-get-status | kyc-pipeline |
| 8 | TEE Secret Vault | ✅ Contract live — TEE-invoked via bridge | store-secret, invoke-with-secret | agent-vault |
| 9 | Autonomous Agent DAO | ✅ Contract live — TEE-invoked via bridge | cast-vote, tally-votes | dao-votes |
| 10 | Verifiable AI Decision Audit | ✅ Contract live — TEE-invoked via bridge | log-decision, audit-decisions | decision-audit |
| 11 | Agent Performance Bond | ✅ Contract live — TEE-invoked via bridge | lock-bond, verify-and-settle | perf-bonds |

## TRIAD Gate Criteria
- **T**ruth: Live T3N testnet execution confirmed
- **R**igor: Rust clean, TypeScript clean, no secrets in code
- **I**mpact: Demonstrates unique T3N capability a judge remembers

## Build Order
2 → 3 → 8 → 5 → 9 → 10 → 7 → 11 → 4 → 6

## LLM Cognitive Layer

Feature agents use `llm/client.py` — a generic OpenAI-compatible client configurable via:
- `LLM_API_KEY` — API key (leave unset to use stub mode)
- `LLM_BASE_URL` — endpoint URL (default: `https://api.openai.com/v1/chat/completions`)
- `LLM_MODEL` — model name (default: `gpt-4o-mini`)
- `LLM_PROVIDER` — informational label

See `.env.example` for the full template. The demo runs fully without an LLM key.
