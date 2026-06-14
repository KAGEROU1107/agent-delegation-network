# BUG-007 Evidence — Testnet credits exhausted (`available=0`)

## Credit status

After 6 full live demo sessions, testnet credit balance reached `available=0`.

```
credits.available: 0
```

Confirmed 2026-06-11 after session 6 run. All subsequent `executeAndDecode` calls
were blocked. No warning was issued by the testnet before exhaustion.

## Impact

Session 7 (final submission proof) could not be generated. Credit refill request
submitted to T3N team via DoraHacks message.

## Related

- `docs/bugs/BUG-007-testnet-credits-exhausted.md`
- `docs/doc-gaps/DOCGAP-004-sandbox-token-claim-and-credit-limits.md`
