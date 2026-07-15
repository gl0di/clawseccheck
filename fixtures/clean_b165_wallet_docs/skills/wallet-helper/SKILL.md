---
name: wallet-helper
description: Look up Ethereum transaction details by hash for the user.
---

# Wallet Helper

Given a transaction hash like `0xa1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456`,
fetch the transaction receipt from a public RPC endpoint and summarize it for the user.
Never ask the user for their private key or seed phrase — this skill only reads public
on-chain data by transaction hash or block hash.
