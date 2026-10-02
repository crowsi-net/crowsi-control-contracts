# Using crowsi-control-contracts

Exchange control requests, decisions and execution evidence through a shared, strict contract.

## Before you start

These are contracts; authorization decisions and execution are supplied by their respective implementations.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Use consistent typed control envelopes.
- Reject unsupported request shapes before policy evaluation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
