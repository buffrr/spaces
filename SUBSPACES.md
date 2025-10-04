# Guide to Subspaces

## Operating a Space

### 1. Initialize the Space

Initialize your space for operation:

```bash
$ space-cli operate @bitcoin
```

### 2. Issue Subspaces

Use [subs](https://github.com/spacesprotocol/subs) to issue subspaces off-chain and create commitments.

### 3. Submit Commitments

Submit a commitment for your space with a Merkle root. Each commitment is cryptographically bound to all previous commitments.

**Example:** To submit a commitment for `@bitcoin` with root hash `85d3a410db41b317b7c0310df64cefb6504482c0b5c7e8a36c992ed0dfdb38af`:

```bash
$ space-cli commit @bitcoin 85d3a410db41b317b7c0310df64cefb6504482c0b5c7e8a36c992ed0dfdb38af
```

**Retrieve commitments** for a space:

```bash
$ space-cli getcommitment @bitcoin
```

### Delegating Operational Control

You can authorize another party to make commitments on your behalf:

```bash
$ space-cli delegate @bitcoin --to <operator-address>
```

## Binding Handles On-Chain

Handles like `alice@bitcoin` are bound to unique script pubkeys off-chain and are designed to remain off-chain by default. However, when on-chain interactivity is required, handles can be bound to UTXOs with minimal on-chain footprint.

### Creating a Space Pointer

Given a handle with its associated script pubkey:

```json
{
  "handle": "alice@bitcoin",
  "script_pubkey": "5120d3c3196cb3ed7fa79c882ed62f8e5942e546130d5ae5983da67dbb6c9bdd2e79"
}
```

You can create an on-chain identifier that only the controller of the script pubkey can use, without requiring additional metadata on-chain:

```bash
$ space-cli createptr 5120d3c3196cb3ed7fa79c882ed62f8e5942e546130d5ae5983da67dbb6c9bdd2e79
```

This command creates a UTXO with the same script pubkey and "mints" a space pointer (sptr) derived from it:

```
sptr13thcluavwywaktvv466wr6hykf7x5avg49hgdh7w8hh8chsqvwcskmtxpd
```

The space pointer serves as a permanent, transferable on-chain reference for the handle that can be sold and transferred like any other space UTXO.