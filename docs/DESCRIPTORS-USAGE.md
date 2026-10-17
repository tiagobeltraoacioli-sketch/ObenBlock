# Public descriptors and pool files

ObenBlock static descriptors record existing public-key or policy output identities.
They contain no private keys and do not derive new keys. Restoring a pool
restores the listed public identities only, not spending keys, transaction
history, balances, or a persistent node wallet index. Keep the encrypted
wallet/key backup separately. A checksum detects typing errors; it does not
authenticate the source of a public key.

The [format specification](DESCRIPTORS.md) describes the exact grammar and
checksum. Creation accepts a checksum-free body; inspection/import require
the checksum. Files contain the exact text, without a trailing newline or
whitespace. Every offline command requires `--mainnet` or `--testnet`, which
must agree with the body/pool. The commands do not connect to a node.

```
gnb-cli descriptor create body.txt --mainnet
gnb-cli descriptor inspect descriptor.txt --mainnet
gnb-cli descriptor pool public-keys.json new-public-pool.json --mainnet
gnb-cli descriptor export descriptors.json new-public-pool.json --mainnet
gnb-cli descriptor import public-pool.json --mainnet
```

`body.txt` can contain `gnbd1(mainnet,pkh(KEY))`, replacing `KEY` with the
complete lowercase public-key hex from an existing wallet. Use `policy` or
`tree` only with the exact grammar in the specification. `public-keys.json`
is a JSON array of already-derived lowercase public-key hex strings.
`descriptors.json` is an array of checksummed descriptor strings. The pool
and export commands create a **new** file and refuse existing files or
symlinks. They also print a JSON response with the canonical bundle, count,
and resolved entries. Import validates a pool and prints the same information;
it does not write a wallet or register addresses with the node.

Descriptor text is limited to 262,144 bytes; pool/list input files to 1,048,576
bytes. There are at most 64 distinct scripts per pool. The shared codec rejects
wrong networks, invalid checksums, unknown or duplicate pool JSON fields,
duplicate scripts and malformed entries. Raw and enveloped public keys retain
their original byte identities; do not replace one representation with another.

Node RPC methods accept an array containing exactly one checksummed descriptor:

```
{"method":"getdescriptorinfo","params":["CHECKSUMMED_DESCRIPTOR"],"id":1}
{"method":"deriveaddresses","params":["CHECKSUMMED_DESCRIPTOR"],"id":2}
```

Both methods use the node's configured network and reject a descriptor for the
other network. `getdescriptorinfo` returns the descriptor, network, kind,
script hex, existing legacy address, optional-format Bech32m address, and
`requires_policy_tree_activation`. `deriveaddresses` returns a one-element
array containing the legacy address. These methods do not import state, scan
the chain or inspect balances. A tree address does not prove spending support
is active on the caller's chain; the activation flag must be considered by the
producer of a later spend.

The browser core exposes the same public operations:

```javascript
const pool = core.descriptor({
  action: "pool", network: "mainnet", public_keys: [publicKeyHex]
});
const restored = core.descriptor({
  action: "import", network: "mainnet", bundle: pool.bundle
});
```

`descriptor()` needs no unlocked signing session and leaves an existing session
unchanged. It always forces the public `descriptor` operation, regardless of
a caller-supplied `op`. There is no new wallet UI or automated chain rescan in
this package. Wildcards, xpubs, derivation paths, private descriptors and secret
backup recovery are not supported.
