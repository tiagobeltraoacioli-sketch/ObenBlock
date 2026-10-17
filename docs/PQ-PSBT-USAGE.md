# PQ-PSBT usage

ObenBlock's PQ-PSBT is a custom format for one policy or one selected tree branch.
Coverage/review remains partial; see the [frontend brief](security/round-3/pqpsbt-frontends.md)
and [browser brief](security/round-3/pqpsbt-browser.md). These developer
interfaces add no PQ-PSBT wallet UI, QR exchange or HWI integration.

## Public roles

`gnb-cli pqpsbt request.json` runs offline, prints JSON and never loads a key.
The same request is the `params` object of authenticated RPC method `pqpsbt`,
or the argument to the browser binding `core.pqpsbt(request)`.

| `action` | Other request fields | Result |
|---|---|---|
| `create` | `spend_json` — legacy PolicySpend JSON **string** | `hex` |
| `encode` | `json` — PQ-PSBT JSON **string** | `hex` |
| `decode` | `hex` | `json` string |
| `update` | `hex`, integer `index`, `input_json` string | `hex` |
| `combine` | `hex`, `other_hex` | `hex` |
| `review` | `hex`, `network`, `next_height`, `max_fee` | `review` |
| `finalize`, `extract` | same context as `review` | transaction `hex`, `txid`, `review` |

`network` is `mainnet` or `testnet`; `next_height` and `max_fee` are canonical
unsigned decimal strings, with fees in base units. Binary hex is lowercase.
Keep document text in strings so duplicate fields reach the strict parser;
parsed document objects are rejected. `update` takes a decoded input record
serialized as a string, as the role test does with `inputs[0]`.

Decode, combine and review do not establish that all partial signatures are
valid or sufficient. `review` reports exact input/output totals, fee, change,
previous-transaction verification count and `current_unspentness:
"not_checked_offline"`. Finalization checks signatures and the completed
transaction; it refuses insufficient signatures. Neither role broadcasts.

## File flow

`SPEND_JSON` is an existing legacy PolicySpend file; `ALICE_WALLET` and
`BOB_WALLET` are keystores for two policy keys. `RPC_URL` is your local/HTTPS
node endpoint. `NETWORK` and `NEXT_HEIGHT` come from that node's
`getnetworkinfo` / `getdaginfo` and must match the document. The same schemas
and 2-of-3 flow are in [`pqpsbt_public_roles.rs`](../node/tests/pqpsbt_public_roles.rs);
its synthetic outpoints are not live UTXOs. `jq` below only wraps requests.

```sh
jq -n --rawfile spend "$SPEND_JSON" '{action:"create",spend_json:$spend}' > create-request.json
gnb-cli pqpsbt create-request.json > created.json
jq '{action:"decode",hex:.hex}' created.json > decode-request.json
gnb-cli pqpsbt decode-request.json > decoded.json
jq -r '.json' decoded.json > unsigned.json
cp unsigned.json alice.json
cp unsigned.json bob.json
gnb-cli --rpc-url "$RPC_URL" policysign alice.json "$ALICE_WALLET" --max-fee 0.02
gnb-cli --rpc-url "$RPC_URL" policysign bob.json "$BOB_WALLET" --max-fee 0.02
jq -n --rawfile doc alice.json '{action:"encode",json:$doc}' > encode-a.json
jq -n --rawfile doc bob.json '{action:"encode",json:$doc}' > encode-b.json
gnb-cli pqpsbt encode-a.json > a.json
gnb-cli pqpsbt encode-b.json > b.json
jq -n --slurpfile a a.json --slurpfile b b.json \
  '{action:"combine",hex:$a[0].hex,other_hex:$b[0].hex}' > combine-request.json
gnb-cli pqpsbt combine-request.json > combined.json
jq --arg network "$NETWORK" --arg height "$NEXT_HEIGHT" \
  '{action:"review",hex:.hex,network:$network,next_height:$height,max_fee:"2000000"}' \
  combined.json > review-request.json
gnb-cli pqpsbt review-request.json
jq '.action="finalize"' review-request.json > finalize-request.json
gnb-cli pqpsbt finalize-request.json > final.json
```

`policysign` checks the configured node's network, activation, height/tip,
selected UTXO values/scripts, mempool spends, maturity and locks before opening
the wallet. Version 1 additionally requires full previous transactions and
is refused at mainnet next height 17,500; imported versions are not rewritten.
The preview shows every input/output, exact totals, fee, ceiling and
same-policy change. Default ceiling: 0.02 GNB. CLI `--max-fee` uses GNB; role
requests use base units. `--yes` skips only confirmation. Signing rewrites the
file in its original format (legacy or PQ-PSBT JSON). A live keystore/TTY
password journey was not exercised by the frontend test package.

## RPC and WASM

To send the public review request above to a node with an API key configured:

```sh
jq '{jsonrpc:"2.0",id:1,method:"pqpsbt",params:.}' review-request.json > rpc-request.json
curl -sS "$RPC_URL" -H 'Content-Type: application/json' \
  -H "X-API-Key: $GNB_RPC_API_KEY" --data-binary @rpc-request.json
```

RPC requires the key even for trusted loopback/private peers. It provides no
signing/private-key operation. Successful data is under `result`; check both
the JSON-RPC `error` and `result.error` before using it.

With the integrated loader and matching WASM artifact, `core` is a loaded
instance holding the matching unlocked session key; `packetHex` comes from
`create`/`encode`:

```js
const decoded = core.pqpsbt({ action: "decode", hex: packetHex });
const partial = core.signPqPsbt(packetHex, network, nextHeight, maxFee);
```

Pass `nextHeight` and `maxFee` as exact decimal strings. The ABI requests are
`{op:"pqpsbt", ...publicRequest}` and
`{op:"pqpsbt_sign", hex, network, next_height, max_fee}`; ABI responses use
`ok` / `error`, which the loader unwraps. Signing returns a partial document
`hex`, `key_index` and `review`, using the session key locally. It makes no
node query and does not prove current unspentness, maturity or relative locks.
The bindings and isolated 2-of-3 exchange are covered by
[`wallet-pqpsbt.test.mjs`](../site/tests/wallet-pqpsbt.test.mjs) and the
[WASM host tests](../crates/gnb-wallet-wasm/src/lib.rs).

## Limits and incomplete observations

Offline core limits are 64 inputs, 64 outputs, 7 policy keys, 8 MiB binary and
17,039,360 bytes of document JSON. RPC is smaller: 1 MiB request body, 4 inputs,
16 present partial signatures and one operation in flight. The offline limits
do not mean all such documents fit the RPC transport.

Online preflight asks `getutxos` for at most 10,000 rows and metadata for at
most 64 selected outpoints. An input absent from that bounded window is
refused, even if the response is truncated. Tip/hash changes are refused;
observations do not reserve inputs against later spends or reorganizations.
Schemas were checked against the [shared dispatcher](../crates/gnb-crypto/src/wallet/pqpsbt.rs),
[CLI/preflight tests](../node/tests/support/pqpsbt_cli_unit.rs) and
[actual RPC router tests](../node/tests/support/pqpsbt_rpc_unit.rs).
This usage note adds no execution evidence or readiness claim.
