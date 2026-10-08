# proof_seeder

Signs EIP-8025 execution proofs and submits them to a beacon node, so a proving service needs no validator key and speaks no SSZ.

```sh
cargo install --locked --git https://github.com/dapplion/proof_seeder
proof_seeder --beacon-node http://127.0.0.1:5052 \
  --keystore keystore.json --keystore-password-file password
```

Listens on `127.0.0.1:8026`; `--listen-address` moves it.

A prover posts the proof and the facts that say what it is of:

```
POST /proofs?beacon_root=0x…&proof_type=1
body: the raw proof
```

The signed envelope commits to the proof, its type and the block, nothing else. The node derives the public input the proof is checked against from its own copy of the payload, so there is no execution block hash to pass here and no way to disagree with the node about one.

`202` once the beacon node has it, `400` if the parameters are malformed, `404` if the beacon node does not have the block yet, `413` if the proof is over `MAX_PROOF_SIZE`, `502` with the node's reason if it refused. `--help` has the flags.

The prover supplies the chain facts, so this holds no cache and follows nothing — the only state is the key. Every proof carries this relay's validator index whoever proved it, and nothing here checks a proof, so running it for a proving service means vouching for that service.

It authenticates nobody, so do not expose the socket. The beacon node binds this validator to a block's proof type on signature validity alone, before its engine has said anything, so whoever can post can burn every proof type of a block for this validator and get the real prover's proofs rejected as duplicates.

[ethproofs_bridge](https://github.com/dapplion/ethproofs_bridge) is one such prover: it posts the proofs Ethproofs publishes.

Apache-2.0 OR MIT.
