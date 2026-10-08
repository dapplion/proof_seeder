//! Signs EIP-8025 execution proofs and submits them to a beacon node.
//!
//! A proving service holds no validator key and speaks no SSZ. It posts a proof and the facts that
//! identify what the proof is of:
//!
//! ```text
//! POST /proofs?beacon_root=..&slot=..&proof_type=..
//! ```
//!
//! and this signs an `ExecutionProofEnvelope` over those and submits it to
//! `POST /eth/v1/beacon/execution_proofs`, which verifies and gossips it.
//!
//! The envelope commits only to the proof, its type and the block. The node derives the public
//! input the proof is checked against from its own copy of the payload, so there is nothing about
//! the execution block to sign here and nothing to disagree with it about.
//!
//! The prover supplies the chain facts rather than this resolving them, so there is nothing to
//! cache, follow or expire here: the only state is the signing key. Whoever proved it, every proof
//! carries this relay's validator index, and nothing here checks a proof — running it for a proving
//! service means vouching for that service.

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use bls::{PublicKeyBytes, SecretKey};
use clap::Parser;
use eth2::types::{StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, Timeouts};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use types::execution::{
    ExecutionProofEnvelope, MAX_PROOF_SIZE, ProofData, ProofType, SignedExecutionProofEnvelope,
};
use types::{
    ChainSpec, ConfigAndPreset, Domain, GnosisEthSpec, Hash256, MainnetEthSpec, MinimalEthSpec,
    SignedRoot, Slot,
};

/// How long to wait between attempts to reach the beacon node at startup.
const RETRY: Duration = Duration::from_secs(4);

#[derive(Parser)]
#[command(
    name = "proof_seeder",
    about = "Sign EIP-8025 execution proofs and submit them"
)]
struct Config {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8026")]
    listen_address: SocketAddr,
    /// Beacon node to submit proofs to.
    #[arg(long, default_value = "http://127.0.0.1:5052")]
    beacon_node: String,
    /// EIP-2335 keystore holding the key to sign proofs with.
    #[arg(long, requires = "keystore_password_file")]
    keystore: Option<String>,
    /// File holding the password for `--keystore`.
    #[arg(long)]
    keystore_password_file: Option<String>,
    /// Hex BLS key instead of a keystore. For devnets.
    #[arg(long)]
    secret_key: Option<String>,
}

struct Relay {
    spec: ChainSpec,
    slots_per_epoch: u64,
    genesis_validators_root: Hash256,
    secret_key: SecretKey,
    validator_index: u64,
    beacon_node: BeaconNodeHttpClient,
}

/// What a prover says a proof is of.
#[derive(Deserialize)]
struct ProofQuery {
    /// Beacon block the proof vouches for.
    beacon_root: String,
    /// Slot of that block, which fixes the fork and so the signing domain.
    slot: u64,
    proof_type: ProofType,
}

impl Relay {
    fn sign(
        &self,
        query: &ProofQuery,
        proof_data: ProofData,
    ) -> Result<SignedExecutionProofEnvelope, String> {
        let Some(beacon_block_root) = parse_root(&query.beacon_root) else {
            return Err("beacon_root must be 32 byte hex".to_string());
        };

        let fork_name = self
            .spec
            .fork_name_at_epoch(Slot::new(query.slot).epoch(self.slots_per_epoch));
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            self.genesis_validators_root,
        );

        let message = ExecutionProofEnvelope {
            proof_data,
            proof_type: query.proof_type,
            beacon_block_root,
        };
        let signing_root = message.signing_root(domain);

        Ok(SignedExecutionProofEnvelope {
            message,
            validator_index: self.validator_index,
            signature: self.secret_key.sign(signing_root),
        })
    }
}

/// `POST /proofs`, body the raw proof.
async fn submit_proof(
    State(relay): State<Arc<Relay>>,
    Query(query): Query<ProofQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let Ok(proof_data) = ProofData::new(body.to_vec()) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("proof is longer than {MAX_PROOF_SIZE} bytes"),
        );
    };

    let signing = relay.clone();
    let signed = match tokio::task::spawn_blocking(move || signing.sign(&query, proof_data)).await {
        Ok(Ok(signed)) => signed,
        Ok(Err(e)) => return (StatusCode::BAD_REQUEST, e),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("signing panicked: {e}"),
            );
        }
    };

    let (beacon_block_root, proof_type) = (signed.beacon_block_root(), signed.proof_type());
    match relay
        .beacon_node
        .post_beacon_execution_proofs(vec![signed])
        .await
    {
        Ok(()) => {
            println!(
                "submitted proof of {:?} type {} ({} bytes)",
                beacon_block_root,
                proof_type,
                body.len()
            );
            (StatusCode::ACCEPTED, String::new())
        }
        Err(e) => {
            let reason = format!("beacon node rejected the proof: {e:?}");
            println!("{reason}");
            (StatusCode::BAD_GATEWAY, reason)
        }
    }
}

/// A 32 byte hex root, with or without the `0x`.
fn parse_root(root: &str) -> Option<Hash256> {
    let bytes = hex::decode(root.trim_start_matches("0x").to_lowercase()).ok()?;
    (bytes.len() == 32).then(|| Hash256::from_slice(&bytes))
}

fn load_key(config: &Config) -> SecretKey {
    if let Some(hex_key) = &config.secret_key {
        let bytes = hex::decode(hex_key.trim_start_matches("0x")).expect("secret key is not hex");
        return SecretKey::deserialize(&bytes).expect("secret key is not a BLS key");
    }

    let keystore_path = config
        .keystore
        .as_ref()
        .expect("either --keystore or --secret-key is required");
    let password_file = config
        .keystore_password_file
        .as_ref()
        .expect("--keystore requires --keystore-password-file");
    let keystore =
        eth2_keystore::Keystore::from_json_file(keystore_path).expect("cannot read keystore");
    let password = std::fs::read_to_string(password_file).expect("cannot read password file");
    keystore
        .decrypt_keypair(password.trim_end().as_bytes())
        .expect("cannot decrypt keystore")
        .sk
}

async fn serve(
    config: Config,
    spec: ChainSpec,
    slots_per_epoch: u64,
    beacon_node: BeaconNodeHttpClient,
    genesis_validators_root: Hash256,
    secret_key: SecretKey,
    validator_index: u64,
) {
    let listen_address = config.listen_address;
    let relay = Arc::new(Relay {
        secret_key,
        validator_index,
        beacon_node,
        genesis_validators_root,
        slots_per_epoch,
        spec,
    });

    let app = Router::new()
        .route("/proofs", post(submit_proof))
        // A real proof runs to a couple of megabytes, over axum's default.
        .layer(DefaultBodyLimit::max(MAX_PROOF_SIZE.saturating_add(1024)))
        .with_state(relay);

    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .expect("cannot bind");
    println!("proof relay on {listen_address}");
    axum::serve(listener, app).await.expect("server failed");
}

#[tokio::main]
async fn main() {
    let config = Config::parse();
    // Before waiting on the beacon node, so a bad keystore fails at once.
    let secret_key = load_key(&config);

    let beacon_node = BeaconNodeHttpClient::new(
        sensitive_url::SensitiveUrl::parse(&config.beacon_node)
            .expect("beacon node url is not a url"),
        Timeouts::set_all(Duration::from_secs(12)),
    );

    // Taken from the beacon node, so this relay cannot disagree with it about the network. It
    // outlives the node's restarts, so it waits rather than exiting.
    let (chain_config, slots_per_epoch) = loop {
        match beacon_node.get_config_spec::<ConfigAndPreset>().await {
            Ok(response) => {
                let spec = response.data;
                break (spec.config().clone(), spec.base_preset().slots_per_epoch);
            }
            Err(e) => {
                println!("waiting for the beacon node: {e:?}");
                tokio::time::sleep(RETRY).await;
            }
        }
    };
    let genesis_validators_root = loop {
        match beacon_node.get_beacon_genesis().await {
            Ok(response) => break response.data.genesis_validators_root,
            Err(e) => {
                println!("waiting for genesis from the beacon node: {e:?}");
                tokio::time::sleep(RETRY).await;
            }
        }
    };
    // A key that is not in the registry is a configuration error, not something to wait on.
    let pubkey = PublicKeyBytes::from(secret_key.public_key());
    let validator_index = loop {
        match beacon_node
            .get_beacon_states_validator_id(StateId::Head, &ValidatorId::PublicKey(pubkey))
            .await
        {
            Ok(Some(response)) => break response.data.index,
            Ok(None) => panic!("{pubkey:?} is not a validator on this beacon node"),
            Err(e) => {
                println!("waiting for the validator index from the beacon node: {e:?}");
                tokio::time::sleep(RETRY).await;
            }
        }
    };

    // A preset type is needed to check the config against its own constants, and nowhere else.
    let spec = match chain_config.preset_base.as_str() {
        "mainnet" => ChainSpec::from_config::<MainnetEthSpec>(&chain_config),
        "minimal" => ChainSpec::from_config::<MinimalEthSpec>(&chain_config),
        "gnosis" => ChainSpec::from_config::<GnosisEthSpec>(&chain_config),
        preset => panic!("unsupported preset {preset}"),
    }
    .expect("beacon node spec does not match its own preset");

    serve(
        config,
        spec,
        slots_per_epoch,
        beacon_node,
        genesis_validators_root,
        secret_key,
        validator_index,
    )
    .await
}
