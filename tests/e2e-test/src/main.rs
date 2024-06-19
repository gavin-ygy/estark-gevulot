use clap::Parser;
use gevulot_node::{
    rpc_client::{RpcClient, RpcClientBuilder},
    types::{
        program::ResourceRequest,
        transaction::{Payload, ProgramData, ProgramMetadata, Workflow, WorkflowStep},
        Hash, Transaction,
    },
};
use libsecp256k1::SecretKey;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;



type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[clap(author = "Gevulot Team", version, about, long_about = None)]
pub struct ArgConfiguration {
    #[clap(short, long)]
    pub prover_img: PathBuf,
    #[clap(short, long)]
    pub verifier_img: PathBuf,
    #[clap(short, long, default_value = "http://localhost:9944")]
    pub json_rpc_url: String,
    #[clap(short, long, default_value = "localkey.pki")]
    pub key_file: PathBuf,
    #[clap(short, long, default_value = "127.0.0.1:0")]
    pub listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    log::info!("====ZKVM-Gevulot e2e-test =======");
    let cfg = ArgConfiguration::parse();
    let client = RpcClientBuilder::default().build(cfg.json_rpc_url)?;
  
    let bs = std::fs::read(cfg.key_file)?;
    let key = SecretKey::parse_slice(&bs)?;

   

    //Prover hash:  e78145a32b208a22b34e03cc6a6146d35683801cc97309ab86ae3ec1f0f26d70  
    //Verifier hash:  3032e67af5a5d4bc058515956911570417d0481183a7c753b907b11a8f97a45f

    let prover_hash   = Hash::from("e78145a32b208a22b34e03cc6a6146d35683801cc97309ab86ae3ec1f0f26d70");
    let verifier_hash = Hash::from("3032e67af5a5d4bc058515956911570417d0481183a7c753b907b11a8f97a45f");

    log::info!("====before proving  =======");
    for nonce in 1..2 {
        send_proving_task(&client, &key, nonce, &prover_hash, &verifier_hash)
            .await
            .expect("send proving task");
    }

    sleep(Duration::from_secs(360)).await;

    Ok(())
}


async fn send_proving_task(
    client: &RpcClient,
    key: &SecretKey,
    nonce: u64,
    prover_hash: &Hash,
    verifier_hash: &Hash,
) -> Result<Hash> {
    let proving_step = WorkflowStep {
        program: *prover_hash,
        args: vec!["--nonce".to_string(), nonce.to_string()],
        inputs: vec![],
    };

    let verifying_step = WorkflowStep {
        program: *verifier_hash,
        args: vec!["--nonce".to_string(), nonce.to_string()],
        inputs: vec![ProgramData::Output {
            source_program: *prover_hash,
            file_name: "/workspace/proof.dat".to_string(),
        }],
    };

    let tx = Transaction::new(
        Payload::Run {
            workflow: Workflow {
                steps: vec![proving_step, verifying_step],
            },
        },
        key,
    );

    client
        .send_transaction(&tx)
        .await
        .expect("send_transaction");

    Ok(tx.hash)
}

fn from_img_file_to_metadata(img_file: &Path, img_file_url: &str) -> ProgramMetadata {
    let mut hasher = blake3::Hasher::new();
    let fd = std::fs::File::open(img_file).expect("open");
    hasher.update_reader(fd).expect("checksum");
    let checksum = hasher.finalize();

    let file_name = img_file
        .file_name()
        .expect("file name")
        .to_str()
        .unwrap()
        .to_string();

    let mut program = ProgramMetadata {
        name: file_name.clone(),
        hash: Hash::default(),
        image_file_name: file_name,
        image_file_url: img_file_url.to_string(),
        image_file_checksum: checksum.to_string(),
        resource_requirements: Some(ResourceRequest {
            cpus: 1,
            mem: 128,
            gpus: 0,
        }),
    };

    program.update_hash();
    program
}
