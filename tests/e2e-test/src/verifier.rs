extern crate clap;
use clap::{command, Parser};


use starky::prove::stark_prove;

use std::time::Instant;
use std::fs;



use gevulot_common::WORKSPACE_PATH;
use gevulot_shim::{Task, TaskResult};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/////////////////////Parameter parse
#[derive(Debug, Parser, Default)]
#[command(about, version, no_binary_name(true))]
struct Cli {

    #[arg(short, long = "proof_file", default_value = "/workspace/lr_chunk_0/lr_proof.bin")]
    proof_file: String,
    #[arg(short, long = "circom_file", default_value = "/workspace/lr_chunk_0.circom")]
    circom_file: String,
    
}

fn main()-> Result<()>  {
   gevulot_shim::run(run_task)
}

fn run_task(task: Task) -> Result<TaskResult> {

    //env_logger::init();
    println!("verifier : task.args: {:?}", &task.args);
    let args =  Cli::parse_from(&task.args);
   
    let mut log_file = File::create("/workspace/test_v.log")?;
    write!(log_file, "verifier : task.args::{}\n",  &task.args)?;
    write!(log_file, "proof file::{}\n",  &args.proof_file)?;
    write!(log_file, "circom file::{}\n",  &args.circom_file)?;
    
    //In this test, the verifier does nothing. 


      //return  the files generated by the prover  to the gevulot's client.
      task.result(vec![1,2,3,4,5,6,7,8,9], vec![String::from("/workspace/test_v.log"),String::from("/workspace/test.log")])
}
