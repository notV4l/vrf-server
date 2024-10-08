use std::sync::Arc;

use clap::Parser;
use katana_primitives::{block::BlockTag, Felt};
use starknet::{
    accounts::{ExecutionEncoding, SingleOwnerAccount},
    macros::short_string,
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Url},
    signers::{LocalWallet, SigningKey},
};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Secret key
    #[arg(short, long, /*required = true,*/ default_value = "1056")] // 0x420
    pub secret_key: u64,

    /// Secret key
    #[arg(short, long, default_value = "8888")]
    pub port: u64,

    /// Vrf provider
    #[arg(
        short,
        long,
        default_value = "0x061ea5f7ebeed84fa95b19d53d362ec786620953a99b298fe25925abb145e377"
    )]
    pub vrf_provider_address: Felt,

    /// RPC
    #[arg(short, long, default_value = "http://localhost:5050")]
    pub rpc: Url,

    #[arg(
        short,
        long,
        default_value = "0x1c9053c053edf324aec366a34c6901b1095b07af69495bffec7d7fe21effb1b"
    )]
    pub private_key: Felt,

    #[arg(
        short,
        long,
        default_value = "0x6b86e40118f29ebe393a75469b4d926c7a44c2e2681b6d319520b7c1156d114"
    )]
    pub address: Felt,
}

impl Args {
    pub fn get_secret_key(self: &Args) -> String {
        self.secret_key.to_string()
    }

    pub fn get_provider(self: &Args) -> Arc<JsonRpcClient<HttpTransport>> {
        Arc::new(JsonRpcClient::new(HttpTransport::new(self.rpc.clone())))
    }

    pub fn get_account(
        self: &Args,
    ) -> SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet> {
        let provider = self.get_provider();
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(self.private_key.clone()));

        let mut account = SingleOwnerAccount::new(
            provider,
            signer,
            self.address,
            short_string!("KATANA"),
            ExecutionEncoding::New,
        );

        account.set_block_id(starknet::core::types::BlockId::Tag(BlockTag::Pending));
        account
    }
}
