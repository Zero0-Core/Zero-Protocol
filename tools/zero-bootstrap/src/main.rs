use zero_api::ZeroClient;

#[tokio::main]
async fn main() {
    println!("Starting Zero Protocol Bootstrap Node...");
    // A bootstrap node is simply a ZeroNode that does not engage in chat 
    // but responds to DHT FindNode requests to help others join the network.
    
    let bind_port = 33445;
    let identity_bytes = zero_crypto::keypair::StaticKeypair::generate().private.as_ref().to_vec();
    
    let _client = match ZeroClient::start(bind_port, identity_bytes).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start bootstrap node: {}", e);
            return;
        }
    };
    
    println!("Bootstrap node running on UDP port {}", bind_port);
    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down bootstrap node.");
}
