use zero_api::ZeroClient;

#[tokio::main]
async fn main() {
    println!("Zero Protocol CLI Client");

    // Default CLI identity (replace with real key loading from storage in production)
    let identity_bytes = zero_crypto::keypair::StaticKeypair::generate().private.as_ref().to_vec();
    let bind_port: u16 = 7000;

    let client = match ZeroClient::start(bind_port, identity_bytes).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start ZeroClient: {}", e);
            return;
        }
    };

    // Example usage
    match client.add_friend("ZeroIdHere".to_string()).await {
        Ok(_) => println!("Friend added successfully!"),
        Err(e) => println!("Error adding friend: {}", e),
    }
}
