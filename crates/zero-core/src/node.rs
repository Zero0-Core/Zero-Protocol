use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};
use zero_dht::node::DhtPublicKey;
use zero_dht::routing::RoutingTable;
use zero_net::transport::TransportSelector;
use zero_net::udp::UdpManager;

/// The central orchestration node that ties all Zero Protocol subsystems together.
pub struct ZeroNode {
    pub identity_pk: DhtPublicKey,
    pub keypair: Arc<zero_crypto::keypair::StaticKeypair>,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub transport: Arc<TransportSelector>,
    pub blob_store: Arc<Mutex<zero_offload::store::BlobStore>>,
    pub rate_limiters: Arc<Mutex<HashMap<std::net::IpAddr, (u32, std::time::Instant)>>>,
    pub lease_store: Arc<Mutex<HashMap<DhtPublicKey, zero_dht::node::LeaseSet>>>,
    pub current_lease: Arc<Mutex<Option<zero_dht::node::LeaseSet>>>,
}

impl ZeroNode {
    pub async fn new(
        bind_addr: std::net::SocketAddr,
        keypair: zero_crypto::keypair::StaticKeypair,
    ) -> Result<Self, crate::CoreError> {
        let udp_manager = UdpManager::bind(bind_addr).await?;
        let transport = Arc::new(TransportSelector::new(Arc::new(udp_manager)));

        let identity_pk = DhtPublicKey(keypair.public);
        let routing_table = Arc::new(Mutex::new(RoutingTable::new(identity_pk.clone())));
        let keypair = Arc::new(keypair);
        let blob_store = Arc::new(Mutex::new(zero_offload::store::BlobStore::new()));

        let rate_limiters = Arc::new(Mutex::new(HashMap::new()));
        let lease_store = Arc::new(Mutex::new(HashMap::new()));
        let current_lease = Arc::new(Mutex::new(None));

        Ok(Self {
            identity_pk,
            keypair,
            routing_table,
            transport,
            blob_store,
            rate_limiters,
            lease_store,
            current_lease,
        })
    }

    /// Starts the asynchronous background event loop for the node.
    pub async fn run_background_tasks(&self) {
        info!("Starting ZeroNode event loop...");

        let transport = self.transport.clone();
        let routing_table = self.routing_table.clone();
        let keypair = self.keypair.clone();
        let blob_store = self.blob_store.clone();
        let rate_limiters = self.rate_limiters.clone();
        let lease_store = self.lease_store.clone();

        // 1. Attempt UPnP port mapping
        let local_port = transport
            .udp
            .socket()
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or(0);
        if local_port > 0 {
            tokio::task::spawn_blocking(move || {
                if let Err(e) = zero_net::upnp::map_port(local_port, local_port) {
                    warn!("UPnP port mapping failed: {:?}", e);
                }
            });
        }

        // 2. Start LAN discovery loop
        let socket = transport.udp.socket();
        let local_pk = self.identity_pk.clone();
        tokio::spawn(async move {
            zero_net::lan::lan_discovery_loop(&socket, &local_pk).await;
        });

        // 3. The core packet ingestion loop
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            loop {
                // Wait for an incoming UDP packet via the public socket() accessor
                match transport.udp.socket().recv_from(&mut buf).await {
                    Ok((size, peer_addr)) => {
                        let packet = &buf[..size];
                        Self::process_packet(
                            &routing_table,
                            &transport,
                            &keypair,
                            &blob_store,
                            &rate_limiters,
                            &lease_store,
                            peer_addr,
                            packet,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("UDP receive error: {}", e);
                    }
                }
            }
        });

        // 4. Offline message garbage collection loop (runs every hour)
        let gc_store = self.blob_store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                gc_store.lock().await.cleanup_expired(current_time);
                info!("DHT garbage collection pass complete.");
            }
        });

        // 5. Build/Maintain our own LeaseSet (Automatic Gateway Selection)
        let node_ref = Arc::new(self.clone_for_loop());
        tokio::spawn(async move {
            loop {
                node_ref.publish_lease_set().await;
                // Rotate gateways or re-publish every 10 minutes
                tokio::time::sleep(tokio::time::Duration::from_secs(600)).await;
            }
        });
    }

    /// Creates a shallow clone of the node for use in background loops.
    fn clone_for_loop(&self) -> Self {
        Self {
            identity_pk: self.identity_pk,
            keypair: self.keypair.clone(),
            routing_table: self.routing_table.clone(),
            transport: self.transport.clone(),
            blob_store: self.blob_store.clone(),
            rate_limiters: self.rate_limiters.clone(),
            lease_store: self.lease_store.clone(),
            current_lease: self.current_lease.clone(),
        }
    }

    async fn process_packet(
        routing_table: &Arc<Mutex<RoutingTable>>,
        transport: &Arc<TransportSelector>,
        keypair: &Arc<zero_crypto::keypair::StaticKeypair>,
        blob_store: &Arc<Mutex<zero_offload::store::BlobStore>>,
        rate_limiters: &Arc<Mutex<HashMap<std::net::IpAddr, (u32, std::time::Instant)>>>,
        lease_store: &Arc<Mutex<HashMap<DhtPublicKey, zero_dht::node::LeaseSet>>>,
        addr: std::net::SocketAddr,
        raw_packet: &[u8],
    ) {
        use crate::packet::{decode_packet, encode_packet, PacketType};
        use zero_dht::node::NodeInfo;
        use zero_dht::packet::{DhtPacket, DhtPayload};

        // 0. Rate limiting check
        {
            let mut limiters = rate_limiters.lock().await;
            let now = std::time::Instant::now();
            let entry = limiters.entry(addr.ip()).or_insert((0, now));

            if now.duration_since(entry.1).as_secs() >= 1 {
                entry.0 = 0;
                entry.1 = now;
            }

            entry.0 += 1;
            if entry.0 > 100 {
                // Max 100 packets per second per IP
                warn!("Rate limit exceeded for {}", addr.ip());
                return;
            }
        }

        match decode_packet(raw_packet) {
            Ok((packet_type, payload)) => match packet_type {
                PacketType::Ping => {
                    info!("Received Ping from {}", addr);
                }
                PacketType::FindNode
                | PacketType::FindNodeResponse
                | PacketType::LeaseStore
                | PacketType::LeaseResponse => {
                    if let Ok(dht_packet) = bincode::deserialize::<DhtPacket>(payload) {
                        // In a real implementation, we would decrypt `encrypted_payload` here using Noise IK.
                        // For now, we assume the payload is serialized `DhtPayload` directly inside.
                        if let Ok(dht_payload) =
                            bincode::deserialize::<DhtPayload>(&dht_packet.encrypted_payload)
                        {
                            // Always insert the sender into our routing table (passive learning)
                            let new_node = NodeInfo {
                                dht_pk: dht_packet.sender_pk,
                                addr,
                                last_seen: Some(std::time::Instant::now()),
                                reputation: 0,
                                consecutive_failures: 0,
                            };

                            let mut rt = routing_table.lock().await;
                            rt.insert(new_node);

                            match dht_payload {
                                DhtPayload::FindNodeRequest { target_pk } => {
                                    // Respond with the K closest nodes we know
                                    let closest = rt.find_closest(&target_pk, zero_dht::routing::K);
                                    let response_payload =
                                        DhtPayload::FindNodeResponse { nodes: closest };
                                    let response_bytes =
                                        bincode::serialize(&response_payload).unwrap();

                                    let resp_dht_packet =
                                        DhtPacket::new(rt.local_key, response_bytes);
                                    let resp_bytes = bincode::serialize(&resp_dht_packet).unwrap();
                                    let encoded =
                                        encode_packet(PacketType::FindNodeResponse, &resp_bytes);

                                    let target_node = NodeInfo {
                                        dht_pk: dht_packet.sender_pk,
                                        addr,
                                        last_seen: Some(std::time::Instant::now()),
                                        reputation: 0,
                                        consecutive_failures: 0,
                                    };
                                    let _ = transport.send_packet(&target_node, &encoded).await;
                                }
                                DhtPayload::FindNodeResponse { nodes } => {
                                    // We got nodes! Insert them into our routing table so our loop can find them.
                                    for node in nodes {
                                        rt.insert(node);
                                    }
                                }
                                DhtPayload::StoreLeaseRequest { lease } => {
                                    info!("Received StoreLeaseRequest for {:?}", lease.dht_pk);
                                    // Verify lease expiration is in the future
                                    let current_time = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();
                                    if lease.expiration > current_time {
                                        // In a production app, we would verify the lease signature here
                                        let mut store = lease_store.lock().await;
                                        store.insert(lease.dht_pk, lease);
                                    }
                                }
                                DhtPayload::GetLeaseRequest { target_pk } => {
                                    let store = lease_store.lock().await;
                                    let lease = store.get(&target_pk).cloned();
                                    let response_payload = DhtPayload::GetLeaseResponse { lease };

                                    if let Ok(response_bytes) =
                                        bincode::serialize(&response_payload)
                                    {
                                        let resp_dht_packet =
                                            DhtPacket::new(rt.local_key, response_bytes);
                                        if let Ok(resp_bytes) = bincode::serialize(&resp_dht_packet)
                                        {
                                            let encoded = encode_packet(
                                                PacketType::FindNodeResponse,
                                                &resp_bytes,
                                            );
                                            let target_node = NodeInfo {
                                                dht_pk: dht_packet.sender_pk,
                                                addr,
                                                last_seen: Some(std::time::Instant::now()),
                                                reputation: 0,
                                                consecutive_failures: 0,
                                            };
                                            let _ =
                                                transport.send_packet(&target_node, &encoded).await;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                PacketType::OnionRequest => {
                    info!("Received Onion Packet to relay/deliver from {}", addr);
                    if let Ok(onion_packet) =
                        bincode::deserialize::<zero_onion::packet::OnionPacket>(payload)
                    {
                        match zero_onion::forward::peel_and_forward(&onion_packet, keypair) {
                            Ok(onion_command) => match onion_command {
                                zero_onion::packet::OnionCommand::Forward { next_hop, packet } => {
                                    if let Ok(serialized_packet) = bincode::serialize(&packet) {
                                        let encoded = encode_packet(
                                            PacketType::OnionRequest,
                                            &serialized_packet,
                                        );
                                        let _ = transport.send_packet(&next_hop, &encoded).await;
                                    }
                                }
                                zero_onion::packet::OnionCommand::Deliver { final_payload } => {
                                    // We are the final destination! Process the peeled inner packet.
                                    Box::pin(Self::process_packet(
                                        routing_table,
                                        transport,
                                        keypair,
                                        blob_store,
                                        rate_limiters,
                                        lease_store,
                                        addr,
                                        &final_payload,
                                    ))
                                    .await;
                                }
                            },
                            Err(e) => {
                                warn!("Failed to peel onion packet: {:?}", e);
                            }
                        }
                    }
                }
                PacketType::SessionMessage => {
                    info!(
                        "Received Encrypted Session Message from {} ({} bytes)",
                        addr,
                        payload.len()
                    );
                }
                PacketType::OffloadStore => {
                    info!("Received Offload Store Request from {}", addr);
                    if let Ok((target_announce_key, blob)) =
                        bincode::deserialize::<([u8; 32], zero_offload::blob::OfflineBlob)>(payload)
                    {
                        let current_time = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if let Err(e) = blob_store.lock().await.store_blob(
                            target_announce_key,
                            blob,
                            current_time,
                        ) {
                            warn!("Failed to store offline blob: {:?}", e);
                        } else {
                            info!("Successfully stored offline blob for announce key");
                        }
                    }
                }
                PacketType::OffloadRetrieve => {
                    info!("Received Offload Retrieve Request from {}", addr);
                    if let Ok(target_announce_key) = bincode::deserialize::<[u8; 32]>(payload) {
                        let blobs = blob_store.lock().await.fetch_blobs(&target_announce_key);
                        if let Ok(serialized_blobs) = bincode::serialize(&blobs) {
                            let encoded =
                                encode_packet(PacketType::OffloadRetrieve, &serialized_blobs);
                            let target_node = NodeInfo {
                                dht_pk: zero_dht::node::DhtPublicKey([0u8; 32]),
                                addr,
                                last_seen: Some(std::time::Instant::now()),
                                reputation: 0,
                                consecutive_failures: 0,
                            };
                            let _ = transport.send_packet(&target_node, &encoded).await;
                        }
                    }
                }
                _ => {
                    info!(
                        "Received packet {:?} from {} ({} bytes)",
                        packet_type,
                        addr,
                        payload.len()
                    );
                }
            },
            Err(e) => {
                warn!("Dropped invalid packet from {}: {}", addr, e);
            }
        }
    }

    /// Performs an iterative Kademlia DHT lookup to find the K closest nodes to the target public key.
    /// This is the core routing algorithm of Zero Protocol.
    pub async fn dht_lookup(&self, target_pk: &DhtPublicKey) -> Vec<zero_dht::node::NodeInfo> {
        info!("Starting DHT lookup for target...");
        let mut queried = std::collections::HashSet::new();
        let alpha = 3; // Kademlia concurrency parameter

        loop {
            // 1. Get K closest nodes from local routing table
            let closest = {
                let rt = self.routing_table.lock().await;
                rt.find_closest(target_pk, zero_dht::routing::K)
            };

            // 2. Filter out nodes we have already queried
            let to_query: Vec<_> = closest
                .iter()
                .filter(|n| !queried.contains(&n.dht_pk))
                .take(alpha)
                .cloned()
                .collect();

            if to_query.is_empty() {
                // We have queried all known closest nodes. The lookup is complete.
                info!("DHT lookup complete. Found {} nodes.", closest.len());
                return closest;
            }

            // 3. Send FindNode requests concurrently
            for node in to_query {
                queried.insert(node.dht_pk);

                let local_key = { self.routing_table.lock().await.local_key };

                let payload = zero_dht::packet::DhtPayload::FindNodeRequest {
                    target_pk: *target_pk,
                };
                let payload_bytes = bincode::serialize(&payload).unwrap();
                let dht_packet = zero_dht::packet::DhtPacket::new(local_key, payload_bytes);
                let packet_bytes = bincode::serialize(&dht_packet).unwrap();

                let encoded = crate::packet::encode_packet(
                    crate::packet::PacketType::FindNode,
                    &packet_bytes,
                );

                let _ = self.transport.send_packet(&node, &encoded).await;
            }

            // 4. Wait for responses to populate the routing table before next iteration
            // In a production implementation, this would wait on a condition variable or response channels,
            // but for safety we use a timeout-based poll.
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        }
    }

    /// Selects 3 gateways and publishes our LeaseSet to the network if we have enough peers.
    pub async fn publish_lease_set(&self) {
        info!("Attempting to publish LeaseSet...");

        // 1. Select 3 highest-quality nodes as gateways
        let gateways = {
            let rt = self.routing_table.lock().await;
            // For selection, we prioritize high reputation and low consecutive failures
            let mut candidates = rt.find_closest(&self.identity_pk, 20);
            candidates.sort_by(|a, b| b.reputation.cmp(&a.reputation));
            candidates.into_iter().take(3).collect::<Vec<_>>()
        };

        if gateways.len() < 3 {
            warn!(
                "Not enough peers ({} < 3) to publish a LeaseSet",
                gateways.len()
            );
            return;
        }

        let expiration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour

        let lease = zero_dht::node::LeaseSet {
            dht_pk: self.identity_pk.clone(),
            gateways,
            expiration,
        };

        // 2. Update local state
        *self.current_lease.lock().await = Some(lease.clone());

        // 3. Find the K nodes closest to our identity to store the LeaseSet
        let storage_nodes = self.dht_lookup(&self.identity_pk).await;

        let payload = zero_dht::packet::DhtPayload::StoreLeaseRequest { lease };
        let payload_bytes = bincode::serialize(&payload).unwrap();

        for node in storage_nodes {
            let dht_packet =
                zero_dht::packet::DhtPacket::new(self.identity_pk, payload_bytes.clone());
            if let Ok(resp_bytes) = bincode::serialize(&dht_packet) {
                let encoded = crate::packet::encode_packet(
                    crate::packet::PacketType::LeaseStore,
                    &resp_bytes,
                );
                let _ = self.transport.send_packet(&node, &encoded).await;
            }
        }

        info!("LeaseSet successfully published to the DHT");
    }

    /// Resolves a peer's LeaseSet (entry points) from the network.
    pub async fn find_lease(&self, target_pk: &DhtPublicKey) -> Option<zero_dht::node::LeaseSet> {
        info!("Searching for LeaseSet for {:?}...", target_pk);

        // 1. Find nodes closest to the target
        let storage_nodes = self.dht_lookup(target_pk).await;

        // 2. Query nodes for the LeaseSet
        for node in storage_nodes {
            let payload = zero_dht::packet::DhtPayload::GetLeaseRequest {
                target_pk: *target_pk,
            };
            if let Ok(payload_bytes) = bincode::serialize(&payload) {
                let dht_packet = zero_dht::packet::DhtPacket::new(self.identity_pk, payload_bytes);
                if let Ok(pkt_bytes) = bincode::serialize(&dht_packet) {
                    let encoded = crate::packet::encode_packet(
                        crate::packet::PacketType::LeaseResponse,
                        &pkt_bytes,
                    );
                    let _ = self.transport.send_packet(&node, &encoded).await;
                }
            }
        }

        // 3. Wait/Poll for response (In a real implementation, we'd use a dedicated response channel)
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check if our lease_store has been populated by an incoming response
        let store = self.lease_store.lock().await;
        store.get(target_pk).cloned()
    }
}
