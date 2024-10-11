use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, BufMut, Buf};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::{HashSet, VecDeque};
use rand::Rng;
use std::net::ToSocketAddrs;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("Cannacoin crawler started.");

    // Known Cannacoin seed nodes
    let seed_nodes = vec![
        "cannacoin.duckdns.org:7143",
    ];

    // Set to keep track of discovered nodes
    let mut discovered_nodes = HashSet::new();
    let mut nodes_to_crawl = VecDeque::new();

    // Add seed nodes to the queue
    for node in seed_nodes {
        println!("Adding seed node to crawl queue: {}", node);
        nodes_to_crawl.push_back(node.to_string());
    }

    // Crawl nodes
    while let Some(node) = nodes_to_crawl.pop_front() {
        println!("Attempting to crawl node: {}", node);
        if discovered_nodes.contains(&node) {
            println!("Node {} has already been discovered. Skipping.", node);
            continue;
        }
        discovered_nodes.insert(node.clone());

        match crawl_node(&node).await {
            Ok(addr_list) => {
                println!("Crawled {} successfully. Found {} new nodes.", node, addr_list.len());
                for addr in addr_list {
                    if !discovered_nodes.contains(&addr) {
                        println!("Discovered new node: {}", addr);
                        nodes_to_crawl.push_back(addr.clone());
                    }
                }
            }
            Err(e) => {
                eprintln!("Error crawling {}: {}", node, e);
            }
        }
    }

    // Print discovered nodes
    println!("Discovered nodes:");
    for node in &discovered_nodes {
        println!("{}", node);
    }

    println!("Crawler has completed execution.");
    Ok(())
}

async fn crawl_node(node: &str) -> std::io::Result<Vec<String>> {
    println!("Connecting to {}", node);

    // Resolve the node address
    let addr = match node.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(address) = addrs.next() {
                address
            } else {
                eprintln!("No valid addresses found for {}", node);
                return Ok(Vec::new());
            }
        }
        Err(e) => {
            eprintln!("Could not resolve {}: {}", node, e);
            return Ok(Vec::new());
        }
    };
    println!("Resolved {} to {}", node, addr);

    // Connect to the node
    let mut stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            println!("Successfully connected to {}", node);
            stream
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", node, e);
            return Ok(Vec::new());
        }
    };

    // Send version message
    let version_message = build_version_message();
    stream.write_all(&version_message).await.map_err(|e| {
        eprintln!("Error sending version message to {}: {}", node, e);
        e
    })?;
    println!("Sent version message to {}", node);

    // Read messages from the node
    let mut buffer = BytesMut::with_capacity(1024 * 1024); // Persistent buffer
    let mut nodes = Vec::new();

    let _handshake_complete = false;

    loop {
        // Read data with a timeout to prevent hanging
        let mut temp_buf = [0u8; 4096];
        let read_result = timeout(Duration::from_secs(10), stream.read(&mut temp_buf)).await;

        let n = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                eprintln!("Error reading from {}: {}", node, e);
                break;
            }
            Err(_) => {
                eprintln!("Read timeout from {}", node);
                break;
            }
        };

        if n == 0 {
            println!("Connection closed by {}", node);
            break;
        }

        println!("Received {} bytes from {}", n, node);
        buffer.extend_from_slice(&temp_buf[..n]);

        // Process messages from buffer
        loop {
            // Check for the complete header
            if buffer.len() < 24 {
                // Not enough data for a full header
                break;
            }

            // Read magic number without advancing the buffer
            let magic = (&buffer[..4]).get_u32_le();
            if magic != 0xd5fcc0c7 {
                eprintln!("Invalid magic number from {}: {:#x}", node, magic);
                // You may choose to close the connection here
                return Ok(nodes);
            }

            // Read payload length
            let payload_len = (&buffer[16..20]).get_u32_le() as usize;
            let message_len = 24 + payload_len;

            if buffer.len() < message_len {
                // Not enough data for the full message
                break;
            }

            // Now we can parse the message
            let mut message = buffer.split_to(message_len);

            // Advance past the magic number
            let _magic = message.get_u32_le();

            // Read command
            let mut cmd_bytes = [0u8; 12];
            message.copy_to_slice(&mut cmd_bytes);
            let command = {
                let cmd_str = String::from_utf8_lossy(&cmd_bytes);
                cmd_str.trim_end_matches('\0').to_string()
            };

            // Read payload length and checksum
            let payload_len = message.get_u32_le() as usize;
            let checksum = {
                let mut checksum_bytes = [0u8; 4];
                message.copy_to_slice(&mut checksum_bytes);
                checksum_bytes
            };

            // Read payload
            let payload = message.copy_to_bytes(payload_len);

            // Validate checksum
            let computed_checksum = &double_sha256(&payload)[..4];
            if checksum != computed_checksum {
                eprintln!("Checksum mismatch for message '{}' from {}", command, node);
                continue;
            }

            println!("Received '{}' message from {}", command, node);

            // Handle the message based on the command
            if command == "version" {
                // Respond with verack
                let verack_message = build_verack_message();
                stream.write_all(&verack_message).await.map_err(|e| {
                    eprintln!("Error sending verack to {}: {}", node, e);
                    e
                })?;
                println!("Sent verack to {}", node);
            } else if command == "verack" {
                println!("Received 'verack' from {}", node);
                // Send getaddr after handshake
                let getaddr_message = build_getaddr_message();
                stream.write_all(&getaddr_message).await.map_err(|e| {
                    eprintln!("Error sending getaddr to {}: {}", node, e);
                    e
                })?;
                println!("Sent getaddr to {}", node);
            } else if command == "ping" {
                println!("Received 'ping' message from {}", node);
                let pong_message = build_pong_message(&payload);
                stream.write_all(&pong_message).await.map_err(|e| {
                    eprintln!("Error sending pong to {}: {}", node, e);
                    e
                })?;
                println!("Sent pong to {}", node);
            } else if command == "addr" {
                // Parse and handle addr message
                let new_nodes = parse_addr_payload(&payload);
                println!("Received {} new addresses from {}", new_nodes.len(), node);
                nodes.extend(new_nodes);
            } else {
                println!("Unhandled message '{}' from {}", command, node);
                // Handle other messages if necessary
            }
        }
    }

    Ok(nodes)
}

fn build_version_message() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(126);

    // Cannacoin's magic number in little-endian format
    let magic: u32 = 0xd5fcc0c7;
    buf.put_u32_le(magic);

    // Command "version"
    let mut command = [0u8; 12];
    let cmd = b"version";
    command[..cmd.len()].copy_from_slice(cmd);
    buf.put_slice(&command);

    // Placeholder for payload length and checksum
    buf.put_u32_le(0); // payload length
    buf.put_u32_le(0); // checksum

    let payload_start = buf.len();

    // Cannacoin's protocol version
    let version: i32 = 2000001;
    buf.put_i32_le(version);

    // Services
    let services: u64 = 1;
    buf.put_u64_le(services);

    // Timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    buf.put_i64_le(timestamp);

    // Addr_recv (Network Address of the remote node)
    buf.put_u64_le(0); // services of the remote node
    buf.put_slice(&[0u8; 16]); // IPv6 or IPv4-mapped IPv6 address
    buf.put_u16(0); // port in big-endian

    // Addr_from (Our network address)
    buf.put_u64_le(services); // our services
    buf.put_slice(&[0u8; 16]); // our IP address (set to zero)
    buf.put_u16(0); // port in big-endian

    // Nonce
    let nonce: u64 = rand::thread_rng().gen();
    buf.put_u64_le(nonce);

    // User Agent
    let user_agent = b"/CannacoinCrawler:0.1.0/";
    buf.put_u8(user_agent.len() as u8);
    buf.put_slice(user_agent);

    // Start Height
    let start_height: i32 = 0; // Adjust if you have a specific start height
    buf.put_i32_le(start_height);

    // Relay (bool)
    buf.put_u8(0);

    // Calculate payload length and checksum
    let payload = &buf[payload_start..];
    let payload_len = payload.len() as u32;

    // Compute checksum
    let checksum = double_sha256(payload);
    let checksum = &checksum[..4];

    // Fill in payload length and checksum in the header
    buf[16..20].copy_from_slice(&payload_len.to_le_bytes());
    buf[20..24].copy_from_slice(checksum);

    buf.to_vec()
}

fn build_verack_message() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(24);

    // Cannacoin's magic number in little-endian format
    let magic: u32 = 0xd5fcc0c7;
    buf.put_u32_le(magic);

    // Command "verack"
    let mut command = [0u8; 12];
    let cmd = b"verack";
    command[..cmd.len()].copy_from_slice(cmd);
    buf.put_slice(&command);

    // Payload length and checksum (verack has no payload)
    buf.put_u32_le(0);
    buf.put_u32_le(0x5df6e0e2); // Checksum for empty payload

    buf.to_vec()
}

fn build_getaddr_message() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(24);

    // Cannacoin's magic number in little-endian format
    let magic: u32 = 0xd5fcc0c7;
    buf.put_u32_le(magic);

    // Command "getaddr"
    let mut command = [0u8; 12];
    let cmd = b"getaddr";
    command[..cmd.len()].copy_from_slice(cmd);
    buf.put_slice(&command);

    // Payload length and checksum (getaddr has no payload)
    buf.put_u32_le(0);
    buf.put_u32_le(0x5df6e0e2); // Checksum for empty payload

    buf.to_vec()
}

fn build_pong_message(payload: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(24 + payload.len());

    // Cannacoin's magic number in little-endian format
    let magic: u32 = 0xd5fcc0c7;
    buf.put_u32_le(magic);

    // Command "pong"
    let mut command = [0u8; 12];
    let cmd = b"pong";
    command[..cmd.len()].copy_from_slice(cmd);
    buf.put_slice(&command);

    // Payload length
    let payload_len = payload.len() as u32;
    buf.put_u32_le(payload_len);

    // Checksum
    let checksum = &double_sha256(payload)[..4];
    buf.put_slice(checksum);

    // Payload (same as received in ping)
    buf.put_slice(payload);

    buf.to_vec()
}

fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let first_hash = Sha256::digest(payload);
    let second_hash = Sha256::digest(&first_hash);
    second_hash.to_vec()
}

fn parse_addr_payload(payload: &[u8]) -> Vec<String> {
    let mut buf = BytesMut::from(payload);
    let count = read_varint(&mut buf);
    let mut nodes = Vec::new();

    for _ in 0..count {
        if buf.remaining() < 30 {
            break;
        }

        let _time = buf.get_u32_le();
        let _services = buf.get_u64_le();
        let mut ip_bytes = [0u8; 16];
        buf.copy_to_slice(&mut ip_bytes);
        let port = buf.get_u16();

        // Convert IP bytes to string
        let ip = if ip_bytes[..12] == [0u8; 12] {
            // IPv4-mapped IPv6 address
            let ipv4_bytes = [ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]];
            std::net::Ipv4Addr::from(ipv4_bytes).to_string()
        } else {
            // IPv6 address
            std::net::Ipv6Addr::from(ip_bytes).to_string()
        };

        let addr = format!("{}:{}", ip, port);
        nodes.push(addr);
    }

    nodes
}

fn read_varint(buf: &mut BytesMut) -> u64 {
    if !buf.has_remaining() {
        return 0;
    }

    let first_byte = buf.get_u8();

    match first_byte {
        0xFF => {
            if buf.remaining() < 8 {
                return 0;
            }
            buf.get_u64_le()
        }
        0xFE => {
            if buf.remaining() < 4 {
                return 0;
            }
            buf.get_u32_le() as u64
        }
        0xFD => {
            if buf.remaining() < 2 {
                return 0;
            }
            buf.get_u16_le() as u64
        }
        x => x as u64,
    }
}
