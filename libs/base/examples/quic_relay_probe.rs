use anyhow::{bail, Context, Result};
use hbb_common::{
    base64::{engine::general_purpose::STANDARD, Engine as _},
    bytes::BytesMut,
    rendezvous_proto::{RendezvousMessage, RequestRelay},
    sha2::{Digest, Sha256},
    uuid::Uuid,
    Stream,
};
use std::{path::Path, process::Stdio, time::Instant};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    time::{sleep, timeout, Duration},
};

async fn receive(stream: &mut Stream, buffered: &mut BytesMut, size: usize) -> Result<Vec<u8>> {
    while buffered.len() < size {
        let bytes = timeout(Duration::from_secs(20), stream.next())
            .await?
            .context("Relay closed before the expected bytes arrived")??;
        buffered.extend_from_slice(&bytes);
    }
    Ok(buffered.split_to(size).to_vec())
}

async fn run(stream: &mut Stream, seconds: u64) -> Result<()> {
    let mut buffered = BytesMut::new();
    let start = Instant::now();
    let mut echoes = 0u32;
    while start.elapsed().as_secs() < seconds {
        let payload = echoes.to_be_bytes();
        let mut command = vec![b'P', 0, 0, 0, 4];
        command.extend_from_slice(&payload);
        stream.send_raw(command).await?;
        if receive(stream, &mut buffered, 4).await? != payload {
            bail!("Native QUIC echo integrity mismatch");
        }
        echoes += 1;
        if echoes % 20 == 0 {
            println!(
                "{}",
                serde_json::json!({"echoes":echoes,"seconds":start.elapsed().as_secs()})
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
    let size = 2 * 1024 * 1024u32;
    let mut download = vec![b'D'];
    download.extend_from_slice(&size.to_be_bytes());
    stream.send_raw(download).await?;
    let data = receive(stream, &mut buffered, size as usize).await?;
    let expected = receive(stream, &mut buffered, 32).await?;
    if Sha256::digest(&data).as_slice() != expected {
        bail!("Native QUIC download integrity mismatch");
    }
    let mut upload = vec![b'U'];
    upload.extend_from_slice(&size.to_be_bytes());
    upload.extend_from_slice(&data);
    stream.send_raw(upload).await?;
    if receive(stream, &mut buffered, 32).await? != expected {
        bail!("Native QUIC upload integrity mismatch");
    }
    stream.send_raw(vec![b'Q']).await?;
    println!(
        "{}",
        serde_json::json!({"status":"ok","transport":"native_quic","echoes":echoes,"seconds":start.elapsed().as_secs_f64(),"bytes_verified_each_direction":size})
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    hbb_common::env_logger::Builder::from_env(
        hbb_common::env_logger::Env::default().default_filter_or("info"),
    )
    .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        bail!("Usage: quic_relay_probe PRIVATE_CONFIG SERVER_PUBLIC_KEY SSH_ALIAS [SECONDS]");
    }
    let seconds = args
        .get(4)
        .map(|x| x.parse::<u64>())
        .transpose()?
        .unwrap_or(70);
    if !(1..=120).contains(&seconds) {
        bail!("Probe duration must be 1-120 seconds");
    }
    let key = tokio::fs::read_to_string(&args[2]).await?;
    let session = format!("codex-native-quic-{}", Uuid::new_v4().simple());
    let config_text = tokio::fs::read_to_string(&args[1]).await?;
    let config: serde_json::Value =
        serde_json::from_str(config_text.trim_start_matches('\u{feff}'))?;
    let relay = config
        .get("relay")
        .and_then(|value| value.as_str())
        .context("Missing relay in probe configuration")?;
    let parameters = serde_json::to_vec(&vec!["peer", relay, &session, key.trim()])?;
    let peer_source = format!(
        "import sys,json,base64\nsys.argv=json.loads(base64.b64decode('{}'))\n{}",
        STANDARD.encode(&parameters),
        include_str!("quic_relay_peer.py"),
    );
    let remote_command = format!(
        "python3 -u -c \"import base64;exec(base64.b64decode('{}'))\"",
        STANDARD.encode(peer_source.as_bytes()),
    );
    let mut command = Command::new("ssh");
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut peer = command
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            &args[3],
            &remote_command,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = peer.stdout.take().context("SSH peer has no stdout")?;
    let mut output = BufReader::new(stdout);
    let mut ready = String::new();
    timeout(Duration::from_secs(15), output.read_line(&mut ready)).await??;
    let ready: serde_json::Value = serde_json::from_str(&ready)?;
    if ready.get("event").and_then(|x| x.as_str()) != Some("peer_ready") {
        bail!("VPS peer did not become ready");
    }
    let mut stream = base::quic_relay::connect_config_file(Path::new(&args[1]), 15_000).await?;
    let mut request = RendezvousMessage::new();
    request.set_request_relay(RequestRelay {
        id: "native-quic-probe".to_owned(),
        uuid: session,
        licence_key: key.trim().to_owned(),
        ..Default::default()
    });
    stream.send(&request).await?;
    stream.set_raw();
    let result = run(&mut stream, seconds).await;
    drop(stream);
    if timeout(Duration::from_secs(5), peer.wait()).await.is_err() {
        peer.kill().await?;
    }
    result
}
