#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("asl-infra currently runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::{env, io, path::Path};

    use asl_app::infrastructure::{InfrastructureConfigV1, load_or_create_relay_identity};
    use asl_net::relay::RelayServer;

    let mut args = env::args_os().skip(1);
    let config_path = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: asl-infra <configuration.toml>",
        )
    })?;
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: asl-infra <configuration.toml>",
        )
        .into());
    }

    let config = InfrastructureConfigV1::load(Path::new(&config_path))?;
    let identity = load_or_create_relay_identity(&config)?;
    let mut server = RelayServer::new(identity, config.relay_limits())?;
    for (kind, address) in config.listen_addresses()? {
        server.listen(kind, address)?;
    }
    eprintln!("ASL relay PeerId: {}", server.peer_id());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(server.run())?;
    Ok(())
}
