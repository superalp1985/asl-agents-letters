use libp2p::{
    autonat, dcutr, identify, kad, mdns, noise, ping, quic, relay, request_response, tcp, yamux,
};

fn main() {
    let _identity = libp2p::identity::Keypair::generate_ed25519();
    let _ = std::any::type_name::<kad::Behaviour<kad::store::MemoryStore>>();
    let _ = std::any::type_name::<mdns::tokio::Behaviour>();
    let _ = (
        std::any::type_name::<autonat::Behaviour>(),
        std::any::type_name::<dcutr::Behaviour>(),
        std::any::type_name::<identify::Behaviour>(),
        std::any::type_name::<ping::Behaviour>(),
        std::any::type_name::<noise::Config>(),
        std::any::type_name::<quic::Config>(),
        std::any::type_name::<relay::client::Behaviour>(),
        std::any::type_name::<tcp::Config>(),
        std::any::type_name::<yamux::Config>(),
        std::any::type_name::<request_response::ProtocolSupport>(),
    );
}
