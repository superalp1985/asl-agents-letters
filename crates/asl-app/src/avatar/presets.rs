macro_rules! presets {
    ($($name:literal),+ $(,)?) => {
        pub const PNGS: &[&[u8]] = &[
            $(include_bytes!(concat!("../../assets/avatars/", $name, "-128.png"))),+
        ];
    };
}

presets!(
    "avatar-01-teal-bob",
    "avatar-02-ink-cap",
    "avatar-03-sky-glasses",
    "avatar-04-coral-band",
    "avatar-05-headphones",
    "avatar-06-cream-bun",
    "avatar-07-antenna",
    "avatar-08-visor",
    "avatar-09-freckles",
    "avatar-10-side-part",
    "avatar-11-earpiece",
    "avatar-12-round-badge",
);
