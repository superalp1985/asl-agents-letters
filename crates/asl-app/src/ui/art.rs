use eframe::egui::{ColorImage, IconData};

const ENVELOPE: [&str; 16] = [
    "................",
    "..TTTTTTTTTTTT..",
    ".TTTTTTTTTTTTTT.",
    ".TTTTTTTTTTTTTT.",
    ".TTWWWWWWWWTTTT.",
    ".TWKWWWWWWKWWTT.",
    ".TWWKWWWWKWWWTT.",
    ".TWWWKWWKWWWWTT.",
    ".TWWWWKKWWWWWTT.",
    ".TWWWWWWWWWKTTT.",
    ".TTWWWWWWWWKOOT.",
    ".TTTTTTTTTTKOOT.",
    ".TTTTTTTTTTTKKT.",
    ".TTTTTTTTTTTTTT.",
    "..TTTTTTTTTTTT..",
    "................",
];

const MASCOT: [&str; 24] = [
    "........................",
    "........KKKKKKK.........",
    "......KKHHHHHHHKK.......",
    ".....KHHHHHHHHHHHK......",
    "....KHHHHHHHHHHTKKK.....",
    "....KHHHHHHHHHTOTKK.....",
    "...KKHHKKHHHHHHTKHK.....",
    "...KHHKSSKKHHKKSHHK.....",
    "...KHKSSSSSKKSSSKHK.....",
    "...KHKSKWSSSSKWSKHK.....",
    "...KHKSKKSSSSKKSKHK.....",
    "...KHKRSSSKKSSRSKHK.....",
    "...KHHKSSSSSSSSKHHK.....",
    "....KHHKKSSSSKKHHK......",
    ".....KKKTTKKTTKKK.......",
    "......KTTTWWTTTK........",
    ".....KTTKWWWWKTTK.......",
    ".....KTSWKKKKWSTK.......",
    "......KSWKWWKWKSK.......",
    ".......KWWWWWWK.........",
    ".......KKTTTTKK.........",
    ".......KSK..KSK.........",
    ".......KKK..KKK.........",
    "........................",
];

pub(super) fn icon() -> IconData {
    IconData {
        width: 16,
        height: 16,
        rgba: pixels(&ENVELOPE),
    }
}

pub(super) fn mascot() -> ColorImage {
    ColorImage::from_rgba_unmultiplied([24, 24], &pixels(&MASCOT))
}

fn pixels<const N: usize>(rows: &[&str; N]) -> Vec<u8> {
    rows.iter()
        .flat_map(|row| {
            row.bytes()
                .chain(std::iter::repeat(b'.'))
                .take(N)
                .flat_map(|c| match c {
                    b'K' => [33, 43, 49, 255],
                    b'T' => [25, 118, 108, 255],
                    b'W' => [251, 250, 243, 255],
                    b'O' => [252, 180, 104, 255],
                    b'H' => [108, 153, 178, 255],
                    b'S' => [249, 216, 187, 255],
                    b'R' => [235, 143, 143, 255],
                    _ => [0, 0, 0, 0],
                })
        })
        .collect()
}
