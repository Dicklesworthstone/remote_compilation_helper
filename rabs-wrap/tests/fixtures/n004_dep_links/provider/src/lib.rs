include!(concat!(env!("OUT_DIR"), "/gen.rs"));

pub fn probe() -> u32 {
    g()
}
