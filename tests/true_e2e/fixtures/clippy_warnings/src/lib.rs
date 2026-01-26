#![forbid(unsafe_code)]

pub fn add(a: i32, b: i32) -> i32 {
    let unused = a + b;
    a + b
}
