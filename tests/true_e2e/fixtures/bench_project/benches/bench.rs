#![feature(test)]

extern crate test;

use bench_project::add;
use test::Bencher;

#[bench]
fn bench_add(b: &mut Bencher) {
    b.iter(|| add(40, 2));
}
