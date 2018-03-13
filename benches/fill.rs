extern crate aesrng;
extern crate xoroshiro;
extern crate rand;

#[macro_use]
extern crate criterion;

use rand::Rng;
use criterion::{Criterion, Fun};

fn fill(c: &mut Criterion) {
    const BUF_SIZE: usize = 1024 * 1024 * 100;
    let fill_aes = {
        let mut rng = aesrng::AesRng::from_seed(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
             0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let mut buf = vec![0; BUF_SIZE];

        Fun::new("aes", move |b, _| b.iter(|| rng.fill(&mut buf)))
    };
    let fill_xoroshiro = {
        let mut rng = xoroshiro::rng::XoroShiro128::new_unseeded();
        let mut buf = vec![0; BUF_SIZE];

        Fun::new("xoroshiro", move |b, _| b.iter(|| rng.fill_bytes(&mut buf)))
    };
    c.bench_functions("fill",
        vec![fill_aes, fill_xoroshiro],
        ());
}

criterion_group!(benches, fill);
criterion_main!(benches);
