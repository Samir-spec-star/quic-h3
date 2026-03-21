use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use quic_h3::h3::{Header, QpackEncoder};

fn bench_qpack_encode(c: &mut Criterion) {
    let headers = vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/"),
        Header::new("user-agent", "quic-h3-client"),
    ];

    c.bench_function("qpack_encode_static", |b| {
        b.iter(|| QpackEncoder::encode(black_box(&headers)))
    });
}

criterion_group!(benches, bench_qpack_encode);
criterion_main!(benches);
