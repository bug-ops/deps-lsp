use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse_simple(_c: &mut Criterion) {
    // TODO: implement parsing benchmark
    // let toml = include_str!("../tests/fixtures/simple.toml");
    // c.bench_function("parse_simple_toml", |b| {
    //     b.iter(|| parse_cargo_toml(black_box(toml)))
    // });
}

fn bench_parse_complex(_c: &mut Criterion) {
    // TODO: implement parsing benchmark
    // let toml = include_str!("../tests/fixtures/complex.toml");
    // c.bench_function("parse_complex_toml", |b| {
    //     b.iter(|| parse_cargo_toml(black_box(toml)))
    // });
}

criterion_group!(benches, bench_parse_simple, bench_parse_complex);
criterion_main!(benches);
