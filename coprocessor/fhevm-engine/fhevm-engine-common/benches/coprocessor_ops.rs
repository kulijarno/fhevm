//! CodSpeed benchmarks for pure-CPU hot paths of the fhevm coprocessor.
//!
//! These benchmarks focus on the input-processing and validation code that runs
//! for every computation request handled by the coprocessor. They are
//! deliberately free of any I/O (no database, no network, no FHE key material),
//! which makes them deterministic and well suited to CodSpeed's instrumentation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use fhevm_engine_common::tfhe_ops::{
    check_fhe_operand_types, does_fhe_operation_support_scalar, to_be_u16_bit, to_be_u160_bit,
    to_be_u2048_bit, to_be_u256_bit, to_be_u32_bit, to_be_u64_bit, validate_fhe_type,
};
use fhevm_engine_common::types::SupportedFheOperations;
use fhevm_engine_common::utils::compact_hex;

/// Build a 32-byte handle with the given ciphertext type byte, as expected by
/// the coprocessor (the type is stored at byte index 30).
fn make_handle(ct_type: u8, seed: u8) -> Vec<u8> {
    let mut handle = vec![seed; 32];
    handle[30] = ct_type;
    handle
}

fn bench_be_conversions(c: &mut Criterion) {
    // A 256-bit big-endian buffer, representative of a scalar operand.
    let input: Vec<u8> = (0..32u8).collect();

    let mut group = c.benchmark_group("be_conversions");
    group.bench_function("to_be_u16_bit", |b| {
        b.iter(|| to_be_u16_bit(black_box(&input)))
    });
    group.bench_function("to_be_u32_bit", |b| {
        b.iter(|| to_be_u32_bit(black_box(&input)))
    });
    group.bench_function("to_be_u64_bit", |b| {
        b.iter(|| to_be_u64_bit(black_box(&input)))
    });
    group.bench_function("to_be_u160_bit", |b| {
        b.iter(|| to_be_u160_bit(black_box(&input)))
    });
    group.bench_function("to_be_u256_bit", |b| {
        b.iter(|| to_be_u256_bit(black_box(&input)))
    });
    group.bench_function("to_be_u2048_bit", |b| {
        b.iter(|| to_be_u2048_bit(black_box(&input)))
    });
    group.finish();
}

fn bench_type_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");
    group.bench_function("validate_fhe_type", |b| {
        b.iter(|| {
            for t in 0..12i32 {
                let _ = validate_fhe_type(black_box(t));
            }
        })
    });

    group.bench_function("does_fhe_operation_support_scalar", |b| {
        let ops = [
            SupportedFheOperations::FheAdd,
            SupportedFheOperations::FheMul,
            SupportedFheOperations::FheNeg,
            SupportedFheOperations::FheCast,
            SupportedFheOperations::FheIfThenElse,
        ];
        b.iter(|| {
            for op in ops.iter() {
                let _ = does_fhe_operation_support_scalar(black_box(op));
            }
        })
    });
    group.finish();
}

fn bench_operand_type_checks(c: &mut Criterion) {
    // FheAdd (binary) with two encrypted 64-bit operands.
    let lhs = make_handle(5, 0x11);
    let rhs = make_handle(5, 0x22);
    let handles = vec![lhs, rhs];
    let scalars = vec![false, false];

    // FheAdd (binary) with a scalar right-hand operand.
    let scalar_rhs: Vec<u8> = (1..=32u8).collect();
    let scalar_handles = vec![make_handle(5, 0x11), scalar_rhs];
    let scalar_flags = vec![false, true];

    let mut group = c.benchmark_group("operand_type_checks");
    group.bench_function("binary_encrypted", |b| {
        b.iter(|| {
            check_fhe_operand_types(
                black_box(SupportedFheOperations::FheAdd as i32),
                black_box(&handles),
                black_box(&scalars),
            )
        })
    });
    group.bench_function("binary_scalar", |b| {
        b.iter(|| {
            check_fhe_operand_types(
                black_box(SupportedFheOperations::FheAdd as i32),
                black_box(&scalar_handles),
                black_box(&scalar_flags),
            )
        })
    });
    group.finish();
}

fn bench_compact_hex(c: &mut Criterion) {
    let handle = make_handle(5, 0xab);
    c.bench_function("compact_hex", |b| {
        b.iter(|| compact_hex(black_box(&handle)))
    });
}

criterion_group!(
    benches,
    bench_be_conversions,
    bench_type_validation,
    bench_operand_type_checks,
    bench_compact_hex
);
criterion_main!(benches);
