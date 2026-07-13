//! Fuzz the page-carving / fragment-reconstruction routines over arbitrary
//! page buffers and split points. Must never panic on garbage pages or lying
//! sizes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Derive a page size and expected record size from the first bytes, kept in
    // a sane bound so the fuzzer explores structure rather than allocation.
    let page_size = 1 + (usize::from(data.first().copied().unwrap_or(0)) % 64) * 64;
    let expected = usize::from(data.get(1).copied().unwrap_or(0)) % 512;
    let body = data.get(2..).unwrap_or(&[]);

    let pairs = ese_carver::detect_fragments(body, page_size, expected);
    for p in pairs.iter().take(64) {
        let prefix = body.get(..p.prefix_len.min(body.len())).unwrap_or(&[]);
        let suffix = body.get(..p.suffix_len.min(body.len())).unwrap_or(&[]);
        let _ = ese_carver::reconstruct_fragment(prefix, suffix, expected);
    }
});
