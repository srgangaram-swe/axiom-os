#![no_main]

use libfuzzer_sys::fuzz_target;
use polytope_boot_elf::{KERNEL_BASE_ADDRESS, KERNEL_LOAD_LIMIT, MAX_LOAD_SEGMENTS, parse};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(elf) = parse(bytes) {
        let segments: Vec<_> = elf.segments().collect();
        assert!(!segments.is_empty());
        assert!(segments.len() <= usize::from(MAX_LOAD_SEGMENTS));
        assert!(segments.iter().all(|segment| {
            segment.physical_address() == segment.virtual_address()
                && segment.physical_address() >= KERNEL_BASE_ADDRESS
                && segment
                    .physical_address()
                    .checked_add(segment.memory_size())
                    .is_some_and(|end| end <= KERNEL_LOAD_LIMIT)
                && segment.file_size() <= segment.memory_size()
                && !(segment.flags().is_writable() && segment.flags().is_executable())
        }));
        assert!(segments.windows(2).all(|pair| {
            pair[0]
                .physical_address()
                .checked_add(pair[0].memory_size())
                .is_some_and(|end| end <= pair[1].physical_address())
        }));
        assert!(segments.iter().any(|segment| {
            segment.flags().is_executable()
                && elf.entry_point() >= segment.virtual_address()
                && elf.entry_point()
                    < segment
                        .virtual_address()
                        .checked_add(segment.memory_size())
                        .expect("validated segment end cannot overflow")
        }));
    }
});
