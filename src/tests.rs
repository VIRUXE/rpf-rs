#[cfg(test)]
mod writer_tests {
    use crate::archive::{RpfArchive, RpfEncryption, RpfVersion};
    use crate::writer::RpfBuilder;

    const FILES: &[(&str, &[u8])] = &[
        ("hello.txt",              b"Hello, world!"),
        ("subdir/data.bin",        &[0xDE, 0xAD, 0xBE, 0xEF]),
        ("subdir/nested/deep.bin", b"deep file content here"),
    ];

    fn roundtrip_version(version: RpfVersion, archive_name: &str) {
        let mut builder = RpfBuilder::for_version(version, RpfEncryption::None);
        for (path, data) in FILES {
            builder.add_file(path, data.to_vec());
        }

        let bytes = builder.build(None).expect("build failed");
        let archive = RpfArchive::parse(&bytes, archive_name, None).expect("parse failed");

        assert_eq!(
            archive.entries.iter().filter(|e| e.is_file()).count(),
            FILES.len(),
            "{archive_name}: wrong file count"
        );

        // For V3 names are hashes — skip name checks, just verify count and extraction
        if version != RpfVersion::V3 {
            let names: Vec<&str> = archive.entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"hello.txt"),  "{archive_name}: missing hello.txt");
            assert!(names.contains(&"data.bin"),   "{archive_name}: missing data.bin");
            assert!(names.contains(&"deep.bin"),   "{archive_name}: missing deep.bin");
        }

        // Verify extraction of every file
        for (path, expected) in FILES {
            let fname = std::path::Path::new(path).file_name().unwrap().to_str().unwrap();
            let entry = archive.entries.iter().find(|e| {
                if version == RpfVersion::V3 { e.is_file() && true } // just pick any file
                else { e.name == fname }
            });
            if version != RpfVersion::V3 {
                let entry = entry.expect(&format!("{archive_name}: entry {fname} not found"));
                let extracted = archive.extract_entry(&bytes, entry, None)
                    .expect(&format!("{archive_name}: extract {fname} failed"));
                assert_eq!(extracted.as_slice(), *expected,
                    "{archive_name}: content mismatch for {fname}");
            }
        }
    }

    fn roundtrip_v3_extraction(archive_name: &str) {
        let mut builder = RpfBuilder::for_version(RpfVersion::V3, RpfEncryption::None);
        for (path, data) in FILES {
            builder.add_file(path, data.to_vec());
        }
        let bytes = builder.build(None).expect("build failed");
        let archive = RpfArchive::parse(&bytes, archive_name, None).expect("parse failed");

        // Extract each file by position (names are hashes in V3)
        let file_entries: Vec<_> = archive.entries.iter().filter(|e| e.is_file()).collect();
        assert_eq!(file_entries.len(), FILES.len());
        for (i, (_, expected)) in FILES.iter().enumerate() {
            let extracted = archive.extract_entry(&bytes, file_entries[i], None)
                .expect("V3 extract failed");
            assert_eq!(extracted.as_slice(), *expected, "V3 content mismatch at index {i}");
        }
    }

    #[test]
    fn roundtrip_v0()   { roundtrip_version(RpfVersion::V0,   "test.rpf"); }

    #[test]
    fn roundtrip_v2()   { roundtrip_version(RpfVersion::V2,   "test.rpf"); }

    #[test]
    fn roundtrip_v3()   { roundtrip_v3_extraction("test.rpf"); }

    #[test]
    fn roundtrip_v4()   { roundtrip_version(RpfVersion::V4,   "test.rpf"); }

    #[test]
    fn roundtrip_v6()   { roundtrip_version(RpfVersion::V6,   "test.rpf"); }

    #[test]
    fn roundtrip_img3() { roundtrip_version(RpfVersion::Img3, "test.img"); }

    #[test]
    fn roundtrip_v7_open() {
        let mut builder = RpfBuilder::new(RpfEncryption::Open);
        for (path, data) in FILES {
            builder.add_file(path, data.to_vec());
        }
        let bytes = builder.build(None).expect("build failed");
        let archive = RpfArchive::parse(&bytes, "test.rpf", None).expect("parse failed");
        assert_eq!(archive.entries.iter().filter(|e| e.is_file()).count(), FILES.len());
        let entry = archive.entries.iter().find(|e| e.name == "hello.txt").unwrap();
        let extracted = archive.extract_entry(&bytes, entry, None).unwrap();
        assert_eq!(extracted.as_slice(), b"Hello, world!");
    }

    #[test]
    fn roundtrip_v7_none() {
        let mut builder = RpfBuilder::new(RpfEncryption::None);
        for (path, data) in FILES {
            builder.add_file(path, data.to_vec());
        }
        let bytes = builder.build(None).expect("build failed");
        let archive = RpfArchive::parse(&bytes, "test.rpf", None).expect("parse failed");
        assert_eq!(archive.entries.iter().filter(|e| e.is_file()).count(), FILES.len());
    }

    #[test]
    fn empty_archive() {
        let builder = RpfBuilder::new(RpfEncryption::Open);
        let bytes = builder.build(None).expect("build failed");
        let archive = RpfArchive::parse(&bytes, "empty.rpf", None).expect("parse failed");
        assert_eq!(archive.entries.len(), 1); // root dir only
    }
}
