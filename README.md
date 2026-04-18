# rpf-archive

Rust library for reading and writing Rockstar Games archive formats — RPF (Rockstar Package File) and IMG — across GTA III through Red Dead Redemption 2.

## Supported formats

| Version | Game(s) | Magic |
|---------|---------|-------|
| IMG1 | GTA III, Vice City | *(none — paired `.dir`+`.img`)* |
| IMG2 | GTA San Andreas | `VER2` |
| IMG3 | RAGE / modding tools | `0xA94E2A52` |
| RPF0 | Table Tennis | `RPF0` |
| RPF2 | GTA IV | `RPF2` |
| RPF3 | GTA IV Audio / MCLA | `RPF3` |
| RPF4 | Max Payne 3 | `RPF4` |
| RPF6 | Red Dead Redemption | `RPF6` |
| RPF7 | GTA V / FiveM | `RPF7` |
| RPF8 | Red Dead Redemption 2 | `RPF8` *(read-only)* |

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
rpf-archive = "0.7"
```

### Reading an RPF archive (RPF2–RPF7)

```rust
use rpf_archive::RpfFile;

let file = RpfFile::open("update.rpf".as_ref(), None)?;

file.walk(None, &mut |path, data| {
    println!("{} ({} bytes)", path, data.len());
})?;
```

### Reading a GTA V archive with encryption

```rust
use rpf_archive::{GtaKeys, RpfFile};

let keys = GtaKeys::load("gta5keys.bin")?;
let file = RpfFile::open("x64a.rpf".as_ref(), Some(&keys))?;
```

### Reading an IMG v2 archive (GTA San Andreas)

```rust
use rpf_archive::RpfFile;

let file = RpfFile::open("gta3.img".as_ref(), None)?;

file.walk(None, &mut |path, data| {
    println!("{}", path);
})?;
```

### Reading an IMG v1 archive (GTA III / Vice City)

```rust
use rpf_archive::RpfFile;

let file = RpfFile::open_img1("gta3.img".as_ref(), "gta3.dir".as_ref())?;

file.walk(None, &mut |path, data| {
    println!("{}", path);
})?;
```

### Building an RPF7 archive (GTA V)

```rust
use rpf_archive::{RpfBuilder, RpfEncryption};

let mut builder = RpfBuilder::new(RpfEncryption::Open);
builder.add_file("data/foo.ydr", my_bytes);
builder.add_file("data/bar.ytd", other_bytes);

let bytes = builder.build(None)?;
std::fs::write("output.rpf", bytes)?;
```

### Building an IMG v2 archive (GTA San Andreas)

```rust
use rpf_archive::{RpfBuilder, RpfEncryption, RpfVersion};

let mut builder = RpfBuilder::for_version(RpfVersion::Img2, RpfEncryption::None);
builder.add_file("vehicle.dff", dff_bytes);
builder.add_file("vehicle.txd", txd_bytes);

let bytes = builder.build(None)?;
std::fs::write("mod.img", bytes)?;
```

### Building an IMG v1 archive (GTA III / Vice City)

```rust
use rpf_archive::{RpfBuilder, RpfEncryption, RpfVersion};

let mut builder = RpfBuilder::for_version(RpfVersion::Img1, RpfEncryption::None);
builder.add_file("player.dff", dff_bytes);

let (dir_data, img_data) = builder.build_img1_pair()?;
std::fs::write("player.dir", dir_data)?;
std::fs::write("player.img", img_data)?;
```

### Directory tree

```rust
use rpf_archive::{RpfFile, build_directory_tree};

let file = RpfFile::open("update.rpf".as_ref(), None)?;
let tree = build_directory_tree(&file.archive);
```

## License

MIT
