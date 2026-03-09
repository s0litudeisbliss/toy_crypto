# toy_crypto

Toy / proof-of-concept implementations of various cryptographic schemes,
written in Rust.

> **Educational purposes only.** None of the code here is production-safe.

---

## Repository layout

```
toy_crypto/
├── Cargo.toml          # workspace root – lists every crate
└── crates/
    └── caesar/         # Caesar-cipher blueprint
        ├── Cargo.toml
        └── src/
            └── lib.rs
```

Each cryptographic scheme lives in its own crate under `crates/`.

---

## Prerequisites

* [Rust toolchain](https://rustup.rs/) (stable, 2021 edition or later)

---

## Building

```bash
# build every crate in the workspace
cargo build --workspace

# build a single crate
cargo build -p caesar
```

## Testing

```bash
# test every crate
cargo test --workspace

# test a single crate
cargo test -p caesar
```

---

## Adding a new scheme

1. Create a new crate under `crates/`:

   ```bash
   cargo new --lib crates/<scheme_name>
   ```

2. Add the new path to the `members` list in the root `Cargo.toml`:

   ```toml
   [workspace]
   members = [
       "crates/caesar",
       "crates/<scheme_name>",   # ← add this line
   ]
   ```

3. Implement your scheme in `crates/<scheme_name>/src/lib.rs` and add
   `#[cfg(test)]` unit tests alongside the implementation (see
   `crates/caesar/src/lib.rs` for the pattern).

---

## Implemented schemes

| Crate | Scheme | Notes |
|-------|--------|-------|
| `caesar` | [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) | Blueprint / hello-world |
