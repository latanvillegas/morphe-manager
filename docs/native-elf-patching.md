# Native ELF patching — initial engine (experimental)

This fork now contains an **opt-in** native library patch engine in `patcher-core`. It runs **after** the existing DEX/resource APK writer and **before** the existing APK signer. The existing patcher, UI, split APK preparation, installers and patch bundles retain their previous behavior by default.

## Implemented

- `NativeLibraryPatch` describes one APK ZIP entry, its exact expected SHA-256, and one or more fixed-length byte edits at **ELF file offsets** (not AArch64 virtual addresses).
- `NativeLibraryPatcher` works with **ELF64 little-endian** `arm64-v8a` and `x86_64` shared libraries in **ZIP STORED entries without data descriptors**, with classic (non-ZIP64) directory metadata.
- Validates ELF machine type, entry identity, SHA-256 of the complete library, original bytes at every edit and overlapping edit ranges before writing any bytes.
- Uses streaming checksums. No need to hold a 215 MB Cromite `libchrome.so` in RAM.
- Preserves the byte length, native page alignment and ZIP structure by patching bytes in place, then updates local-header and central-directory CRC-32.
- Rejects encrypted or compressed entries, unsupported ZIP variants, unsupported architectures, mismatched versions, inconsistent CRCs, invalid edit lengths and missing libraries.
- `PatchRequest.nativeLibraryPatches` defaults to an empty list; when omitted, no native patching occurs. `PatchPipeline` passes the optional specs to `Session`; `Session` invokes the engine after `PatchResult.applyTo` and before moving the output APK.
- The manager already performs APK signing *after* the patching runtime returns, in `PatcherWorker.kt`.

## Not implemented yet

- No visible native patch editor or import screen and **no `.mpp` native patch definition format** yet: specs can presently only be supplied programmatically via `PatchRequest`.
- Does not discover instructions, analyze C++ symbols, understand branches/relocations or generate a function-specific patch automatically.
- Does not support ELF32, compressed `.so` files, ZIP64, variable-length modifications, rebuilding libraries, or bypassing anti-tamper checks.
- This change does **not** provide a working AMOLED `#000000` patch for Cromite. The renderer instruction bytes and corresponding file offsets remain unverified.

## Example specification (illustrative; not a Cromite patch)

```kotlin
NativeLibraryPatch(
    apkEntry = "lib/arm64-v8a/libexample.so",
    expectedSha256 = "<64 hex characters from original ELF>",
    edits = listOf(
        NativeByteEdit(
            offset = 0x1234L, // file offset, NOT ELF virtual address
            expectedHex = "11223344",
            replacementHex = "AABBCCDD"
        )
    )
)
```

Only use byte patches when the exact instruction encoding, replacement and ELF file offsets have been independently verified. A wrong native edit can crash the app.

## Testing performed

A standalone Kotlin/JVM smoke test passed using a synthetic `lib/arm64-v8a/libexample.so` inside a generated ZIP/APK: bytes changed; entry size and CRC remained valid. Four tests also passed with Kotlin's test assertions in a local harness (valid edit, wrong-hash refusal, deflated-entry refusal, default no-op). Full Android/Gradle build and device installation have **not yet been performed**.

## Rollout plan

1. Run the full Gradle test suite in CI on this branch; then test with a disposable APK on Android.
2. Add an explicit experimental UI workflow to import reviewed native patch specs and select an APK, plus dry-run previews.
3. Add the trusted `.mpp` native patch manifest/schema and enforce per-package/version/ABI selection.
4. Build native symbol/ELF analysis tooling using known Build IDs to compute correct file offsets.
5. For Cromite, locate verified Blink renderer instructions and preserve the 18 existing Morphe patches. Existing Claro/Oscuro/Sistema behavior and per-site ALLOW/BLOCK logic must remain authoritative.
