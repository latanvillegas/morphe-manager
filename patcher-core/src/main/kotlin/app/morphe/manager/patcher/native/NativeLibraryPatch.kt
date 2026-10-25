package app.morphe.manager.patcher.native

import kotlinx.serialization.Serializable

/** A guarded, equal-length ELF byte edit. [offset] is an ELF FILE offset, not a virtual address. */
@Serializable
data class NativeByteEdit(
    val offset: Long,
    val expectedHex: String,
    val replacementHex: String
)

/**
 * Exact-version patch for one ELF in an APK. A full SHA-256 pin is mandatory: no fuzzy
 * matching, heuristics, or modifications of unexpected native binaries.
 *
 * This is an advanced programmatic patch specification. The UI and .mpp patch-bundle
 * integration are separate work; no native edits are performed unless explicitly requested.
 */
@Serializable
data class NativeLibraryPatch(
    val apkEntry: String,
    val expectedSha256: String,
    val edits: List<NativeByteEdit>
)
