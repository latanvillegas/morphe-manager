package app.morphe.manager.patcher.native

import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.CRC32

/**
 * Version-pinned, in-place edits for uncompressed ELF libraries inside an unsigned APK.
 *
 * The ZIP layout (including native library page alignment) and entry sizes are preserved;
 * only selected bytes and the local/central CRC-32 fields are updated. This does NOT sign
 * the APK. It must run after other APK rewriting and before the manager's APK signer.
 *
 * Intentionally unsupported: deflated entries, ZIP64, data descriptors, encrypted entries,
 * non-ELF native libraries and edits that change size. All fail closed.
 */
object NativeLibraryPatcher {
    private const val LOCAL = 0x04034b50L
    private const val CENTRAL = 0x02014b50L
    private const val END = 0x06054b50L
    private const val STORED = 0
    private val entryPath = Regex("""lib/(arm64-v8a|x86_64)/[A-Za-z0-9_.+-]+\.so""")
    private val sha256 = Regex("[a-fA-F0-9]{64}")
    private val hex = Regex("(?:[a-fA-F0-9]{2})+")

    private data class ZipElf(
        val path: String,
        val dataOffset: Long,
        val size: Long,
        val crc: Long,
        val localCrcOffset: Long,
        val centralCrcOffset: Long
    )

    private data class CompiledEdit(val offset: Long, val before: ByteArray, val after: ByteArray)
    private data class Prepared(val entry: ZipElf, val edits: List<CompiledEdit>)

    /** Returns the number of edited libraries. No-op when [patches] is empty. */
    fun apply(apk: File, patches: List<NativeLibraryPatch>): Int {
        if (patches.isEmpty()) return 0
        require(patches.size <= 32) { "Too many native library patches" }
        require(patches.map { it.apkEntry }.distinct().size == patches.size) {
            "Each native library may be specified only once"
        }
        RandomAccessFile(apk, "rw").use { raf ->
            val entries = findEntries(raf, patches.map { it.apkEntry }.toSet())
            // Preflight ALL edits and libraries BEFORE changing any bytes.
            val prepared = patches.map { spec ->
                require(entryPath.matches(spec.apkEntry)) { "Unsupported native library path: ${spec.apkEntry}" }
                require(sha256.matches(spec.expectedSha256)) { "Native SHA-256 must be 64 hex characters" }
                require(spec.edits.isNotEmpty() && spec.edits.size <= 256) { "Invalid native edit count" }
                val entry = requireNotNull(entries[spec.apkEntry]) { "Missing native library: ${spec.apkEntry}" }
                verifyElf(raf, entry)
                val compiled = spec.edits.map { edit ->
                    val before = parseHex(edit.expectedHex)
                    val after = parseHex(edit.replacementHex)
                    require(before.size == after.size && before.size <= 4096) {
                        "Native edits must have equal nonzero lengths <= 4096"
                    }
                    require(edit.offset >= 0 && edit.offset <= entry.size - before.size) {
                        "Native edit offset outside ${entry.path}: ${edit.offset}"
                    }
                    CompiledEdit(edit.offset, before, after)
                }.sortedBy { it.offset }
                compiled.zipWithNext().forEach { (left, right) ->
                    require(left.offset + left.before.size <= right.offset) {
                        "Overlapping native edits in ${spec.apkEntry}"
                    }
                }
                val (actualHash, actualCrc) = checksum(raf, entry)
                require(actualHash.equals(spec.expectedSha256, ignoreCase = true)) {
                    "Native library SHA-256 mismatch: ${spec.apkEntry}"
                }
                require(actualCrc == entry.crc) { "Corrupt ZIP CRC: ${spec.apkEntry}" }
                for (edit in compiled) {
                    raf.seek(entry.dataOffset + edit.offset)
                    val original = ByteArray(edit.before.size)
                    raf.readFully(original)
                    require(original.contentEquals(edit.before)) {
                        "Native expected bytes mismatch in ${spec.apkEntry} at ${edit.offset}"
                    }
                }
                Prepared(entry, compiled)
            }
            for ((entry, edits) in prepared) {
                for (edit in edits) {
                    raf.seek(entry.dataOffset + edit.offset)
                    raf.write(edit.after)
                }
                val (_, crc) = checksum(raf, entry)
                raf.seek(entry.localCrcOffset)
                raf.writeU32(crc)
                raf.seek(entry.centralCrcOffset)
                raf.writeU32(crc)
            }
            raf.fd.sync()
        }
        return patches.size
    }

    private fun parseHex(value: String): ByteArray {
        require(value.length <= 8192 && hex.matches(value)) { "Invalid native edit hex" }
        return ByteArray(value.length / 2) { i ->
            value.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun verifyElf(raf: RandomAccessFile, entry: ZipElf) {
        require(entry.size >= 64) { "ELF library too short: ${entry.path}" }
        raf.seek(entry.dataOffset)
        val header = ByteArray(64)
        raf.readFully(header)
        require(header[0] == 0x7f.toByte() && header[1] == 'E'.code.toByte() &&
                header[2] == 'L'.code.toByte() && header[3] == 'F'.code.toByte() &&
                header[4] == 2.toByte() && header[5] == 1.toByte()) {
            "Only ELF64 little-endian is supported: ${entry.path}"
        }
        val machine = (header[18].toInt() and 255) or ((header[19].toInt() and 255) shl 8)
        val expectedMachine = when (entry.path.substringAfter("lib/").substringBefore('/')) {
            "arm64-v8a" -> 183 // EM_AARCH64
            "x86_64" -> 62 // EM_X86_64
            else -> error("Unsupported ELF architecture: ${entry.path}")
        }
        require(machine == expectedMachine) { "ELF architecture mismatch: ${entry.path}" }
    }

    private fun checksum(raf: RandomAccessFile, entry: ZipElf): Pair<String, Long> {
        raf.seek(entry.dataOffset)
        val digest = MessageDigest.getInstance("SHA-256")
        val crc = CRC32()
        val buf = ByteArray(64 * 1024)
        var left = entry.size
        while (left > 0) {
            val count = minOf(left, buf.size.toLong()).toInt()
            raf.readFully(buf, 0, count)
            digest.update(buf, 0, count)
            crc.update(buf, 0, count)
            left -= count
        }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) } to crc.value
    }

    private fun findEntries(raf: RandomAccessFile, targets: Set<String>): Map<String, ZipElf> {
        val tailLength = minOf(raf.length(), 65557L).toInt()
        require(tailLength >= 22) { "Not an APK ZIP" }
        val tailStart = raf.length() - tailLength
        raf.seek(tailStart)
        val tail = ByteArray(tailLength).also(raf::readFully)
        fun u16(pos: Int) = (tail[pos].toInt() and 255) or ((tail[pos + 1].toInt() and 255) shl 8)
        fun u32(pos: Int) = u16(pos).toLong() or (u16(pos + 2).toLong() shl 16)
        val eocd = (tailLength - 22 downTo 0).firstOrNull { index ->
            u32(index) == END && index + 22 + u16(index + 20) == tailLength
        } ?: error("ZIP end-of-central-directory not found")
        require(u16(eocd + 4) == 0 && u16(eocd + 6) == 0) { "Multi-disk ZIP unsupported" }
        val count = u16(eocd + 10)
        require(count == u16(eocd + 8) && count != 65535) { "ZIP64 / multi-disk unsupported" }
        val centralSize = u32(eocd + 12)
        val centralStart = u32(eocd + 16)
        require(centralStart != 0xffffffffL && centralSize != 0xffffffffL &&
                centralStart + centralSize <= tailStart + eocd) { "Unsupported ZIP central directory" }
        val result = mutableMapOf<String, ZipElf>()
        var cursor = centralStart
        repeat(count) {
            raf.seek(cursor)
            require(raf.readU32() == CENTRAL) { "Invalid ZIP central directory" }
            raf.seek(cursor + 8)
            val flags = raf.readU16()
            val method = raf.readU16()
            val crc = run { raf.seek(cursor + 16); raf.readU32() }
            val compressed = raf.readU32()
            val uncompressed = raf.readU32()
            val nameLength = raf.readU16()
            val extraLength = raf.readU16()
            val commentLength = raf.readU16()
            raf.seek(cursor + 42)
            val localOffset = raf.readU32()
            require(compressed != 0xffffffffL && uncompressed != 0xffffffffL &&
                    localOffset != 0xffffffffL) { "ZIP64 entry unsupported" }
            raf.seek(cursor + 46)
            val name = String(ByteArray(nameLength).also(raf::readFully), StandardCharsets.UTF_8)
            val next = cursor + 46 + nameLength + extraLength + commentLength
            require(next <= centralStart + centralSize) { "Corrupt ZIP directory bounds" }
            if (name in targets) {
                require(name !in result) { "Duplicate native library entry: $name" }
                require(flags and 0x0009 == 0 && method == STORED && compressed == uncompressed) {
                    "Only uncompressed, descriptor-free native libraries supported: $name"
                }
                raf.seek(localOffset)
                require(raf.readU32() == LOCAL) { "Invalid local ZIP header: $name" }
                raf.seek(localOffset + 6)
                require(raf.readU16() == flags && raf.readU16() == method) {
                    "ZIP local/central flags differ: $name"
                }
                raf.seek(localOffset + 14)
                require(raf.readU32() == crc) { "ZIP CRC fields differ: $name" }
                raf.seek(localOffset + 26)
                val localNameLength = raf.readU16()
                val localExtraLength = raf.readU16()
                raf.seek(localOffset + 30)
                val localName = String(ByteArray(localNameLength).also(raf::readFully), StandardCharsets.UTF_8)
                require(localName == name) { "ZIP local/central names differ: $name" }
                val dataStart = localOffset + 30 + localNameLength + localExtraLength
                require(dataStart + uncompressed <= centralStart && dataStart >= 0) {
                    "ZIP native data overlaps directory: $name"
                }
                result[name] = ZipElf(name, dataStart, uncompressed, crc, localOffset + 14, cursor + 16)
            }
            cursor = next
        }
        return result
    }

    private fun RandomAccessFile.readU16(): Int =
        readUnsignedByte() or (readUnsignedByte() shl 8)

    private fun RandomAccessFile.readU32(): Long =
        readU16().toLong() or (readU16().toLong() shl 16)

    private fun RandomAccessFile.writeU32(value: Long) {
        require(value in 0..0xffffffffL)
        write((value and 255).toInt())
        write(((value ushr 8) and 255).toInt())
        write(((value ushr 16) and 255).toInt())
        write(((value ushr 24) and 255).toInt())
    }
}
