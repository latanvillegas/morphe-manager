package app.morphe.manager.patcher.native

import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NativeLibraryPatcherTest {
    private val entryPath = "lib/arm64-v8a/libexample.so"

    private fun elf(): ByteArray = ByteArray(128).also {
        it[0] = 0x7f
        it[1] = 'E'.code.toByte()
        it[2] = 'L'.code.toByte()
        it[3] = 'F'.code.toByte()
        it[4] = 2 // ELF64
        it[5] = 1 // Little endian
        it[18] = 183.toByte() // AArch64
        it[19] = 0
        it[80] = 0x11
        it[81] = 0x22
        it[82] = 0x33
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun apk(data: ByteArray, stored: Boolean): File {
        val file = Files.createTempFile("native-elf-patcher", ".apk").toFile()
        ZipOutputStream(file.outputStream()).use { zip ->
            val entry = ZipEntry(entryPath)
            if (stored) {
                val crc = CRC32().apply { update(data) }
                entry.method = ZipEntry.STORED
                entry.size = data.size.toLong()
                entry.compressedSize = data.size.toLong()
                entry.crc = crc.value
            }
            zip.putNextEntry(entry)
            zip.write(data)
            zip.closeEntry()
        }
        return file
    }

    @Test fun patchesStoredLibraryAndRetainsValidZipCrc() {
        val original = elf()
        val apk = apk(original, stored = true)
        try {
            val patch = NativeLibraryPatch(entryPath, sha256(original),
                listOf(NativeByteEdit(80, "112233", "aabbcc")))
            assertEquals(1, NativeLibraryPatcher.apply(apk, listOf(patch)))
            ZipFile(apk).use { zip ->
                val result = zip.getInputStream(zip.getEntry(entryPath)).use { it.readBytes() }
                val expected = original.clone().also {
                    it[80] = 0xaa.toByte()
                    it[81] = 0xbb.toByte()
                    it[82] = 0xcc.toByte()
                }
                assertContentEquals(expected, result)
                assertEquals(CRC32().apply { update(expected) }.value, zip.getEntry(entryPath).crc)
            }
        } finally { apk.delete() }
    }

    @Test fun wrongHashFailsWithoutMutatingApk() {
        val original = elf()
        val apk = apk(original, stored = true)
        try {
            val before = apk.readBytes()
            assertFailsWith<IllegalArgumentException> {
                NativeLibraryPatcher.apply(apk, listOf(NativeLibraryPatch(
                    entryPath, "0".repeat(64), listOf(NativeByteEdit(80, "112233", "aabbcc")))))
            }
            assertContentEquals(before, apk.readBytes())
        } finally { apk.delete() }
    }

    @Test fun deflatedLibraryIsExplicitlyRejected() {
        val original = elf()
        val apk = apk(original, stored = false)
        try {
            assertFailsWith<IllegalArgumentException> {
                NativeLibraryPatcher.apply(apk, listOf(NativeLibraryPatch(
                    entryPath, sha256(original), listOf(NativeByteEdit(80, "112233", "aabbcc")))))
            }
        } finally { apk.delete() }
    }

    @Test fun existingPatchingRemainsNoOpByDefault() {
        assertEquals(0, NativeLibraryPatcher.apply(File("not-present.apk"), emptyList()))
    }
}
