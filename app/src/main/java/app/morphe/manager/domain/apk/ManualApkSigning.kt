/*
 * Copyright 2026 Morphe.
 * https://github.com/MorpheApp/morphe-manager
 *
 * See the included NOTICE file for GPLv3 Section 7 terms that apply to Morphe contributions.
 */
package app.morphe.manager.domain.apk

import android.content.Context
import android.net.Uri
import app.morphe.manager.domain.manager.KeystoreManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile

/**
 * Signs an APK selected through Android's document picker with Morphe's existing signing key.
 *
 * The source document is never written: its bytes are staged in app-private cache before signing.
 * Unlike the patcher worker this accepts a user-provided archive, so it validates the APK's ZIP
 * container and manifest first. Invalid or unsupported APKs can still be rejected by ApkSigner.
 *
 * Does not install, patch, overwrite the source APK, or alter existing signing preferences.
 */
suspend fun signSelectedApk(
    context: Context,
    keystoreManager: KeystoreManager,
    source: Uri,
    destination: Uri
) {
    if (source == destination) {
        throw IOException("The signed APK must be saved to a different document")
    }

    val app = context.applicationContext
    val staged = withContext(Dispatchers.IO) {
        File.createTempFile("morphe-manual-sign-", ".apk", app.cacheDir)
    }

    try {
        withContext(Dispatchers.IO) {
            val input = app.contentResolver.openInputStream(source)
                ?: throw IOException("Unable to read the selected APK")
            input.use { stream ->
                staged.outputStream().use { output -> stream.copyTo(output) }
            }

            // The selected file must be a complete APK, not an .apks/.xapk archive or a random ZIP.
            ZipFile(staged).use { zip ->
                if (zip.getEntry("AndroidManifest.xml") == null) {
                    throw IOException("The selected file is not an APK")
                }
            }
        }

        // Uses the same certificate as Morphe's automatic post-patch signing. ApkSigner may reject
        // malformed or unsupported third-party ZIPs; report failure rather than changing the source.
        keystoreManager.sign(staged)

        withContext(Dispatchers.IO) {
            val output = app.contentResolver.openOutputStream(destination, "wt")
                ?: throw IOException("Unable to create the signed APK")
            output.use { stream ->
                staged.inputStream().use { input -> input.copyTo(stream) }
            }
        }
    } finally {
        withContext(Dispatchers.IO) { staged.delete() }
    }
}
