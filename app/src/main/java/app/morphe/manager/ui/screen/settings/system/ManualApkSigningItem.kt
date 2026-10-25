/*
 * Copyright 2026 Morphe.
 * https://github.com/MorpheApp/morphe-manager
 *
 * An opt-in standalone signing action. The normal patcher still signs automatically.
 */
package app.morphe.manager.ui.screen.settings.system

import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import app.morphe.manager.R
import app.morphe.manager.domain.manager.KeystoreManager
import app.morphe.manager.ui.screen.shared.SettingsItem
import app.morphe.manager.ui.screen.shared.ThemedIcon
import app.morphe.manager.ui.screen.shared.UserMessages
import app.morphe.manager.util.displayName
import app.morphe.manager.util.rememberAdaptiveFilePicker
import com.composables.icons.materialsymbols.MaterialSymbols
import com.composables.icons.materialsymbols.rounded.Key
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.koin.compose.koinInject

/**
 * Signs an existing APK using the same key the patching pipeline uses, without repatching it.
 *
 * The selected APK is NEVER modified: it is copied into private app cache, signed there, and only
 * then copied to the SAF destination. An unsuccessful operation attempts to delete the destination.
 * Signing a third-party APK does not authorize it to update an installed app: Android requires the
 * same signing certificate as the installation being replaced.
 */
@Composable
fun ManualApkSigningItem() {
    val context = LocalContext.current
    val resolver = context.contentResolver
    val keystore = koinInject<KeystoreManager>()
    val messages = koinInject<UserMessages>()
    val scope = rememberCoroutineScope()
    val savedText = stringResource(R.string.settings_apk_signing_manual_success)
    var sourceApk by remember { mutableStateOf<Uri?>(null) }
    var signing by remember { mutableStateOf(false) }

    val saveSignedApk = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")
    ) { target ->
        val source = sourceApk
        sourceApk = null
        if (source == null || target == null || signing) return@rememberLauncherForActivityResult

        signing = true
        scope.launch {
            var temporaryApk: File? = null
            var completed = false
            try {
                val apk = withContext(Dispatchers.IO) {
                    val temp = File.createTempFile("morphe_manual_sign_", ".apk", context.cacheDir)
                    try {
                        val input = resolver.openInputStream(source)
                            ?: throw IOException(context.getString(R.string.settings_apk_signing_manual_cannot_read))
                        input.use { stream ->
                            temp.outputStream().use { output -> stream.copyTo(output) }
                        }
                        ZipFile(temp).use { archive ->
                            if (archive.getEntry("AndroidManifest.xml") == null) {
                                throw IOException(context.getString(R.string.settings_apk_signing_manual_invalid))
                            }
                        }
                        temp
                    } catch (failure: Exception) {
                        temp.delete()
                        throw failure
                    }
                }
                temporaryApk = apk

                // Existing Morphe signing key, or Morphe's standard first-use key generation.
                // sign() runs its cryptographic work off the UI thread.
                keystore.sign(apk)

                withContext(Dispatchers.IO) {
                    val output = resolver.openOutputStream(target, "wt")
                        ?: throw IOException(context.getString(R.string.settings_apk_signing_manual_cannot_write))
                    output.use { stream ->
                        apk.inputStream().use { input -> input.copyTo(stream) }
                    }
                }
                completed = true
                messages.show(savedText)
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Exception) {
                Log.e("MorpheManualApkSign", "Failed to sign APK", failure)
                messages.show(
                    context.getString(
                        R.string.settings_apk_signing_manual_failure,
                        failure.localizedMessage ?: failure.javaClass.simpleName
                    ),
                    long = true
                )
            } finally {
                withContext(NonCancellable + Dispatchers.IO) {
                    temporaryApk?.delete()
                    if (!completed) {
                        // Some providers do not implement deleteDocument; a failed cleanup is
                        // harmless and should not mask the original signing error.
                        runCatching { DocumentsContract.deleteDocument(resolver, target) }
                    }
                }
                signing = false
            }
        }
    }

    val selectApk = rememberAdaptiveFilePicker(
        mimeTypes = arrayOf("application/vnd.android.package-archive", "application/octet-stream"),
        customPickerMimeTypes = arrayOf("application/vnd.android.package-archive", "application/octet-stream"),
        onResult = { uri ->
            if (uri == null || signing) return@rememberAdaptiveFilePicker
            val name = uri.displayName(resolver).orEmpty().substringAfterLast('/')
            val base = name.takeIf { it.endsWith(".apk", ignoreCase = true) }
                ?.dropLast(4)?.takeIf { it.isNotBlank() } ?: "application"
            sourceApk = uri
            saveSignedApk.launch("${base}-signed.apk")
        }
    )

    SettingsItem(
        onClick = { if (!signing) selectApk() },
        leadingContent = { ThemedIcon(icon = MaterialSymbols.Rounded.Key) },
        title = stringResource(R.string.settings_apk_signing_manual_title),
        subtitle = stringResource(
            if (signing) R.string.settings_apk_signing_manual_busy
            else R.string.settings_apk_signing_manual_description
        )
    )
}
