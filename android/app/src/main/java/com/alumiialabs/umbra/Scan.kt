package com.alumiialabs.umbra

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.camera2.Camera2Config
import androidx.camera.core.CameraSelector
import androidx.camera.core.CameraXConfig
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Observer
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.common.util.concurrent.ListenableFuture
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** The scanner view of an invitation. The link goes to the view below. */
@Composable
fun ScanInvitationScreen(onBack: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        BackBar("Scan code", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Headline("Scan their invitation")
            Spacer(Modifier.height(20.dp))
            Scanner { text ->
                Core.scannedInvitation = text
                onBack()
            }
            Spacer(Modifier.height(16.dp))
            SecondaryButton("Paste a link instead", onClick = onBack)
        }
    }
}

/**
 * The scanner view of a safety number. The two devices hold one number, thus
 * a scanned number that is equal to the number of this device verifies the
 * contact (`IDN-176`).
 */
@Composable
fun ScanSafetyNumberScreen(chat: Chat, onBack: () -> Unit) {
    var isMatch by remember { mutableStateOf<Boolean?>(null) }
    Column(Modifier.fillMaxSize()) {
        BackBar("Verify ${chat.title}", onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            when (isMatch) {
                null -> {
                    Headline("Scan the code of ${chat.title}")
                    Spacer(Modifier.height(20.dp))
                    Scanner { text -> Core.verifyByNumber(chat.conversation, text) { isMatch = it } }
                }
                true -> {
                    HeroIcon("shield-check")
                    Spacer(Modifier.height(20.dp))
                    Headline("You verified ${chat.title}.")
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton("Done", onClick = onBack)
                }
                false -> {
                    HeroIcon("triangle-exclamation")
                    Spacer(Modifier.height(20.dp))
                    // A user cannot know what a mismatch means.
                    Headline(
                        "The codes do not match.",
                        "Another party can be between you and ${chat.title}.",
                    )
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton("Scan again") { isMatch = null }
                }
            }
        }
    }
}

/**
 * The camera of the device in a frame, and the text of the first QR code
 * that it sees. The view asks for the camera when it opens and at no other
 * time. A frame stays on the device, and no part of the app stores it.
 */
@Composable
fun Scanner(onText: (String) -> Unit) {
    val context = LocalContext.current
    var isAllowed by remember {
        val state = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
        mutableStateOf(state == PackageManager.PERMISSION_GRANTED)
    }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { isAllowed = it }
    LaunchedEffect(Unit) { if (!isAllowed) ask.launch(Manifest.permission.CAMERA) }

    val frame = RoundedCornerShape(24.dp)
    Box(
        Modifier.fillMaxWidth().aspectRatio(1f).clip(frame).background(Palette.Container),
        contentAlignment = Alignment.Center,
    ) {
        if (isAllowed) {
            CameraFrames(onText)
            // The dashed square of the mockup, above the picture of the camera.
            Box(
                Modifier.fillMaxSize().padding(48.dp).drawBehind {
                    drawRoundRect(
                        Color.White,
                        cornerRadius = CornerRadius(20.dp.toPx()),
                        style = Stroke(
                            width = 2.dp.toPx(),
                            pathEffect = PathEffect.dashPathEffect(floatArrayOf(18f, 14f)),
                        ),
                    )
                },
            )
        } else {
            FaIcon("qrcode", size = 40.dp, tint = Palette.Action)
        }
    }
    if (!isAllowed) {
        Spacer(Modifier.height(12.dp))
        Note("UMBRA has no access to the camera.", isError = true)
        Spacer(Modifier.height(12.dp))
        PrimaryButton("Allow the camera") { ask.launch(Manifest.permission.CAMERA) }
    }
}

@Composable
private fun CameraFrames(onText: (String) -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val deliver by rememberUpdatedState(onText)
    val analysis = remember { Executors.newSingleThreadExecutor { Thread(it, "umbra-scan") } }
    val preview = remember {
        PreviewView(context).apply {
            // A texture view obeys the rounded clip of the frame.
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }
    var isStreaming by remember { mutableStateOf(false) }
    // The activity keeps a turn of the device, thus the camera takes the
    // new rotation of the display here.
    var bound by remember { mutableStateOf<Pair<Preview, ImageAnalysis>?>(null) }
    val orientation = LocalConfiguration.current.orientation
    LaunchedEffect(orientation, bound) {
        val rotation = preview.display?.rotation ?: return@LaunchedEffect
        bound?.let { (picture, frames) ->
            picture.targetRotation = rotation
            frames.targetRotation = rotation
        }
    }
    DisposableEffect(owner) {
        val main = Handler(Looper.getMainLooper())
        val isFound = AtomicBoolean(false)
        var isLeft = false
        val providers = backCameraProvider(context)
        providers.addListener({
            // The start of the camera can end after the user left the view.
            if (isLeft) return@addListener
            val picture = Preview.Builder().build().also { it.surfaceProvider = preview.surfaceProvider }
            val frames = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            frames.setAnalyzer(analysis) { image ->
                val text = image.use(::qrText)
                // One code serves one scan.
                if (text != null && isFound.compareAndSet(false, true)) main.post { deliver(text) }
            }
            val provider = providers.get()
            provider.unbindAll()
            provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, picture, frames)
            bound = picture to frames
        }, ContextCompat.getMainExecutor(context))
        val watcher = Observer<PreviewView.StreamState> { isStreaming = it == PreviewView.StreamState.STREAMING }
        preview.previewStreamState.observe(owner, watcher)
        onDispose {
            isLeft = true
            preview.previewStreamState.removeObserver(watcher)
            if (providers.isDone) providers.get().unbindAll()
            analysis.shutdown()
        }
    }
    // A preview with no frame is black. The ground of the frame shows until
    // the first picture is there.
    AndroidView({ preview }, Modifier.fillMaxSize().alpha(if (isStreaming) 1f else 0f))
}

private var isCameraConfigured = false

/**
 * The camera provider of the process. The scanner uses the back camera
 * alone, thus the start of CameraX looks for no other one. A device with no
 * front camera otherwise waits for several tries of that search.
 */
private fun backCameraProvider(context: Context): ListenableFuture<ProcessCameraProvider> {
    if (!isCameraConfigured) {
        isCameraConfigured = true
        val config = CameraXConfig.Builder.fromConfig(Camera2Config.defaultConfig())
            .setAvailableCamerasLimiter(CameraSelector.DEFAULT_BACK_CAMERA)
            .build()
        ProcessCameraProvider.configureInstance(config)
    }
    return ProcessCameraProvider.getInstance(context)
}

private val qrHints = mapOf(
    DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
    DecodeHintType.TRY_HARDER to true,
)

/** The text of a QR code in the luminance plane of a frame, or null. */
private fun qrText(image: ImageProxy): String? {
    val plane = image.planes[0]
    val bytes = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
    val source = PlanarYUVLuminanceSource(
        bytes, plane.rowStride, image.height, 0, 0, image.width, image.height, false,
    )
    return try {
        QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), qrHints).text
    } catch (none: NotFoundException) {
        null
    } catch (damaged: ReaderException) {
        null
    }
}
