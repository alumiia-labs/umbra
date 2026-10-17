package com.alumiialabs.umbra

import android.graphics.Bitmap
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The side of a picture that the user can change, in dp. */
const val EDITABLE_PICTURE_SIZE = 104

/** The space between the frame of a crop and the edge of the screen. */
private val CROP_MARGIN = 24.dp

/**
 * A picture with an edit mark at its corner: the picture of the profile or
 * the picture that the user gave a contact. A press opens a sheet. A new
 * picture goes through the picker and a crop before [onSet] gets it, and a
 * removal gives [onSet] null.
 */
@Composable
fun EditablePicture(hasPicture: Boolean, onSet: (Bitmap?) -> Unit, picture: @Composable () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var isChoosing by remember { mutableStateOf(false) }
    var cropping by remember { mutableStateOf<Bitmap?>(null) }

    // The picker gives this app the picked image alone (DIS-195).
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { picked ->
        if (picked != null) {
            scope.launch {
                val image = withContext(Dispatchers.Default) { Photos.forCrop(context.applicationContext, picked) }
                if (image == null) Core.fault = UiText.get(R.string.picture_did_not_open) else cropping = image
            }
        }
    }

    Box(
        Modifier.press(role = Role.Button, label = stringResource(R.string.picture_edit_picture)) { isChoosing = true },
    ) {
        Box(Modifier.clip(CircleShape)) { picture() }
        Text(
            stringResource(R.string.picture_edit),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = Palette.OnAction,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .offset(x = 4.dp, y = 2.dp)
                // A ring of the ground keeps the mark apart from the picture.
                .border(2.dp, Palette.Surface, CircleShape)
                .padding(2.dp)
                .background(Palette.Action, CircleShape)
                .padding(horizontal = 10.dp, vertical = 3.dp),
        )
    }

    if (isChoosing) {
        ActionSheet(
            stringResource(R.string.picture_picture),
            buildList {
                add(
                    RowEntry("image", stringResource(R.string.picture_choose_picture)) {
                        Core.awaitsResult()
                        picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                    },
                )
                if (hasPicture) add(RowEntry("trash-can", stringResource(R.string.picture_remove_picture)) { onSet(null) })
            },
            onDismiss = { isChoosing = false },
        )
    }

    cropping?.let { image ->
        CropDialog(
            image,
            onDone = { square ->
                cropping = null
                onSet(square)
            },
            onCancel = { cropping = null },
        )
    }
}

/**
 * The crop of a picked image: the user moves and scales the image under a
 * round frame. The frame starts on the center square. [onDone] gets a copy
 * of the square, and the image is erased when the dialog leaves.
 */
@Composable
private fun CropDialog(image: Bitmap, onDone: (Bitmap) -> Unit, onCancel: () -> Unit) {
    // The last frame of the dialog can draw the image after a press of
    // Done, thus the erase waits for the dialog to leave.
    DisposableEffect(image) {
        onDispose {
            image.eraseColor(0)
            image.recycle()
        }
    }

    Dialog(
        onDismissRequest = onCancel,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false,
            // IMP-055: the dialog is a window of its own, as a sheet is.
            securePolicy = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                SecureFlagPolicy.SecureOn
            } else {
                SecureFlagPolicy.Inherit
            },
        ),
    ) {
        val shown = remember(image) { image.asImageBitmap() }
        val width = image.width.toFloat()
        val height = image.height.toFloat()

        BoxWithConstraints(Modifier.fillMaxSize().background(Color.Black)) {
            val frame = with(LocalDensity.current) { (minOf(maxWidth, maxHeight) - CROP_MARGIN * 2).toPx() }

            // The frame shows no pixel outside the image, and no zoom makes
            // a square smaller than the largest picture.
            val scaleMin = frame / minOf(width, height)
            val scaleMax = maxOf(scaleMin, frame / Photos.PICTURE_SIDE_MAX)
            var scale by remember(frame) { mutableFloatStateOf(scaleMin) }

            // The point of the image at the center of the frame.
            var centerX by remember(frame) { mutableFloatStateOf(width / 2) }
            var centerY by remember(frame) { mutableFloatStateOf(height / 2) }
            fun keepFrameInside() {
                val half = frame / scale / 2
                centerX = centerX.coerceIn(half, width - half)
                centerY = centerY.coerceIn(half, height - half)
            }

            Canvas(
                Modifier.fillMaxSize().pointerInput(frame) {
                    detectTransformGestures { centroid, pan, zoom, _ ->
                        val middle = Offset(size.width / 2f, size.height / 2f)
                        // The point under the fingers stays under them.
                        val heldX = centerX + (centroid.x - middle.x) / scale
                        val heldY = centerY + (centroid.y - middle.y) / scale

                        scale = (scale * zoom).coerceIn(scaleMin, scaleMax)
                        centerX = heldX - (centroid.x - middle.x) / scale - pan.x / scale
                        centerY = heldY - (centroid.y - middle.y) / scale - pan.y / scale
                        keepFrameInside()
                    }
                },
            ) {
                val middle = center
                drawImage(
                    shown,
                    dstOffset = IntOffset(
                        (middle.x - centerX * scale).toInt(),
                        (middle.y - centerY * scale).toInt(),
                    ),
                    dstSize = IntSize((width * scale).toInt(), (height * scale).toInt()),
                    filterQuality = FilterQuality.High,
                )

                val hole = Rect(middle, frame / 2)
                val shade = Path().apply {
                    fillType = PathFillType.EvenOdd
                    addRect(Rect(Offset.Zero, size))
                    addOval(hole)
                }
                drawPath(shade, Color.Black.copy(alpha = 0.6f))
                drawCircle(Color.White, radius = frame / 2, center = middle, style = Stroke(1.5.dp.toPx()))
            }

            Row(
                Modifier
                    .align(Alignment.TopStart)
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .padding(start = 4.dp, end = 12.dp, top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier
                        .size(48.dp)
                        .clip(CircleShape)
                        .press(role = Role.Button, label = stringResource(R.string.common_cancel), onClick = onCancel),
                    contentAlignment = Alignment.Center,
                ) { FaIcon("xmark", label = stringResource(R.string.common_cancel), size = 20.dp, tint = Color.White) }
                Spacer(Modifier.weight(1f))
            }

            Text(
                stringResource(R.string.common_done),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = Palette.OnAction,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .navigationBarsPadding()
                    .padding(bottom = 24.dp)
                    .clip(CircleShape)
                    .background(Palette.Action)
                    .press(role = Role.Button, label = stringResource(R.string.common_done)) {
                        val side = (frame / scale).toInt().coerceIn(1, minOf(image.width, image.height))
                        val left = (centerX - side / 2f).toInt().coerceIn(0, image.width - side)
                        val top = (centerY - side / 2f).toInt().coerceIn(0, image.height - side)
                        onDone(Bitmap.createBitmap(image, left, top, side, side))
                    }
                    .padding(horizontal = 32.dp, vertical = 12.dp),
            )
        }
    }
}
