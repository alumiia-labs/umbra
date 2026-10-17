package com.alumiialabs.umbra

import android.Manifest
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.ComposeView
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    /** IMP-055: the task snapshot of the platform holds this view. */
    private lateinit var cover: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Appearances.start(this)
        UiText.start(this)
        Notifier.makeChannels(this)
        // NTF-052: a network change draws a new phase of the Private clock.
        Modes.watchNetwork(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // With no permission the app shows no alert, and it takes each
            // record all the same.
            registerForActivityResult(ActivityResultContracts.RequestPermission()) {}
                .launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }

        val content = ComposeView(this).apply { setContent { NoPersonalizedLearning { UmbraApp() } } }
        // The cover is a platform view and no composable, because the
        // platform takes the snapshot before a recomposition can run.
        cover = View(this).apply { visibility = View.GONE }
        paintWindow(Appearances.isDark)
        lifecycleScope.launch { snapshotFlow { Appearances.isDark }.collect(::paintWindow) }

        val root = FrameLayout(this)
        // No autofill service reads a view of the app. A service that sees
        // the passphrase field offers to keep the passphrase in an account
        // outside the device. No content capture service reads message text.
        root.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            root.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        }
        root.addView(content, MATCH_PARENT, MATCH_PARENT)
        root.addView(cover, MATCH_PARENT, MATCH_PARENT)
        setContentView(root)

        if (savedInstanceState == null) takeInvitation(intent)
    }

    // A choice in a sheet changes the look while the sheet holds the focus,
    // and the bars then keep the look of the sheet. The window paints them
    // again when it takes the focus back.
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) paintWindow(Appearances.isDark)
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        Appearances.follow(newConfig)
    }

    /**
     * The bars take icons that show on the ground of the app, and the window
     * and the cover take that ground, in the light and in the dark look.
     */
    private fun paintWindow(isDark: Boolean) {
        val clear = Color.TRANSPARENT
        val style = if (isDark) SystemBarStyle.dark(clear) else SystemBarStyle.light(clear, clear)
        enableEdgeToEdge(style, style)

        val ground = Palette.Surface.toArgb()
        window.setBackgroundDrawable(ColorDrawable(ground))
        cover.setBackgroundColor(ground)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeInvitation(intent)
    }

    /**
     * An invitation link from a tap or from a share goes to the view of the
     * link. That view opens it only at a tap of the user. Each app of the
     * device can send this intent, thus the link alone starts no lookup and
     * no request.
     */
    private fun takeInvitation(intent: Intent?) {
        // Each app can send this intent, and a crafted extra throws at the
        // read. A styled text is a CharSequence and no String.
        val text = try {
            when (intent?.action) {
                Intent.ACTION_VIEW -> intent.dataString
                Intent.ACTION_SEND -> intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                else -> null
            }
        } catch (fault: RuntimeException) {
            null
        } ?: return
        if (text.length > LINK_TEXT_MAX) return

        val link = INVITATION_LINK.find(text)?.value
            ?: REUSABLE_LINK.find(text)?.value
            ?: PROFILE_LINK.find(text)?.takeIf { isHandleName(it.groupValues[1]) }?.value
        link?.let { Core.linkedInvitation = it }
    }

    companion object {
        /** Whether a web link is an invitation link of this app (Part 4 §4.3). */
        fun isInvitation(url: String) = INVITATION_LINK.matches(url)

        private val INVITATION_LINK = Regex("""https://[A-Za-z0-9.-]+/i#[A-Za-z0-9_-]+""")

        // Part 4 §4.3.2: the address in the Crockford alphabet.
        private val REUSABLE_LINK = Regex("""umbra://p/[0-9A-Za-z]{32}""")

        // Part 9 §9.3.1 and `DIS-179`: the name, a discriminator of 2 to 9
        // digits, then the fragment of the profile.
        private val PROFILE_LINK = Regex("""umbra://h/([^\s#%/?@]{1,32})(?:%23|#)[0-9]{2,9}#[0-9A-Za-z]{26}""")

        /** The longest text of an intent that the app reads for a link. */
        private const val LINK_TEXT_MAX = 4_096

        /**
         * Whether the `name` part of a handle from outside the app can show
         * in a view. The name holds at most 32 bytes (`DIS-090`), and letters,
         * digits, marks, and punctuation alone. A control character, a format
         * character such as a change of the text direction, and a code point
         * with no letter never show. The core applies the whole profile of
         * `DIS-088` at the lookup.
         */
        private fun isHandleName(name: String): Boolean {
            if (name.toByteArray(Charsets.UTF_8).size > 32) return false

            return name.codePoints().allMatch { point ->
                when (Character.getType(point).toByte()) {
                    Character.CONTROL, Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE,
                    Character.UNASSIGNED, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
                    Character.SPACE_SEPARATOR,
                    -> false
                    else -> true
                }
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        Core.touched()
    }

    override fun onStart() {
        super.onStart()
        Core.visible(this, true)
    }

    override fun onStop() {
        Core.visible(this, false)
        super.onStop()
    }

    override fun onPause() {
        cover.visibility = View.VISIBLE
        super.onPause()
    }

    override fun onResume() {
        super.onResume()
        cover.visibility = View.GONE
    }
}
