package org.umbra.app

import android.Manifest
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.ComposeView

class MainActivity : ComponentActivity() {

    /** IMP-055: the task snapshot of the platform holds this view. */
    private lateinit var cover: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app has one light theme, thus the bars take dark icons in each
        // mode of the system.
        val clear = Color.TRANSPARENT
        enableEdgeToEdge(SystemBarStyle.light(clear, clear), SystemBarStyle.light(clear, clear))
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
        val content = ComposeView(this).apply { setContent { UmbraApp() } }
        cover = View(this).apply {
            setBackgroundColor(getColor(R.color.surface))
            visibility = View.GONE
        }
        // The cover is a platform view and no composable, because the
        // platform takes the snapshot before a recomposition can run.
        val root = FrameLayout(this)
        root.addView(content, MATCH_PARENT, MATCH_PARENT)
        root.addView(cover, MATCH_PARENT, MATCH_PARENT)
        setContentView(root)
        if (savedInstanceState == null) takeInvitation(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeInvitation(intent)
    }

    /**
     * An invitation link from a tap or from a share goes to the view of the
     * link. That view opens it only at a tap of the user.
     */
    private fun takeInvitation(intent: Intent?) {
        val text = when (intent?.action) {
            Intent.ACTION_VIEW -> intent.dataString
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            else -> null
        } ?: return
        (INVITATION_LINK.find(text) ?: REUSABLE_LINK.find(text) ?: PROFILE_LINK.find(text))
            ?.let { Core.linkedInvitation = it.value }
    }

    private companion object {
        val INVITATION_LINK = Regex("""https://[A-Za-z0-9.-]+/i#[A-Za-z0-9_-]+""")

        // Part 4 §4.3.2: the address in the Crockford alphabet.
        val REUSABLE_LINK = Regex("""umbra://p/[0-9A-Za-z]{32}""")

        // Part 9 §9.3.1: the handle, then the fragment of its profile.
        val PROFILE_LINK = Regex("""umbra://h/[^\s#]+(%23|#)[0-9]+#[0-9A-Za-z]{26}""")
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
