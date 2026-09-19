package org.umbra.app

import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.compose.ui.platform.ComposeView

class MainActivity : ComponentActivity() {

    /** IMP-055: the task snapshot of the platform holds this view. */
    private lateinit var cover: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }
        val content = ComposeView(this).apply { setContent { UmbraApp() } }
        cover = View(this).apply {
            setBackgroundColor(Color.BLACK)
            visibility = View.GONE
        }
        // The cover is a platform view and no composable, because the
        // platform takes the snapshot before a recomposition can run.
        val root = FrameLayout(this)
        root.addView(content, MATCH_PARENT, MATCH_PARENT)
        root.addView(cover, MATCH_PARENT, MATCH_PARENT)
        setContentView(root)
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
