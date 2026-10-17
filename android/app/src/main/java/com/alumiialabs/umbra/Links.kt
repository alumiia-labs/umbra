package com.alumiialabs.umbra

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * The links of a message (Part 3 §3.10). The client fetches no link: the
 * user sees each URL before it opens (`NET-146`), a web link opens in the
 * browser of the platform, and an `umbra` link stays in the app (`NET-147`).
 */
object Links {
    private val SCHEMES = listOf("https://", "http://", "umbra:")

    /** A character that ends a link: a space, or the end of a sentence at the end. */
    private const val TRAILING = ".,;:!?)]}'\""

    /** The place of each link in the text, with no `String` of the text. */
    fun ranges(chars: CharArray): List<IntRange> {
        val out = mutableListOf<IntRange>()
        var at = 0
        while (at < chars.size) {
            val isStart = at == 0 || chars[at - 1].isWhitespace() || chars[at - 1] == '('
            val scheme = if (isStart) SCHEMES.firstOrNull { startsWith(chars, at, it) } else null
            if (scheme == null) {
                at++
                continue
            }

            var end = at
            while (end < chars.size && !chars[end].isWhitespace()) end++
            while (end > at + scheme.length && chars[end - 1] in TRAILING) end--
            if (end > at + scheme.length) out.add(at until end)
            at = end.coerceAtLeast(at + 1)
        }

        return out
    }

    private fun startsWith(chars: CharArray, at: Int, prefix: String): Boolean {
        if (at + prefix.length > chars.size) return false
        return prefix.indices.all { chars[at + it].lowercaseChar() == prefix[it] }
    }

    /** The text of each link, for the sheet that shows it before it opens. */
    fun of(chars: CharArray): List<String> = ranges(chars).map { String(chars, it.first, it.last - it.first + 1) }

    /**
     * Opens one link that the user chose. A link of the `umbra` scheme, and an
     * invitation link, go to the view of the link in the app, which opens
     * it at a tap. Each other link goes to the browser.
     */
    fun open(context: Context, url: String) {
        if (url.startsWith("umbra:", ignoreCase = true) || MainActivity.isInvitation(url)) {
            Core.linkedInvitation = url
            return
        }

        try {
            val view = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(view)
        } catch (missing: ActivityNotFoundException) {
            // No browser: the sheet showed the URL, and the user can copy it.
        }
    }
}
