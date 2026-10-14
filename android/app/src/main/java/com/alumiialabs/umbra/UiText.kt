package com.alumiialabs.umbra

import android.content.Context

/**
 * The strings of the resources of the app, for code that has no
 * composition. A composable reads them with `stringResource`. The app sets
 * the context at its start.
 */
object UiText {
    private var context: Context? = null

    fun start(context: Context) {
        this.context = context.applicationContext
    }

    /** The string of `id`, or an empty string before the start. */
    fun get(id: Int, vararg args: Any): String {
        val context = context ?: return ""
        // A string with no argument takes no format pass, thus a `%` in it stays.
        return if (args.isEmpty()) context.getString(id) else context.getString(id, *args)
    }

    /** The form of the plural `id` for `count`, or an empty string before the start. */
    fun plural(id: Int, count: Int, vararg args: Any): String =
        context?.resources?.getQuantityString(id, count, *args).orEmpty()
}
