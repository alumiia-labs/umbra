package org.umbra.app

import android.content.Context

/**
 * The strings that rules of the specification require (Part 14 §14.9.3),
 * from the resources of the app, for code that has no composition. The app
 * sets the context at its start.
 */
object UiText {
    private var context: Context? = null

    fun start(context: Context) {
        this.context = context.applicationContext
    }

    /** The string of `id`, or an empty string before the start. */
    fun get(id: Int, vararg args: Any): String = context?.getString(id, *args).orEmpty()
}
