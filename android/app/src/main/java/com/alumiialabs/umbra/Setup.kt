package com.alumiialabs.umbra

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/** A step of the setup that the chat list offers in one card. */
enum class SetupStep { Recovery, Battery }

object Setup {
    /**
     * The steps that wait, in the order of the setup view. The code of a
     * linked device is the code of the device that owns the backup, thus
     * the recovery step shows there alone.
     */
    fun pending(context: Context): List<SetupStep> = buildList {
        if (RecoveryPrompt.isDue(context) && Core.ownsChannels) add(SetupStep.Recovery)
        if (!Battery.isNoted && Battery.slowsDirect(context)) add(SetupStep.Battery)
    }
}

/**
 * The one card of the steps that wait. A stack of prompts weakens each one,
 * thus the steps share a card. The inbox stays open (`IDN-051`).
 */
@Composable
fun SetupPrompt(push: (Screen) -> Unit) {
    val count = Setup.pending(LocalContext.current).size
    if (count == 0) return

    PromptCard(onClick = { push(Screen.Setup) }) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FaIcon("check", size = 18.dp, tint = Palette.Action)
            Spacer(Modifier.width(14.dp))
            Text(stringResource(R.string.setup_finish), Modifier.weight(1f))
            Text(
                pluralStringResource(R.plurals.setup_left, count, count),
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
            )
            Spacer(Modifier.width(8.dp))
            FaIcon("chevron-right", size = 14.dp, tint = Palette.TextSecondary)
        }
    }
}

/**
 * One step at a time, each with a skip. A skip of the recovery step is one
 * of the two dismissals of `IDN-053`. The view closes after the last step.
 */
@Composable
fun SetupScreen(onBack: () -> Unit, push: (Screen) -> Unit) {
    val context = LocalContext.current
    val steps = Setup.pending(context)
    // The count at the open, thus a done step moves "1 of 2" to "2 of 2".
    val opened = remember { steps.size }
    val total = maxOf(opened, steps.size)
    val step = steps.firstOrNull()

    LaunchedEffect(step) {
        if (step == null) onBack()
    }
    if (step == null) return

    Column(Modifier.fillMaxSize()) {
        BackBar(stringResource(R.string.setup_title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp)) {
            Text(
                stringResource(R.string.setup_step, total - steps.size + 1, total),
                style = MaterialTheme.typography.labelMedium,
                color = Palette.TextSecondary,
            )
            Spacer(Modifier.height(16.dp))

            when (step) {
                SetupStep.Recovery -> {
                    HeroIcon("key")
                    Spacer(Modifier.height(24.dp))
                    Headline(
                        stringResource(R.string.recovery_write_down_code),
                        stringResource(R.string.setup_recovery_body),
                    )
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton(stringResource(R.string.setup_recovery_show)) { push(Screen.RecoveryCode) }
                    QuietButton(stringResource(R.string.setup_skip)) { RecoveryPrompt.dismiss(context) }
                }
                SetupStep.Battery -> {
                    HeroIcon("bell")
                    Spacer(Modifier.height(24.dp))
                    Headline(stringResource(R.string.setup_battery_title), batteryLine())
                    Spacer(Modifier.height(20.dp))
                    PrimaryButton(stringResource(R.string.battery_allow)) {
                        Battery.note(context)
                        Battery.open(context)
                    }
                    QuietButton(stringResource(R.string.setup_skip)) { Battery.note(context) }
                }
            }
        }
    }
}
