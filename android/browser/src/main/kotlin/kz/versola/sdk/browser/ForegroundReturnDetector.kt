package kz.versola.sdk.browser

import android.app.Activity
import android.app.Application
import android.os.Bundle

/**
 * Tells a user cancel from everything else.
 *
 * Android gives no callback for "the Custom Tab was dismissed". What it does give is the
 * host app's activity resuming again; if that happens while an authorization is outstanding
 * and no redirect has been delivered, the user closed the tab. This is the same signal
 * AppAuth's management activity reads from its own `onResume`, without requiring the
 * integrator to route the flow through an extra activity.
 *
 * `Application.ActivityLifecycleCallbacks` is framework API — no `androidx.lifecycle`
 * dependency is pulled in for one boolean.
 */
internal class ForegroundReturnDetector(
    private val application: Application,
    private val onReturnedWithoutRedirect: () -> Unit,
) : Application.ActivityLifecycleCallbacks {

    @Volatile
    private var armed = false

    /**
     * The host app must have gone to the background first. Without this, a resume that
     * arrives between arming and the tab actually appearing — a launch that failed, a
     * configuration change — would read as a dismissal the user never performed.
     */
    @Volatile
    private var leftForeground = false

    fun arm() {
        armed = true
        leftForeground = false
        application.registerActivityLifecycleCallbacks(this)
    }

    fun disarm() {
        armed = false
        application.unregisterActivityLifecycleCallbacks(this)
    }

    override fun onActivityStopped(activity: Activity) {
        if (armed) leftForeground = true
    }

    override fun onActivityResumed(activity: Activity) {
        // The redirect receiver resuming is the success path, not a dismissal; and once a
        // redirect has been delivered every subsequent resume belongs to it.
        if (!armed || !leftForeground) return
        if (activity is VersolaRedirectActivity || RedirectDispatcher.redirectDelivered) return
        armed = false
        onReturnedWithoutRedirect()
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?): Unit = Unit
    override fun onActivityStarted(activity: Activity): Unit = Unit
    override fun onActivityPaused(activity: Activity): Unit = Unit
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle): Unit = Unit
    override fun onActivityDestroyed(activity: Activity): Unit = Unit
}
