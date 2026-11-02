package versola.sdk.browser

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

    /**
     * The activity that went to the background first: the one the tab opened over. Only it coming
     * back is the user returning from the tab; another activity of the host app resuming meanwhile
     * (a splash handing over, a deep-link screen) is not (`AUDIT C14`). Weak, so a detector that is
     * never disarmed pins no activity.
     */
    private var host: java.lang.ref.WeakReference<Activity>? = null

    /**
     * Set when the [host] is destroyed for a configuration change while the tab is up: the instance
     * that comes back is a new object of the same class, and is the host.
     */
    private var recreatedAs: Class<out Activity>? = null

    fun arm() {
        armed = true
        leftForeground = false
        host = null
        recreatedAs = null
        application.registerActivityLifecycleCallbacks(this)
    }

    fun disarm() {
        armed = false
        application.unregisterActivityLifecycleCallbacks(this)
    }

    override fun onActivityStopped(activity: Activity) {
        if (!armed) return
        if (!leftForeground) host = java.lang.ref.WeakReference(activity)
        leftForeground = true
    }

    override fun onActivityDestroyed(activity: Activity) {
        if (armed && activity.isChangingConfigurations && host?.get() === activity) {
            host = null
            recreatedAs = activity.javaClass
        }
    }

    override fun onActivityResumed(activity: Activity) {
        // The redirect receiver resuming is the success path, not a dismissal; and once a
        // redirect has been delivered every subsequent resume belongs to it.
        if (!armed || !leftForeground) return
        if (activity is VersolaRedirectActivity || RedirectDispatcher.redirectDelivered) return
        val expected = host?.get()
        val isHost = if (expected != null) activity === expected else recreatedAs?.let { it == activity.javaClass } == true
        if (!isHost) return
        armed = false
        onReturnedWithoutRedirect()
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?): Unit = Unit
    override fun onActivityStarted(activity: Activity): Unit = Unit
    override fun onActivityPaused(activity: Activity): Unit = Unit
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle): Unit = Unit
}
