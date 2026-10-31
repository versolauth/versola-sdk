package versola.oauth.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Where the SDK runs its own blocking work: the token request, discovery and key-set fetches, the
 * files its caches keep, DataStore, the Keystore's wrap, unwrap and sign, and pushed authorization.
 * Every one of those uses this and none uses `Dispatchers.IO` directly (`.claude/rules/android-kotlin.md`).
 *
 * **Why not `Dispatchers.IO`.** The authenticated client blocks the calling thread while a token
 * is refreshed (an OkHttp interceptor cannot suspend), and an app is free to make that call from
 * its own coroutines on `Dispatchers.IO`. With 64 callers waiting on one refresh, every thread of
 * that dispatcher's default view is parked in the interceptor, and a refresh whose own work was
 * dispatched there would wait for a thread that none of them will ever give back: the process
 * hangs. The work the callers wait for must not depend on a thread the callers occupy.
 *
 * **Why this works.** `Dispatchers.IO.limitedParallelism(n)` is a view with a quota of its own, and
 * on `Dispatchers.IO` that quota is not taken out of the 64 threads of the default view: the view
 * is cut from the unlimited IO scheduler, whose threads are created as blocking work needs them
 * (kotlinx-coroutines 1.11.0: `DefaultIoScheduler.limitedParallelism` delegates to
 * `UnlimitedIoScheduler`, and `SdkDispatchersTest` and the saturation tests prove it by holding every
 * thread of `Dispatchers.IO` and running the SDK's work anyway). Nothing is lost by sharing the pool:
 * it is the same threads, and it is simply allowed to grow past what the app has parked.
 *
 * **Why 64.** It is a ceiling, not a target. What the SDK has in flight at one time is small: one
 * refresh (single-flight) with its token request, a discovery or key-set fetch, a storage read or
 * write, a DPoP proof, a handful in all, so the quota is never what a caller waits on. The network
 * calls of many concurrent authenticated requests are not counted here at all: OkHttp runs those on
 * the caller's own thread, or on its own dispatcher for `enqueue`. 64 is the size `Dispatchers.IO`
 * gives its default view; a lower value would be a trap the day a facade fans out, a higher one
 * buys nothing.
 *
 * Only a scheduling choice: it changes which thread runs a block and never what the block does, in
 * what order, or how it is cancelled.
 */
@VersolaInternalApi
public object SdkDispatchers {
    /** The dispatcher for the SDK's own blocking work. See the class comment before using another. */
    public val blocking: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(QUOTA)

    /**
     * Where a facade parks the threads of the calls it blocks for their whole duration
     * (`OAuthClient.call()`: OkHttp's `execute()`, and inside it the interceptor waiting for the
     * access token). **Never [blocking]**: those threads wait for work that runs on [blocking], and
     * 64 of them would take its whole quota, leaving the refresh they wait for no thread to run on.
     * A view of its own keeps the two quotas apart, and keeps those calls out of the 64 threads of
     * `Dispatchers.IO` that the app's own work (a database, a file) shares.
     */
    public val blockedCalls: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(QUOTA)

    private const val QUOTA = 64
}
