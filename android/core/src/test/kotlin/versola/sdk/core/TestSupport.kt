package versola.sdk.core

/** `assertThrows` cannot take a suspending block; this can. */
internal suspend fun failure(block: suspend () -> Unit): Throwable =
    runCatching { block() }.exceptionOrNull() ?: throw AssertionError("expected a failure")
