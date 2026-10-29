package versola.oauth.core

/**
 * Marks wiring that is public only so another module of this repository can reach it: the
 * Versola facade's edge half, the conformance drivers, a test. It is not part of the SDK's
 * public API, carries no compatibility promise, and an app that opts in has said so in its
 * own source (architecture review 2026-10-12, F6).
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "Internal wiring of the Versola SDKs: no compatibility promise. Opt in only from a module of this repository.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
)
public annotation class VersolaInternalApi
