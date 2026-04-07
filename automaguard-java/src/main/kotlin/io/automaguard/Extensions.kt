package io.automaguard

/**
 * Kotlin-idiomatic extension API for AutomaGuard.
 *
 * These extensions mirror the Java [PolicyEngine] surface but use Kotlin
 * conventions: nullable types, trailing-lambda callbacks, and `isDenied`
 * as a property rather than a method call.
 */

// ── PolicyResult extensions ───────────────────────────────────────────────────

/** `true` when the verdict is [Verdict.DENY]. */
val PolicyResult.isDenied: Boolean
    get() = verdict == Verdict.DENY

/** `true` when the verdict is [Verdict.ALLOW]. */
val PolicyResult.isAllowed: Boolean
    get() = verdict == Verdict.ALLOW

/** `true` when the verdict is [Verdict.AUDIT]. */
val PolicyResult.isAudited: Boolean
    get() = verdict == Verdict.AUDIT

/** `true` when the verdict is [Verdict.REDACT]. */
val PolicyResult.isRedacted: Boolean
    get() = verdict == Verdict.REDACT

// ── PolicyEngine extensions ───────────────────────────────────────────────────

/**
 * Evaluate an event using a Kotlin [Map] of fields and invoke [onDeny] if the
 * verdict is [Verdict.DENY].
 *
 * ```kotlin
 * engine.evaluate("tool_call", mapOf("tool_name" to "send_email")) {
 *     throw EnforcementException(it)
 * }
 * ```
 */
fun PolicyEngine.evaluate(
    eventType: String,
    fields: Map<String, Any?> = emptyMap(),
    onDeny: (PolicyResult) -> Unit = { throw EnforcementException(it) },
): PolicyResult {
    val result = evaluate(eventType, fields)
    if (result.isDenied) onDeny(result)
    return result
}

/**
 * Evaluate an event with no fields.
 *
 * ```kotlin
 * engine.evaluate("session_start")
 * ```
 */
fun PolicyEngine.evaluate(eventType: String): PolicyResult =
    evaluate(eventType, emptyMap<String, Any?>())
