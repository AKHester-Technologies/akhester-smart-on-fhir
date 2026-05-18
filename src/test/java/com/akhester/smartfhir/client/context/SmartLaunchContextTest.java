package com.akhester.smartfhir.client.context;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartLaunchContext helper methods.
 *
 * Test cases:
 *  1.  hasEncounter() — true when encounter is present.
 *  2.  hasEncounter() — false when encounter is null.
 *  3.  hasEncounter() — false when encounter is blank.
 *  4.  isTokenExpired() — false for a token expiring in the future.
 *  5.  isTokenExpired() — true for an already-expired token.
 *  6.  isTokenExpired(buffer) — true when within buffer window.
 *  7.  hasScope() — true when scope was granted.
 *  8.  hasScope() — false when scope was not granted.
 *  9.  hasScope() — false when scope is null.
 *  10. hasScope() — matches exact scope string (no partial match).
 *  11. SESSION_KEY constant is defined.
 */
class SmartLaunchContextTest {

    private SmartLaunchContext context(String encounterId, Instant expiresAt, String scope) {
        return new SmartLaunchContext(
                "access-token-xyz",
                "ePatient-123",
                encounterId,
                "https://fhir.epic.com/fhir/r4",
                true,
                scope,
                expiresAt,
                "refresh-token",
                null);
    }

    // ── hasEncounter ──────────────────────────────────────────────────────────

    @Test
    void hasEncounter_trueWhenEncounterPresent() {
        var ctx = context("eEncounter-456", Instant.now().plusSeconds(3600), "launch openid");
        assertThat(ctx.hasEncounter()).isTrue();
    }

    @Test
    void hasEncounter_falseWhenEncounterNull() {
        var ctx = context(null, Instant.now().plusSeconds(3600), "launch openid");
        assertThat(ctx.hasEncounter()).isFalse();
    }

    @Test
    void hasEncounter_falseWhenEncounterBlank() {
        var ctx = context("  ", Instant.now().plusSeconds(3600), "launch openid");
        assertThat(ctx.hasEncounter()).isFalse();
    }

    // ── isTokenExpired ────────────────────────────────────────────────────────

    @Test
    void isTokenExpired_falseForFutureToken() {
        var ctx = context(null, Instant.now().plusSeconds(3600), "launch");
        assertThat(ctx.isTokenExpired()).isFalse();
    }

    @Test
    void isTokenExpired_trueForPastToken() {
        var ctx = context(null, Instant.now().minusSeconds(10), "launch");
        assertThat(ctx.isTokenExpired()).isTrue();
    }

    @Test
    void isTokenExpired_trueWhenWithinBuffer() {
        // Token expires in 20s, buffer is 30s — should be considered expired
        var ctx = context(null, Instant.now().plusSeconds(20), "launch");
        assertThat(ctx.isTokenExpired(30)).isTrue();
    }

    @Test
    void isTokenExpired_falseWhenOutsideBuffer() {
        // Token expires in 60s, buffer is 30s — not yet expired
        var ctx = context(null, Instant.now().plusSeconds(60), "launch");
        assertThat(ctx.isTokenExpired(30)).isFalse();
    }

    // ── hasScope ──────────────────────────────────────────────────────────────

    @Test
    void hasScope_trueWhenGranted() {
        var ctx = context(null, Instant.now().plusSeconds(3600),
                "launch openid patient/Patient.rs patient/Condition.rs");
        assertThat(ctx.hasScope("patient/Patient.rs")).isTrue();
    }

    @Test
    void hasScope_falseWhenNotGranted() {
        var ctx = context(null, Instant.now().plusSeconds(3600),
                "launch openid patient/Patient.rs");
        assertThat(ctx.hasScope("patient/MedicationRequest.rs")).isFalse();
    }

    @Test
    void hasScope_falseWhenScopeNull() {
        var ctx = context(null, Instant.now().plusSeconds(3600), null);
        assertThat(ctx.hasScope("launch")).isFalse();
    }

    @Test
    void hasScope_noPartialMatch() {
        // "patient/Patient.rs" must not match "patient/Patient.cruds"
        var ctx = context(null, Instant.now().plusSeconds(3600),
                "patient/Patient.cruds");
        assertThat(ctx.hasScope("patient/Patient.rs")).isFalse();
    }

    @Test
    void sessionKey_isDefined() {
        assertThat(SmartLaunchContext.SESSION_KEY)
                .isNotBlank()
                .isEqualTo("smart_launch_context");
    }
}
