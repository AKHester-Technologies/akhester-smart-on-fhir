package com.akhester.smartfhir.client.security;

import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartAuthenticationToken.
 *
 * Test cases:
 *  1.  isAuthenticated() is true after construction.
 *  2.  getPrincipal() returns patientId from context.
 *  3.  getCredentials() returns null — access token not exposed.
 *  4.  getAuthorities() contains ROLE_SMART_USER.
 *  5.  getLaunchContext() returns the original context.
 *  6.  toString() does not expose the access token.
 */
class SmartAuthenticationTokenTest {

    private SmartLaunchContext context() {
        return new SmartLaunchContext(
                "eyJ.secret_access_token",
                "ePatient-123",
                "eEncounter-456",
                "https://fhir.epic.com/fhir/r4",
                true,
                "launch openid patient/Patient.rs",
                Instant.now().plusSeconds(3600),
                "refresh_token"
        );
    }

    @Test
    void isAuthenticated_trueAfterConstruction() {
        var token = new SmartAuthenticationToken(context());
        assertThat(token.isAuthenticated()).isTrue();
    }

    @Test
    void getPrincipal_returnsPatientId() {
        var token = new SmartAuthenticationToken(context());
        assertThat(token.getPrincipal()).isEqualTo("ePatient-123");
    }

    @Test
    void getCredentials_returnsNull() {
        // Access token must not be exposed as credentials —
        // Spring Security logs credentials in some configurations.
        var token = new SmartAuthenticationToken(context());
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    void getAuthorities_containsRoleSmartUser() {
        var token = new SmartAuthenticationToken(context());
        assertThat(token.getAuthorities())
                .extracting(a -> a.getAuthority())
                .containsExactly(SmartAuthenticationToken.ROLE_SMART_USER);
    }

    @Test
    void getLaunchContext_returnsOriginalContext() {
        SmartLaunchContext ctx = context();
        var token = new SmartAuthenticationToken(ctx);
        assertThat(token.getLaunchContext()).isSameAs(ctx);
    }

    @Test
    void toString_doesNotExposeAccessToken() {
        var token = new SmartAuthenticationToken(context());
        String str = token.toString();
        assertThat(str).doesNotContain("eyJ.secret_access_token");
        assertThat(str).contains("ePatient-123");
    }
}
