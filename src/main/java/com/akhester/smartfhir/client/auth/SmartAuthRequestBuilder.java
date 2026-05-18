package com.akhester.smartfhir.client.auth;

import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.launch.SmartLaunchSession;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Builds the complete OAuth2 authorize URL for an Epic EHR launch, including
 * all Epic-specific parameters and PKCE.
 *
 * <h3>Responsibility split with SmartLaunchController</h3>
 * Task 3's {@link com.akhester.smartfhir.client.launch.SmartLaunchController} owns the
 * HTTP layer: validating params, running discovery, generating the state nonce,
 * and issuing the redirect. This class owns the URL construction and PKCE
 * generation — a pure function that takes a {@link SmartLaunchSession} and
 * returns a fully-formed authorize URL string. Keeping them separate makes
 * both independently testable.
 *
 * <h3>Parameters added to the authorize URL</h3>
 * <pre>
 *   response_type          = code          (required, standard)
 *   client_id              = {clientId}    (from EpicProperties)
 *   redirect_uri           = {redirectUri} (from EpicProperties, must match App Orchard)
 *   launch                 = {launchToken} (Epic EHR launch — opaque token from /launch)
 *   scope                  = {scopes}      (space-separated, from EpicProperties)
 *   state                  = {state}       (CSRF nonce, generated in Task 3)
 *   aud                    = {iss}         (Epic-specific — must equal the FHIR base URL)
 *   code_challenge         = {challenge}   (PKCE S256)
 *   code_challenge_method  = S256          (PKCE method — plain not accepted by Epic)
 * </pre>
 *
 * <h3>Side effect: session storage</h3>
 * {@link PkceParameters} are stored in the session under
 * {@link PkceParameters#SESSION_KEY} so Task 5's token exchange can retrieve
 * the {@code code_verifier} to complete the PKCE handshake.
 */
@Component
public class SmartAuthRequestBuilder {

    private static final Logger log = LoggerFactory.getLogger(SmartAuthRequestBuilder.class);

    private final EpicProperties epicProperties;
    private final PkceHelper pkceHelper;

    public SmartAuthRequestBuilder(EpicProperties epicProperties, PkceHelper pkceHelper) {
        this.epicProperties = epicProperties;
        this.pkceHelper = pkceHelper;
    }

    /**
     * Builds the authorize URL and stores the PKCE verifier in the session.
     *
     * @param launchSession the session populated by SmartLaunchController (Task 3)
     * @param httpSession   the current HTTP session — receives the PKCE parameters
     * @return fully-formed authorize URL to redirect the browser to
     */
    public String buildAuthorizeUrl(SmartLaunchSession launchSession, HttpSession httpSession) {

        // ── 1. Generate PKCE pair ─────────────────────────────────────────────
        PkceParameters pkce = pkceHelper.generate();

        // Store verifier in session — Task 5 POSTs this to the token endpoint.
        // The challenge goes to Epic; the verifier stays secret server-side.
        httpSession.setAttribute(PkceParameters.SESSION_KEY, pkce);
        log.debug("PKCE generated and stored in session — challenge method: S256");

        // ── 2. Build the authorize URL ────────────────────────────────────────
        // Scopes come from the session — validated @NotEmpty at startup via EpicProperties.
        String scopeString = String.join(" ", launchSession.scopes());

        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(launchSession.authEndpoint())
                // Standard OAuth2
                .queryParam("response_type", "code")
                .queryParam("client_id", epicProperties.clientId())
                .queryParam("redirect_uri", epicProperties.redirectUri())
                .queryParam("scope", scopeString)
                .queryParam("state", launchSession.state())
                // Epic-specific aud param — required for both EHR and standalone
                .queryParam("aud", launchSession.iss())
                // PKCE (required for public clients in SMART v2; Epic enforces this)
                .queryParam("code_challenge", pkce.codeChallenge())
                .queryParam("code_challenge_method", "S256");

        // launch param — only included for EHR launch (not standalone).
        // When launchToken is null, this is a standalone launch and the param
        // must be omitted — sending launch=null would confuse Epic's auth server.
        if (launchSession.launchToken() != null && !launchSession.launchToken().isBlank()) {
            builder.queryParam("launch", launchSession.launchToken());
        }

        String url = builder.build(false).toUriString();

        log.info("Authorize URL built — endpoint={}, state={}",
                launchSession.authEndpoint(), launchSession.state());

        return url;
    }

}
