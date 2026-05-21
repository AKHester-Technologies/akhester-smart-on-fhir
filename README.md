# SMART on FHIR Client

> A production-ready **SMART on FHIR EHR launch client**  — Spring Boot 3.3.5 · Java 21 · HAPI FHIR R4

[![Java](https://img.shields.io/badge/Java-21-blue?logo=openjdk)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.5-brightgreen?logo=springboot)](https://spring.io/projects/spring-boot)
[![HAPI FHIR](https://img.shields.io/badge/HAPI%20FHIR-7.4.5-orange)](https://hapifhir.io)
[![SMART](https://img.shields.io/badge/SMART%20App%20Launch-v2.2-blueviolet)](https://hl7.org/fhir/smart-app-launch/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What this is

A complete,Spring implementation of the [SMART App Launch v2.2](https://hl7.org/fhir/smart-app-launch/) specification targeting EHR Servers. It handles everything between Server clicking "launch" and your code receiving a ready-to-use FHIR client — PKCE, dynamic discovery, token exchange, token refresh, OIDC user profiles, Spring Security 6 wiring, and a clinical Thymeleaf UI.

**Why it exists:** Every existing Spring Boot SMART library (including [HealthLX/smart-on-fhir](https://github.com/HealthLX/smart-on-fhir)) uses `WebSecurityConfigurerAdapter`, which was removed in Spring Security 6. None compile on Spring Boot 3. This was built from scratch to fill that gap.

---

## Features

| | Feature | Detail |
|---|---|---|
| 🔐 | **SMART App Launch v2.2** | EHR launch + standalone launch, dynamic `/.well-known/smart-configuration` discovery |
| 🔑 | **PKCE (RFC 7636)** | S256, 96-byte verifier, mathematically verified in tests |
| 🏥 | **Epic-specific params** | `aud=iss`, `launch` token, token response extras (`patient`, `encounter`, `need_patient_banner`) |
| 🔄 | **Proactive token refresh** | 120s buffer before expiry, refresh token rotation handled |
| 👤 | **OIDC user profiles** | `id_token` validation — algorithm, issuer, audience, expiry, nonce, JWKS key presence |
| 🛡️ | **Spring Security 6** | `SecurityFilterChain`, session fixation, CSRF Double-Submit Cookie, `denyAll()` fallback |
| 📦 | **HAPI FHIR R4 client** | Per-session `IGenericClient` with `BearerTokenInterceptor`, configurable timeouts |
| 🌐 | **Both launch modes** | EHR launch (Epic-initiated) and standalone (direct URL, `launch/patient` scope) |
| ⚕️ | **Clinical UI** | Thymeleaf patient banner, dashboard, conditions table, medications table |
| 🧪 | **140+ tests** | WireMock, `@WebMvcTest`, `@SpringBootTest`, SMART Health IT + Epic sandbox integration tests |

---

## Quick start

### SMART Health IT sandbox (no account needed — 5 minutes)

```bash
git clone https://github.com/your-org/smart-fhir-client.git
cd smart-fhir-client
mvn spring-boot:run -Dspring-boot.run.profiles=smart
```

Go to [launch.smarthealthit.org](https://launch.smarthealthit.org), set the launch URL to `http://localhost:8080/launch`, pick a patient, and click Launch.

### Epic non-production sandbox

```bash
export EPIC_CLIENT_ID=your-non-production-client-id
mvn spring-boot:run -Dspring-boot.run.profiles=epic
```

Get a free client ID at [fhir.epic.com](https://fhir.epic.com) (takes ~15 minutes + 1 hour sync).

---

## Requirements

| Requirement | Version |
|---|---|
| Java | 21+ |
| Maven | 3.6.3+ |
| Spring Boot | 3.3.5 |

---

## Project structure

```
src/main/java/com/smartfhir/client/
├── auth/          PkceHelper · PkceParameters · SmartAuthRequestBuilder
├── context/       SmartLaunchContext · SmartContextExtractor
├── discovery/     SmartDiscoveryService · SmartConfiguration
├── fhir/          FhirClientFactory · BearerTokenInterceptor · PatientDataController
├── launch/        SmartLaunchController · SmartLaunchSession
├── oidc/          IdTokenValidator · UserProfile · IdTokenException
├── refresh/       TokenRefreshService · TokenRefreshFilter
├── security/      SecurityConfig · SmartSecurityFilter · SmartAuthenticationToken
├── token/         SmartCallbackController · SmartTokenService · SmartTokenResponse
└── ui/            UiController

src/main/resources/
├── application.yml          Base config
├── application-epic.yml     Epic sandbox profile
├── application-smart.yml    SMART Health IT sandbox profile
└── templates/               Thymeleaf pages (index, patient, conditions, medications)

src/test/java/com/smartfhir/client/
├── it/            EpicSandboxIT · SmartHealthSandboxIT
└── (17 unit test classes across all packages)
```

---

## Configuration

Minimum required properties (`application.yml`):

```yaml
smart:
  epic:
    client-id: ${EPIC_CLIENT_ID}
    redirect-uri: http://localhost:8080/callback
    scopes:
      - launch
      - openid
      - patient/Patient.rs
      - patient/Condition.rs
      - patient/MedicationRequest.rs
    discovery-cache-minutes: 60

hapi:
  fhir:
    socket-timeout-ms: 30000
    connect-timeout-ms: 10000
    log-requests-and-responses: false  # never true in production
```

| Property | Required | Default | Description |
|---|---|---|---|
| `smart.epic.client-id` | ✅ | — | Epic OAuth2 client ID (`EPIC_CLIENT_ID` env var) |
| `smart.epic.redirect-uri` | ✅ | `http://localhost:8080/callback` | Must match App Orchard registration |
| `smart.epic.scopes` | ✅ | See above | SMART v2 scope list |
| `smart.epic.discovery-cache-minutes` | No | `60` | ISS discovery cache TTL |
| `hapi.fhir.socket-timeout-ms` | No | `30000` | FHIR API socket timeout |
| `hapi.fhir.connect-timeout-ms` | No | `10000` | FHIR API connect timeout |

---

## The launch flow

```
Epic Hyperspace
  │
  │  GET /launch?iss=https://fhir.epic.com/...&launch=abc123
  ▼
SmartLaunchController          validates ISS · discovers endpoints · generates PKCE
  │
  │  302 → https://fhir.epic.com/oauth2/authorize
  │        ?response_type=code&client_id=...&aud=iss&launch=abc123
  │        &code_challenge=S256_HASH&code_challenge_method=S256
  ▼
Epic Auth Server               auto-approves in sandbox
  │
  │  GET /callback?code=AUTH_CODE&state=NONCE
  ▼
SmartCallbackController        validates state · exchanges code + PKCE verifier
  │
SmartTokenService              POST grant_type=authorization_code
  │
SmartContextExtractor          parses patient/encounter/id_token · stores SmartLaunchContext
  │
  │  302 → /
  ▼
Dashboard                      renders with real Epic FHIR data
```

---

## API endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /launch` | None | Initiates EHR or standalone launch |
| `GET /callback` | None | OAuth2 authorization code callback |
| `GET /api/session` | Required | Session metadata — always safe, works in standalone |
| `GET /api/me` | Required | OIDC user profile (404 if `openid` not granted) |
| `GET /api/patient` | Required | Patient demographics (`patient/Patient.rs`) |
| `GET /api/conditions` | Required | Active conditions (`patient/Condition.rs`) |
| `GET /api/medications` | Required | Active medications (`patient/MedicationRequest.rs`) |
| `GET /api/summary` | Required | Combined session + FHIR data |

Example response from `GET /api/session`:

```json
{
  "launchMode":        "ehr",
  "patientId":         "erXuFYUfucBZaryVksYEcMg3",
  "encounterId":       "eEnc-789XYZ",
  "needPatientBanner": true,
  "grantedScopes":     "launch openid patient/Patient.rs ...",
  "hasUserProfile":    true,
  "tokenExpiresAt":    "2025-01-15T10:30:00Z"
}
```

---

## Testing

```bash
# Unit tests only — fast, no network, no credentials (~18 seconds)
mvn test

# Integration tests against SMART Health IT sandbox (no credentials needed)
mvn verify -Psmart

# Integration tests against Epic non-production sandbox
export EPIC_CLIENT_ID=your-non-production-client-id
mvn verify -Pepic
```

### Test coverage

| Package | Test class | Tests |
|---|---|---|
| `auth` | `PkceHelperTest`, `SmartAuthRequestBuilderTest` | 15 |
| `context` | `SmartLaunchContextTest`, `SmartContextExtractorTest` | 26 |
| `discovery` | `SmartDiscoveryServiceTest` | 8 |
| `fhir` | `BearerTokenInterceptorTest`, `FhirClientFactoryTest`, `PatientDataControllerTest` | 23 |
| `launch` | `SmartLaunchControllerTest` | 8 |
| `oidc` | `IdTokenValidatorTest` | 15 |
| `refresh` | `TokenRefreshServiceTest`, `TokenRefreshFilterTest` | 26 |
| `security` | `SecurityConfigTest`, `SmartSecurityFilterTest`, `SmartAuthenticationTokenTest` | 25 |
| `token` | `SmartCallbackControllerTest`, `SmartTokenServiceTest` | 25 |
| `it` | `SmartHealthSandboxIT`, `EpicSandboxIT` | 18 |

---

## Security

Several hardening measures are applied beyond standard Spring Security:

- **Log injection prevention** — attacker-controlled URL params (`iss`, `error`) are sanitised before logging
- **ISS URI validation** — `URI.create()` with host check, not `startsWith("https://")`
- **Constant-time state comparison** — `MessageDigest.isEqual()` prevents timing attacks on the CSRF nonce
- **Token masking** — `SmartLaunchContext.toString()` and `SmartAuthenticationToken.getCredentials()` never expose the bearer token
- **`denyAll()` route fallback** — unknown routes return `403`, not `404` (prevents route enumeration)
- **Session fixation protection** — `changeSessionId()` after authentication
- **Redis-ready session objects** — all `Serializable` with pinned `serialVersionUID`

---

## Production notes

Before deploying to a real hospital environment:

1. **HTTPS** — Epic requires HTTPS for production redirect URIs. Use a reverse proxy (nginx) or set `server.ssl.*`
2. **Redis sessions** — add `spring-session-data-redis` and set `spring.session.store-type: redis` for clustering
3. **OIDC crypto** — add `nimbus-jose-jwt` for full RS256 `id_token` signature verification (currently structural only)
4. **HIPAA BAA** — must be signed with the hospital and any cloud provider before real patient data flows
5. **App Orchard** — Epic requires app registration and review before production hospital deployment (2–12 weeks)

See [Production Checklist](https://smart-on-fhir-doc.akhester.com/operations/production-checklist/) in the docs for the complete list.

---

## Akhester/smart-on-fhir vs HealthLX/smart-on-fhir

| | HealthLX (2019) | This project |
|---|---|---|
| Spring Boot | 2.x | **3.3.5** |
| Spring Security | 5 (`WebSecurityConfigurerAdapter` — **removed in SS6**) | **6** (`SecurityFilterChain`) |
| SMART spec | v1, static config | **v2.2**, dynamic discovery |
| PKCE | ❌ Missing | ✅ RFC 7636 S256 |
| Token refresh | ❌ Not implemented | ✅ Proactive 120s buffer |
| OIDC validation | ❌ Not implemented | ✅ RS256, JWKS, nonce |
| Standalone launch | ❌ Not implemented | ✅ Full support |
| FHIR client included | ❌ | ✅ HAPI R4 + bearer token |
| Epic `aud` param | ❌ Missing | ✅ Required by Epic |
| Test coverage | Minimal | **140+ tests** |
| Last commit | December 2019 | **2025** |

---


## Contributing

Contributions are welcome — especially:

- 🐛 Bug reports with reproduction steps
- 🏥 Testing against non-Epic SMART servers (Cerner, generic HAPI)
- 🔐 Nimbus JOSE+JWT integration for full RS256 id_token verification
- 📦 Extracting into a `smart-fhir-spring-boot-starter` reusable library
- 📝 Documentation improvements

Please open an issue before submitting a large PR.

---

## License

[MIT](LICENSE) — free for personal, educational, and commercial use.
