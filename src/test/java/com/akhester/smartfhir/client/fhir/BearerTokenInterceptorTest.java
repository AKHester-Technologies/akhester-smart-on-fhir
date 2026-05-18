package com.akhester.smartfhir.client.fhir;

import ca.uhn.fhir.rest.client.api.IHttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for BearerTokenInterceptor.
 *
 * Test cases:
 *  1.  interceptRequest adds Authorization: Bearer {token} header.
 *  2.  Header value uses exact token string passed at construction.
 *  3.  Blank token throws IllegalArgumentException at construction.
 *  4.  Null token throws IllegalArgumentException at construction.
 *  5.  interceptResponse is a no-op (does not throw).
 */
@ExtendWith(MockitoExtension.class)
class BearerTokenInterceptorTest {

    @Mock
    IHttpRequest mockRequest;

    @Test
    void interceptRequest_addsAuthorizationHeader() {
        String token = "eyJ.testtoken.sig";
        var interceptor = new BearerTokenInterceptor(token);

        interceptor.interceptRequest(mockRequest);

        ArgumentCaptor<String> nameCaptor  = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockRequest).addHeader(nameCaptor.capture(), valueCaptor.capture());

        assertThat(nameCaptor.getValue()).isEqualTo("Authorization");
        assertThat(valueCaptor.getValue()).isEqualTo("Bearer " + token);
    }

    @Test
    void interceptRequest_usesExactTokenString() {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        var interceptor = new BearerTokenInterceptor(token);

        interceptor.interceptRequest(mockRequest);

        verify(mockRequest).addHeader(eq("Authorization"), eq("Bearer " + token));
    }

    @Test
    void constructor_rejectsBlankToken() {
        assertThatThrownBy(() -> new BearerTokenInterceptor("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_rejectsNullToken() {
        assertThatThrownBy(() -> new BearerTokenInterceptor(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void interceptResponse_isNoOp() {
        var interceptor = new BearerTokenInterceptor("valid.token");
        // Must not throw — response interception is a no-op
        assertThatNoException().isThrownBy(() -> interceptor.interceptResponse(null));
    }
}
