package com.akhester.smartfhir.client;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Task 1 smoke test — updated Task 8.
 *
 * Verifies:
 *  1. Application context loads (all beans wire up, EpicProperties validates).
 *  2. GET /health returns 200 WITHOUT authentication (SecurityConfig permits it).
 *
 * Run with: mvn test -Dtest=SmartFhirApplicationTest
 */
@SpringBootTest
@AutoConfigureMockMvc
class SmartFhirApplicationTest {

    @Autowired
    MockMvc mvc;

    @Test
    void contextLoads_andHealthEndpointIsPublic() throws Exception {
        // No @WithMockUser — /health must be accessible without authentication.
        // This test would have failed before Task 8's SecurityConfig was added.
        mvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.app").value("smart-fhir-client"));
    }
}
