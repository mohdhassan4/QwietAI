package org.sasanlabs.controller.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.sasanlabs.internal.utility.MessageBundle;
import org.sasanlabs.service.exception.ExceptionStatusCodeEnum;
import org.sasanlabs.service.exception.ServiceApplicationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.WebRequest;

class ControllerExceptionHandlerTest {

    @Mock private MessageBundle messageBundle;

    @Mock private WebRequest webRequest;

    private ControllerExceptionHandler controllerExceptionHandler;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
        controllerExceptionHandler = new ControllerExceptionHandler(messageBundle);
    }

    @Test
    void shouldHandleControllerExceptionsWithGenericMessage() {
        // Arrange - use a specific exception type but expect generic SYSTEM_ERROR response
        when(messageBundle.getString("SYSTEM_ERROR", null)).thenReturn("System Error Occurred");
        ServiceApplicationException serviceApplicationException =
                new ServiceApplicationException(
                        ExceptionStatusCodeEnum.INVALID_END_POINT, "sensitiveEndpoint");

        // Act
        ResponseEntity<String> responseEntity =
                controllerExceptionHandler.handleControllerExceptions(
                        new ControllerException(serviceApplicationException), webRequest);

        // Assert - response must contain generic message, not exception-specific details
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertEquals("System Error Occurred", responseEntity.getBody());
        verify(messageBundle).getString("SYSTEM_ERROR", null);
    }

    @Test
    void shouldHandleExceptions() {
        // Arrange
        when(messageBundle.getString(any(), any())).thenReturn("IO exception occurred");

        // Act
        ResponseEntity<String> responseEntity =
                controllerExceptionHandler.handleExceptions(
                        new IOException("IO operation failed"), webRequest);

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
        assertEquals("IO exception occurred", responseEntity.getBody());
        verify(messageBundle).getString(any(), any());
    }
}
