package org.sasanlabs.controller.exception;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sasanlabs.internal.utility.MessageBundle;
import org.sasanlabs.service.exception.ExceptionStatusCodeEnum;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Exception Handler for all the VulnerableApp's exceptions.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
@ControllerAdvice
public class ControllerExceptionHandler extends ResponseEntityExceptionHandler {

    private MessageBundle messageBundle;

    private static final transient Logger LOGGER =
            LogManager.getLogger(ControllerExceptionHandler.class);

    /** Placeholder substituted for exception derived message arguments. */
    private static final String OMITTED_DETAIL = "[detail omitted]";

    public ControllerExceptionHandler(MessageBundle messageBundle) {
        this.messageBundle = messageBundle;
    }

    @ExceptionHandler(ControllerException.class)
    public ResponseEntity<String> handleControllerExceptions(
            ControllerException ex, WebRequest request) {
        LOGGER.error("Controller Exception Occurred :-", ex);
        return new ResponseEntity<String>(
                ex.getExceptionStatusCode()
                        .getMessage(withoutExceptionDetails(ex.getArgs()), messageBundle),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleExceptions(Exception ex, WebRequest request) {
        LOGGER.error("General Exception Occurred :- ", ex);
        return new ResponseEntity<String>(
                ExceptionStatusCodeEnum.SYSTEM_ERROR.getMessage(null, messageBundle),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Replaces every exception derived message argument with a fixed placeholder so that exception
     * messages, types and stack traces are never formatted into the client facing error body. The
     * full exception is logged instead. The response envelope and the remaining message arguments
     * are left untouched.
     */
    private Object[] withoutExceptionDetails(Object[] args) {
        if (args == null) {
            return null;
        }
        Object[] safeArgs = new Object[args.length];
        for (int index = 0; index < args.length; index++) {
            safeArgs[index] = args[index] instanceof Throwable ? OMITTED_DETAIL : args[index];
        }
        return safeArgs;
    }
}
