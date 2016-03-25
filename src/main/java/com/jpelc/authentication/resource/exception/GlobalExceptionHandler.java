package com.jpelc.authentication.resource.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR, reason = "We have some problems. Sorry...")
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public String exceptionHandler(Exception ex) {
        return ex.getMessage();
    }

}
