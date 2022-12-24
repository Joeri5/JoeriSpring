package com.github.joeri5.joeridev.auth;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ControllerAdvice
public class AuthControllerAdvice {

    @ResponseBody
    @ExceptionHandler({ ConstraintViolationException.class })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, List<String>> handleException(ConstraintViolationException ex) {
        HashMap<String, List<String>> errors = new HashMap<>();
        errors.put("errors", ex.getConstraintViolations()
                .stream()
                .map(ConstraintViolation::getMessage)
                .toList()
        );
        return errors;
    }

}