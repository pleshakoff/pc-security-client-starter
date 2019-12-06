package com.parcom.security_client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by apleshakov on 17.02.2015.
 */
@Getter
@Setter
@NoArgsConstructor
class ExceptionResource {

    private static Logger logger = LoggerFactory.getLogger(ExceptionResource.class);

    public static ExceptionResource getExceptionResource(HttpServletRequest request, Exception ex, String message) {
        logger.error(String.format("Method: \"%s\"; URI: \"%s\" ", request.getMethod(), request.getRequestURI().toString()));
        logger.error(ex.getMessage(), ex);
        ExceptionResource result = new ExceptionResource();
        result.setUrl(request.getRequestURI().toString());
        result.setExceptionClass(ex.getClass().getName());
        result.setMethod(request.getMethod());
        result.setMessage(message);
        return result;
    }


    private String type = "exception";
    private String url;
    private String method;
    private String message;
    private String exceptionClass;
    private String description;

    String toJson() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return   mapper.writeValueAsString(this);
    }

  }