package com.parcom.security_client;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@RequiredArgsConstructor
public class UnauthorizedEntryPoint implements AuthenticationEntryPoint
{

	private final MessageSource messageSource;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
			throws IOException
	{
		response.sendError(
				HttpServletResponse.SC_UNAUTHORIZED,
				messageSource.getMessage("access.denied",null, "Access denied", LocaleContextHolder.getLocale()));
	}

}