package com.parcom.security_client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.concurrent.TimeUnit;


public class TokenCreate extends TokenUtils {

	@FunctionalInterface
	interface DurationSetter {
		Date getExpirationDate(Date now);
	}

	private static final long DEFAULT_TOKEN_DURATION = 30L;


	static String createToken(UserDetails userDetails)
	{
		return createToken(userDetails,now -> new Date(now.getTime() + TimeUnit.MINUTES.toMillis(DEFAULT_TOKEN_DURATION)));
	}

	public static String createToken(UserDetails userDetails, Integer duration) {
		int lduration = (duration!=null)?duration:1;
		return createToken(userDetails,now -> new Date(now.getTime() + TimeUnit.DAYS.toMillis(lduration)));
	}

	private static String createToken(UserDetails userDetails, DurationSetter durationSetter) {

		UserDetailsPC userDetailsPC = (UserDetailsPC) userDetails;

		Date now = new Date();
		Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
		claims.put(JWT_USER, userDetailsPC.getUsername());
		claims.put(JWT_ID_USER, userDetailsPC.getId());
		claims.put(JWT_ID_GROUP, userDetailsPC.getIdGroup());
		claims.put(JWT_ID_STUDENT, userDetailsPC.getIdStudent());
		claims.put(JWT_AUTHORITIES, userDetailsPC.getAuthoritiesStr());

		return Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(new Date())
				.setExpiration(durationSetter.getExpirationDate(now))
				.signWith(SignatureAlgorithm.HS512, MAGIC_KEY)
				.compact();
	}


}