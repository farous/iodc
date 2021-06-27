package com.developer.oidc;

import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.endpoint.*;

import javax.servlet.http.*;
import java.util.*;

@SpringBootApplication
public class OidcApplication {

	public static void main(String[] args) {
		SpringApplication.run(OidcApplication.class, args);
	}


	@EnableWebSecurity
	public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private ClientRegistrationRepository clientRegistrationRepository;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.anyRequest().authenticated()
					.and()
					.oauth2Login()
					.authorizationEndpoint()
					.baseUri("/login-callback")
					.and()
					.authorizationEndpoint()
					.authorizationRequestResolver(
							new CustomAuthorizationRequestResolver(
									this.clientRegistrationRepository));
		}
	}

	public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
		private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;

		public CustomAuthorizationRequestResolver(
				ClientRegistrationRepository clientRegistrationRepository) {

			this.defaultAuthorizationRequestResolver =
					new DefaultOAuth2AuthorizationRequestResolver(
							clientRegistrationRepository, "/login-callback");
		}

		@Override
		public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
			OAuth2AuthorizationRequest authorizationRequest =
					this.defaultAuthorizationRequestResolver.resolve(request);

			return authorizationRequest != null ?
			customAuthorizationRequest(authorizationRequest) :
			null;
		}

		@Override
		public OAuth2AuthorizationRequest resolve(
				HttpServletRequest request, String clientRegistrationId) {

			OAuth2AuthorizationRequest authorizationRequest =
					this.defaultAuthorizationRequestResolver.resolve(
							request, clientRegistrationId);

			return authorizationRequest != null ?
			customAuthorizationRequest(authorizationRequest) :
			null;
		}

		private OAuth2AuthorizationRequest customAuthorizationRequest(
				OAuth2AuthorizationRequest authorizationRequest) {

			Map<String, Object> additionalParameters =
					new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
			additionalParameters.put("nonce", "randomNonce1");
			additionalParameters.put("acr_values", "eidas1");

			return OAuth2AuthorizationRequest.from(authorizationRequest)
					.additionalParameters(additionalParameters)
					.build();
		}
	}
}
