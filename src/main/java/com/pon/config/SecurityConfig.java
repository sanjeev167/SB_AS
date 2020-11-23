/**
 * 
 */
package com.pon.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

/**
 * @author Sanjeev Kumar
 * @Date Dec 7, 2018
 * @Time 2:56:12 AM
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment environment;

	@Autowired
	private DataSource dataSource;

	private TokenStore tokenStore;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("sanjeev").password(passwordEncoder().encode("password")).roles("USER");
	}

	/**
	 * In case of OAuthServer following end points are open by default.
	 *  oauth/token,  oauth/check_token, oauth/refresh_token, oauth/token_key
	 * 
	 **/

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		 http.authorizeRequests().antMatchers("/oauth/authorize").authenticated();
		http
		    .authorizeRequests()
		    .antMatchers("/", "/login**").permitAll()// This url has been permitted to all
		    //Other urls other than oauth can also be configured here.
			.anyRequest().authenticated();// Rest request needs authentication only
	}

	
	/**
	 * This is a token store bean where you to tell which token store AS will use
	 * **/
	@Bean
	public TokenStore tokenStore() {
		if (tokenStore == null) {
			// tokenStore= new InMemoryTokenStore();//In this case, you have to change application.properties for check_token
			// tokenStore= new JdbcTokenStore(dataSource);//In this case, you have to change application.properties for check_token
			tokenStore = new JwtTokenStore(jwtTokenEnhancer());
		}
		return tokenStore;
	}
	
	/**
	 * This is required when JWT token-store is stored. It will be used for signing access token
	 * **/

	@Bean
	protected JwtAccessTokenConverter jwtTokenEnhancer() {

		String certificateFilePath = environment.getProperty("security.jwt.key-store");
		String certificateAlias = environment.getProperty("security.jwt.key-pair-alias");
		
		String pwd = environment.getProperty("security.jwt.key-store-password");

		System.out.println("certificateFilePath = " + certificateFilePath);
		System.out.println("certificateAlias = " + certificateAlias);
		System.out.println("pwd = " + pwd);
		
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource(certificateFilePath),
				pwd.toCharArray());
		
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setKeyPair(keyStoreKeyFactory.getKeyPair(certificateAlias));
		return converter;
	}

	
	/**
	 * This is required to be configured for any type of token implementation
	 * **/
	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setSupportRefreshToken(true);
		return defaultTokenServices;
	}

}