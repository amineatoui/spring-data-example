package tn.enig.config;

import javax.activation.DataSource;
import javax.servlet.jsp.tagext.TryCatchFinally;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class Securityconfig  extends WebSecurityConfigurerAdapter{

	@Autowired
	javax.sql.DataSource dataSource;
	
	//for authentication
	
	protected void configure(AuthenticationManagerBuilder auth) {
	
		/*
		PasswordEncoder crypt=cryptageMP();
		try {
			auth.inMemoryAuthentication().withUser("adminGcr")
			.password(crypt.encode("gcr"))
			.roles("ADMIN");
			
			auth.inMemoryAuthentication().withUser("amine")
			.password(crypt.encode("gcr"))
			.roles("AGENT");
			
			auth.inMemoryAuthentication().withUser("hamma")
			.password(crypt.encode("gcr"))
			.roles("AGENT");
			
			auth.inMemoryAuthentication().withUser("ali1")
			.password(crypt.encode("gcr"))
			.roles("USER");
			
			auth.inMemoryAuthentication().withUser("ali2")
			.password(crypt.encode("gcr"))
			.roles("USER");
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		
		PasswordEncoder crypt=cryptageMP();
		try {
			auth.jdbcAuthentication().dataSource(dataSource)
			.usersByUsernameQuery("select username as principal , password as credentials, active from user where username=?")
			.authoritiesByUsernameQuery("select user_username as principal, roles_role as role from user_roles where user_username=?")
			.passwordEncoder(crypt)
			.rolePrefix("ROLE_");

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
	//for authorisation
	
	protected void configure(HttpSecurity http) {
		
		try {
			
			http.formLogin();
			http.authorizeRequests().antMatchers("/delete**").hasRole("ADMIN");
          
       
       	http.authorizeRequests().antMatchers("/list**","/add**").hasAnyRole("AGENT","ADMIN");
        
    	http.authorizeRequests().antMatchers("/listdepartement").authenticated();
        

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		
		
	}
	
	//for hashing
	@Bean
	public PasswordEncoder cryptageMP() {
           return new BCryptPasswordEncoder();		
	}
}
