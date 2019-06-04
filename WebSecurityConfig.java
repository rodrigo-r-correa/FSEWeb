package br.com.finiciativas.fseweb.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

import br.com.finiciativas.fseweb.services.impl.ConsultorServiceImpl;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private ConsultorServiceImpl collabServiceImpl;

	@Autowired
	private AccessDeniedHandler accessDeniedHandler;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		
		http.authorizeRequests()
		    .antMatchers("/resources/**").permitAll()
		    .antMatchers("/css/**").permitAll()
		    .antMatchers("/js/**").permitAll()
		    .antMatchers("/img/**").permitAll()
		    .antMatchers("/fonts/**").permitAll()
		    .antMatchers("/js/producao/**").permitAll()
		    .antMatchers("/").authenticated()
		    .antMatchers("/consultores").hasRole("ADMIN")
		    .anyRequest().authenticated()
		    .and().formLogin().loginPage("/login").permitAll()
		    .and().logout().logoutUrl("/logout")
		    .and()
		    .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(collabServiceImpl).passwordEncoder(new BCryptPasswordEncoder());
	}

}
