package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

import javax.naming.Context;
import java.util.*;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${ldap.urls}")
    private String ldapUrls;
    @Value("${ldap.base.dn}")
    private String ldapBaseDn;
    @Value("${ldap.username}")
    private String ldapSecurityPrincipal;
    @Value("${ldap.password}")
    private String ldapPrincipalPassword;
    @Value("${ldap.user.dn.pattern}")
    private String ldapUserDnPattern;
    @Value("${ldap.enabled}")
    private String ldapEnabled;

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests().anyRequest().fullyAuthenticated().and().formLogin();


    }

    @Override
    public void configure(AuthenticationManagerBuilder auth)  {
        try {
//            auth
//                .ldapAuthentication()
////                .userDnPatterns("uid={0},ou=people")
////                .groupSearchBase("ou=groups")
////                .contextSource()
////                .url("ldap://localhost:8389/dc=springframework,dc=org")
////                .and()
////                .passwordCompare()
////                .passwordEncoder(new BCryptPasswordEncoder())
////                .passwordAttribute("userPassword");
//
//                    .contextSource()
//                    .url(ldapUrls + ldapBaseDn)
//                    .managerDn(ldapSecurityPrincipal)
//                    .managerPassword(ldapPrincipalPassword)
//                    .and()
//                    .userDnPatterns(ldapUserDnPattern)

            auth.inMemoryAuthentication().withUser("ram").password("{noop}ram123").roles("ADMIN");
            auth.ldapAuthentication()
                    .contextSource()
                    .url(ldapUrls + ldapBaseDn)
                    .managerDn(ldapSecurityPrincipal)
                    .managerPassword(ldapPrincipalPassword)
                    .and()
                    .userDnPatterns(ldapUserDnPattern)
                    .userDetailsContextMapper(userDetailsContextMapper());
//
//            auth.authenticationProvider(activeDirectoryLdapAuthenticationProvider())
//                    .ldapAuthentication()
//                    .contextSource()
//                    .url(ldapUrls + ldapBaseDn)
//                    .managerDn(ldapSecurityPrincipal)
//                    .managerPassword(ldapPrincipalPassword)
//                    .and()
//                    .userDnPatterns(ldapUserDnPattern)
                    ;
//            auth.authenticationProvider(activeDirectoryLdapAuthenticationProvider());

//                    .contextSource()
//                    .url("ldap://localhost:389/dc=planetexpress,dc=com")
//                    .managerDn("cn=admin,dc=planetexpress,dc=com")
//                    .managerPassword("GoodNewsEveryone")
//                    .and()
//                    .userDnPatterns(ldapUserDnPattern)

            ;

            auth.eraseCredentials(false);

        }


        catch (Exception e){
            e.printStackTrace();
        }

    }


    @Bean
    public UserDetailsContextMapper userDetailsContextMapper() {
        return new LdapUserDetailsMapper() {
            @Override
            public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
                List<GrantedAuthority> newAuthorities = new ArrayList<>();

                List<String> authString = new ArrayList<String>();
                for (GrantedAuthority authority: authorities) {
                    authString.add(authority.toString());
                }

                String[] groups = ctx.getStringAttributes("memberOf");



//                DB CALL HERE WITH AUTH STRING TO GET NEW ROLES

//                WRITE STUFF HERE

//                Assign roles to new auth list
                for (String stringAuth: authString) {
                    newAuthorities.add(new SimpleGrantedAuthority("ROLE_" + stringAuth));
                }

                UserDetails details = super.mapUserFromContext(ctx, username, newAuthorities);
                return  details;
            }
        };
    }

//    @Bean
//    public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
////        ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("my.domain", "ldap://LDAP_ID:389/OU=A_GROUP,DC=domain,DC=tld");
//        ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("example.com", "LDAP://ldap.forumsys.com:389");
//        provider.setConvertSubErrorCodesToExceptions(true);
//        provider.setContextEnvironmentProperties(createProperties(ldapSecurityPrincipal, ldapPrincipalPassword));
//        provider.setUseAuthenticationRequestCredentials(true);
////        provider.setSearchFilter(ldapUserDnPattern);
//        return provider;
//    }



//    @Bean
//    public AuthenticationManager authenticationManager() {
//        return new ProviderManager(Arrays.asList(activeDirectoryLdapAuthenticationProvider()));
//    }
//
//    @Bean
//    public AuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
//        ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("dc=example,dc=com","ldap://ldap.forumsys.com:389/");
//        provider.setContextEnvironmentProperties(createProperties(ldapSecurityPrincipal, ldapPrincipalPassword));
//        provider.setConvertSubErrorCodesToExceptions(true);
////        provider.setUseAuthenticationRequestCredentials(true);
//        return provider;
//    }
//
    private Map<String, Object> createProperties(String ldapSecurityPrincipal, String ldapPrincipalPassword) {

        Map<String, Object> properties = new HashMap<>();
        properties.put(Context.SECURITY_PRINCIPAL, "cn=read-only-admin,dc=example,dc=com");
        properties.put(Context.SECURITY_CREDENTIALS, "password");
        return properties;
    }


}
