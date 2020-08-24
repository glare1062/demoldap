package com.example.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class OverrideActiveDirectoryLdapAuthenticationProvider extends CustomActiveDirectoryLdapAuthenticationProvider {


//    @Autowired

    public static final Logger logger = LoggerFactory.getLogger(OverrideActiveDirectoryLdapAuthenticationProvider.class);
    public OverrideActiveDirectoryLdapAuthenticationProvider(String domain, String url) {
        super(domain, url);
    }

    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username, String password) {
        String[] groups = userData.getStringAttributes("memberOf");
        if (groups == null) {
            logger.debug("No values for 'memberOf' attribute. No Authorities in Active Directory!");
            return AuthorityUtils.NO_AUTHORITIES;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
        }

        List<GrantedAuthority> authorities = createGrantedAuthoritiesFromLdapGroups(groups);
        return authorities;
    }

    private List<GrantedAuthority> createGrantedAuthoritiesFromLdapGroups(String[] groups) {



        List<String> groupNames = new ArrayList<>(groups.length);
        //'groups' is array of Acitve Directory groups which user that tries to authenticate has.
        for (String group : groups) {
            String groupName = new DistinguishedName(group)
                    .removeLast().getValue();
            groupNames.add(groupName);
        }

        // I use Active Directory groups that user which tries to login has and get all application privileges for them from database.
        // You can map privileges or roles form database to application roles and easily use them in application for example in @Secured annotation
//        List<String> privileges = roleDao.findPrivilegesForLDAPGroups(groupNames);
//
//        // Your roles/privileges in database need to have 'ROLE_' prefix or you need to append it here.
        String DEFAULT_ROLE_PREFIX = "ROLE_";
        List<GrantedAuthority> authorities = new ArrayList<>();

//        if (){
            authorities.add(new SimpleGrantedAuthority(DEFAULT_ROLE_PREFIX+"USER"));

//        }

        return authorities;
    }
}
