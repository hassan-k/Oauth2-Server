package com.oauth.server;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.ppolicy.PasswordPolicyControl;
import org.springframework.security.ldap.ppolicy.PasswordPolicyResponseControl;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.util.Assert;


public class AttributeLdapUserDetailsMapper implements UserDetailsContextMapper {
	// ~ Instance fields
	// ================================================================================================

	private final Log logger = LogFactory.getLog(AttributeLdapUserDetailsMapper.class);
	private String pAttributeName = "userPassword";
	private String rolePrefix = "ROLE_";
	private String[] roleAttributes = null;
	private boolean convertToUpperCase = true;

	// ~ Methods
	// ========================================================================================================

	@Override
	public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
			Collection<? extends GrantedAuthority> authorities) {
		String dn = ctx.getNameInNamespace();

		this.logger.debug("Mapping user details from context with DN: " + dn);

		LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();
		essence.setDn(dn);

		Object passwordValue = ctx.getObjectAttribute(this.pAttributeName);

		if (passwordValue != null) {
			essence.setPassword(mapPassword(passwordValue));
		}

		essence.setUsername(username);

		// Map the roles
		for (int i = 0; (this.roleAttributes != null)
				&& (i < this.roleAttributes.length); i++) {
			String[] rolesForAttribute = ctx.getStringAttributes(this.roleAttributes[i]);

			if (rolesForAttribute == null) {
				this.logger.debug("Couldn't read role attribute '"
						+ this.roleAttributes[i] + "' for user " + dn);
				continue;
			}

			for (String role : rolesForAttribute) {
				GrantedAuthority authority = createAuthority(role);

				if (authority != null) {
					essence.addAuthority(authority);
				}
			}
		}

		// Add the supplied authorities

		for (GrantedAuthority authority : authorities) {
			essence.addAuthority(authority);
		}

		// Check for PPolicy data

		PasswordPolicyResponseControl ppolicy = (PasswordPolicyResponseControl) ctx
				.getObjectAttribute(PasswordPolicyControl.OID);

		if (ppolicy != null) {
			essence.setTimeBeforeExpiration(ppolicy.getTimeBeforeExpiration());
			essence.setGraceLoginsRemaining(ppolicy.getGraceLoginsRemaining());
		}

		return essence.createUserDetails();

	}

	@Override
	public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
		throw new UnsupportedOperationException(
				"LdapUserDetailsMapper only supports reading from a context. Please"
						+ "use a subclass if mapUserToContext() is required.");
	}

	/**
	 * Extension point to allow customized creation of the user's password from the
	 * attribute stored in the directory.
	 *
	 * @param passwordValue the value of the password attribute
	 * @return a String representation of the password.
	 */
	protected String mapPassword(Object passwordValue) {

		if (!(passwordValue instanceof String)) {
			// Assume it's binary
			passwordValue = new String((byte[]) passwordValue);
		}

		return (String) passwordValue;

	}

	/**
	 * Creates a GrantedAuthority from a role attribute. Override to customize authority
	 * object creation.
	 * <p>
	 * The default implementation converts string attributes to roles, making use of the
	 * <tt>rolePrefix</tt> and <tt>convertToUpperCase</tt> properties. Non-String
	 * attributes are ignored.
	 * </p>
	 *
	 * @param role the attribute returned from
	 * @return the authority to be added to the list of authorities for the user, or null
	 * if this attribute should be ignored.
	 */
	protected GrantedAuthority createAuthority(Object role) {
		if (role instanceof String) {
			String ro = (String) role;

			int indexOfComma = ((String) role).indexOf(",");
			int indexOfEqual = ((String) role).indexOf("=");
			String roleName = ro.substring(indexOfEqual + 1, indexOfComma);
			
			if (this.convertToUpperCase) {
				roleName = roleName.toUpperCase();
			}
			
			return new SimpleGrantedAuthority(this.rolePrefix + roleName.toUpperCase());
		}
		return null;
	}

	/**
	 * Determines whether role field values will be converted to upper case when loaded.
	 * The default is true.
	 *
	 * @param convertToUpperCase true if the roles should be converted to upper case.
	 */
	public void setConvertToUpperCase(boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

	/**
	 * The name of the attribute which contains the user's password. Defaults to
	 * "userPassword".
	 *
	 * @param passwordAttributeName the name of the attribute
	 */
	public void setPAttributeName(String pAttributeName) {
		this.pAttributeName = pAttributeName;
	}

	/**
	 * The names of any attributes in the user's entry which represent application roles.
	 * These will be converted to <tt>GrantedAuthority</tt>s and added to the list in the
	 * returned LdapUserDetails object. The attribute values must be Strings by default.
	 *
	 * @param roleAttributes the names of the role attributes.
	 */
	public void setRoleAttributes(String[] roleAttributes) {
		Assert.notNull(roleAttributes, "roleAttributes array cannot be null");
		this.roleAttributes = roleAttributes;
	}

	/**
	 * The prefix that should be applied to the role names
	 * @param rolePrefix the prefix (defaults to "ROLE_").
	 */
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}
}
