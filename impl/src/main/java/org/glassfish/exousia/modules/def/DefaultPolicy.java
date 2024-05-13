/*
 * Copyright (c) 2019, 2021 OmniFaces. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */
package org.glassfish.exousia.modules.def;

import static java.util.Arrays.asList;

import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;

import org.glassfish.exousia.spi.PrincipalMapper;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultPolicy extends Policy {

    private final static Logger logger = Logger.getLogger(DefaultPolicy.class.getName());

    private final Policy defaultPolicy = getDefaultPolicy();

    @Override
    public boolean implies(ProtectionDomain domain, Permission permission) {

        PolicyConfiguration policyConfiguration = getPolicyConfigurationFactory().getPolicyConfiguration();
        
        PrincipalMapper roleMapper = ((DefaultPolicyConfiguration) policyConfiguration).getRoleMapper();

        // fixme: if roleMappe is null what is the best return value? true or false?
        if (roleMapper == null) {
            return false;
        }

        if (isExcluded(policyConfiguration.getExcludedPermissions(), permission)) {
            // Excluded permissions cannot be accessed
            // by anyone
            return false;
        }

        if (isUnchecked(policyConfiguration.getUncheckedPermissions(), permission)) {
            // Unchecked permissions are free to
            // be accessed by everyone
            return true;
        }

        List<Principal> currentUserPrincipals = asList(domain.getPrincipals());

        if (!roleMapper.isAnyAuthenticatedUserRoleMapped() && !currentUserPrincipals.isEmpty()) {
            // The "any authenticated user" role is not
            // mapped, so available to anyone and the current
            // user is assumed to be authenticated (we assume
            // that an unauthenticated user doesn't have any
            // principals whatever they are)
            if (hasAccessViaRole(policyConfiguration.getPerRolePermissions(), "**", permission)) {
                // Access is granted purely based
                // on the user being authenticated
                // (the actual roles, if any, the user
                // has it not important)
                return true;
            }
        }

        final Subject subject = getCurrentSubject();

        if (hasAccessViaRoles(policyConfiguration.getPerRolePermissions(), roleMapper.getMappedRoles(currentUserPrincipals, subject), permission)) {
            // Access is granted via role. Note that if
            // this returns false
            // it doesn't mean the permission is not
            // granted. A role can only grant, not take
            // away permissions.
            return true;
        }

        if (defaultPolicy != null) {
            return defaultPolicy.implies(domain, permission);
        }

        return false;
    }

    @Override
    public PermissionCollection getPermissions(ProtectionDomain domain) {

        Permissions permissions = new Permissions();

        PolicyConfiguration policyConfiguration = getPolicyConfigurationFactory().getPolicyConfiguration();

        PrincipalMapper roleMapper = getRoleMapper(policyConfiguration);

        PermissionCollection excludedPermissions = policyConfiguration.getExcludedPermissions();

        // First get all permissions from the previous (original) policy
        if (defaultPolicy != null) {
            collectPermissions(defaultPolicy.getPermissions(domain), permissions, excludedPermissions);
        }

        // If there are any static permissions, add those next
        if (domain.getPermissions() != null) {
            collectPermissions(domain.getPermissions(), permissions, excludedPermissions);
        }

        // Thirdly, get all unchecked permissions
        collectPermissions(policyConfiguration.getUncheckedPermissions(), permissions, excludedPermissions);

        final Subject subject = getCurrentSubject();

        // Finally get the permissions for each role
        // *that the current user has*
        //
        Map<String, PermissionCollection> perRolePermissions = policyConfiguration.getPerRolePermissions();

        for (String role : roleMapper.getMappedRoles(domain.getPrincipals(), subject)) {
            if (perRolePermissions.containsKey(role)) {
                collectPermissions(perRolePermissions.get(role), permissions, excludedPermissions);
            }
        }

        return permissions;
    }

    @Override
    public PermissionCollection getPermissions(CodeSource codesource) {

        Permissions permissions = new Permissions();

        PolicyConfiguration policyConfiguration = getPolicyConfigurationFactory().getPolicyConfiguration();
        
        PermissionCollection excludedPermissions = policyConfiguration.getExcludedPermissions();

        // First get all permissions from the previous
        // (original) policy
        if (defaultPolicy != null) {
            collectPermissions(defaultPolicy.getPermissions(codesource), permissions, excludedPermissions);
        }

        // Secondly get the static permissions.
        // Note that there are only two sources
        // possible here, without knowing the roles
        // of the current user we can't check the per
        // role permissions.
        collectPermissions(policyConfiguration.getUncheckedPermissions(), permissions, excludedPermissions);

        return permissions;
    }

    // --- Private methods ----------------------------------------------------------------------------------
    
    private static PolicyConfigurationFactory getPolicyConfigurationFactory() {
        try {
            return PolicyConfigurationFactory.getPolicyConfigurationFactory();
        } catch (ClassNotFoundException | PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Policy getDefaultPolicy() {
        Policy policy = Policy.getPolicy();
        if (policy instanceof DefaultPolicy) {
            logger.warning("Cannot obtain default / previous policy.");
            return null;
        }

        return policy;
    }
    
    private static PrincipalMapper getRoleMapper(PolicyConfiguration policyConfiguration) {
        return ((DefaultPolicyConfiguration) policyConfiguration).getRoleMapper();
    }

    private static boolean isExcluded(PermissionCollection excludedPermissions, Permission permission) {

        return excludedPermissions.implies(permission) ||
               excludedPermissions.elementsAsStream().anyMatch(permission::implies);
    }

    private static boolean isUnchecked(PermissionCollection uncheckedPermissions, Permission permission) {
        return uncheckedPermissions.implies(permission);
    }

    private static boolean hasAccessViaRoles(Map<String, PermissionCollection> perRolePermissions, List<String> roles, Permission permission) {
        for (String role : roles) {
            if (hasAccessViaRole(perRolePermissions, role, permission)) {
                return true;
            }
        }

        return false;
    }

    private static boolean hasAccessViaRole(Map<String, PermissionCollection> perRolePermissions, String role, Permission permission) {

        PermissionCollection permissions = perRolePermissions.get(role);

        return permission != null && permissions.implies(permission);
    }

    /**
     * Copies permissions from a source into a target
     * skipping any permission that's excluded.
     */
    private static void collectPermissions(PermissionCollection sourcePermissions, PermissionCollection targetPermissions, PermissionCollection excludedPermissions) {

        boolean hasExcludedPermissions = excludedPermissions.elements().hasMoreElements();

        sourcePermissions.elementsAsStream().forEach( permission -> {
            if (!hasExcludedPermissions || !isExcluded(excludedPermissions, permission)) {
                targetPermissions.add(permission);
            }
        });
    }

    public static Subject getCurrentSubject() {
        try {
            return PolicyContext.getContext("javax.security.auth.Subject.container");
        } catch (PolicyContextException ex) {
            throw new RuntimeException(ex);
        }
    }

}