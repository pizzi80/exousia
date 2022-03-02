/*
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.exousia.modules.locked;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 *
 * @author monzillo
 */
public class Role {  // Serializable ??

    private final String name;
    private Permissions permissions;
    private Set<Principal> principals;
    private boolean isAnyAuthenticatedUserRole;

    public Role(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    void addPermission(Permission permission) {
        if (permissions == null) permissions = new Permissions();
        permissions.add(permission);
    }

    void addPermissions(PermissionCollection permissionCollection) {
        if (permissions == null) permissions = new Permissions();
        permissionCollection.elements().asIterator().forEachRemaining(permissions::add);
    }

    Permissions getPermissions() {
        return permissions;
    }

    void setPrincipals(Set<Principal> principals) {
        if (principals != null) {
            this.principals = principals;
        }
    }

    boolean implies(Permission permission) {
        if (permissions == null) return false;

        return permissions.implies(permission);
    }

    void determineAnyAuthenticatedUserRole() {
        // If no principals are present then any authenticated user is possible
        isAnyAuthenticatedUserRole = (principals == null) || principals.isEmpty();
    }

    boolean isAnyAuthenticatedUserRole() {
        return isAnyAuthenticatedUserRole;
    }

    boolean isPrincipalInRole(Principal principal) {
        if (isAnyAuthenticatedUserRole && (principal != null))  return true;
        if (principals == null)                                 return false;
        return principals.contains(principal);
    }

    boolean arePrincipalsInRole(Principal[] subject) {
        if (subject == null || subject.length == 0)     return false;
        if (isAnyAuthenticatedUserRole)                 return true;
        if (principals == null || principals.isEmpty()) return false;
        return Arrays.stream(subject).anyMatch(principals::contains);
    }

    /**
     * NB: Class Overrides equals and hashCode Methods such that 2 Roles are equal simply based on having a common name.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return Objects.equals(name,role.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

}
