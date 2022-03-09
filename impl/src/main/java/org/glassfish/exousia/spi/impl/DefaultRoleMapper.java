/*
 * Copyright (c) 2019 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.spi.impl;

import org.glassfish.exousia.spi.PrincipalMapper;

import javax.security.auth.Subject;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/**
 *
 * @author Arjan Tijms
 */
public class DefaultRoleMapper implements PrincipalMapper {

    private final Map<String,List<String>> groupToRoles = new HashMap<>();

    private boolean oneToOneMapping;
    private boolean anyAuthenticatedUserRoleMapped = false;

    public DefaultRoleMapper(String contextID,Collection<String> allDeclaredRoles) {
        // Initialize the groupToRoles map
        // Try to get a hold of the proprietary role mapper of each known
        // AS. Sad that this is needed :(

        // Tomcat first ;) ... it's servlet standard and requires no special work... Jetty?
        if ( isTomcat() ) oneToOneMapping = true;

        // JakartaEE servers shouldn't be compliant by default?...... o_O
        else if (tryGlassFish(contextID,allDeclaredRoles));
        else if (tryWebLogic(contextID,allDeclaredRoles));
        else if (tryGeronimo(contextID,allDeclaredRoles));

        // default
        else oneToOneMapping = true;

    }

//    @Override
//    public List<String> getMappedRoles(Collection<Principal> principals, Subject subject) {
//        return getMappedRoles(principals,subject);
//    }

    @Override
    public boolean isAnyAuthenticatedUserRoleMapped() {
        return anyAuthenticatedUserRoleMapped;
    }

    /**
     * Tries to get the roles from the principals list and only if it fails,
     * falls back to looking at the Subject.
     *
     * Liberty is the only known server that falls back.
     *
     * @param principals the primary entities to look in for roles
     * @param subject the fall back to use if looking at principals fails
     * @return a list of mapped roles
     */
    @Override
    public List<String> getMappedRoles(Iterable<Principal> principals, Subject subject) {

        // Extract the list of groups from the principals. These principals typically contain
        // different kind of principals, some groups, some others. The groups are unfortunately vendor
        // specific.
        List<String> groups = getGroups(principals, subject);

        // Map the groups to roles. E.g. map "admin" to "administrator". Some servers require this.
        return mapGroupsToRoles(groups);
    }

    private List<String> mapGroupsToRoles(List<String> groups) {

        if (oneToOneMapping) {
            // There is no mapping used, groups directly represent roles.
            return groups;
        }

        List<String> roles = new ArrayList<>();

        for (String group : groups) {
            if (groupToRoles.containsKey(group)) {
                roles.addAll(groupToRoles.get(group));
            } else {
                // Default to 1:1 mapping when group is not explicitly mapped
                roles.add(group);
            }
        }

        return roles;
    }

    // --- Tomcat --------------------------------------------------------------------

    public static boolean isTomcat() { return IS_TOMCAT; }

    private static final boolean IS_TOMCAT = existsClass("org.apache.tomcat.util.descriptor.web.SecurityConstraint");

    // --- GlassFish ---------------------------------------------------------------------------------------------------------

    private boolean tryGlassFish(String contextID, Collection<String> allDeclaredRoles) {

        try {
            Class<?> SecurityRoleMapperFactoryClass = Class.forName("org.glassfish.deployment.common.SecurityRoleMapperFactory");

            Object factoryInstance = Class.forName("org.glassfish.internal.api.Globals")
                                          .getMethod("get", SecurityRoleMapperFactoryClass ) // .getClass()
                                          .invoke(null, SecurityRoleMapperFactoryClass);

            Object securityRoleMapperInstance = SecurityRoleMapperFactoryClass.getMethod("getRoleMapper", String.class)
                                                                              .invoke(factoryInstance, contextID);

            @SuppressWarnings("unchecked")
            Map<String, Subject> roleToSubjectMap = (Map<String, Subject>) Class.forName("org.glassfish.deployment.common.SecurityRoleMapper")
                                                                                .getMethod("getRoleToSubjectMapping")
                                                                                .invoke(securityRoleMapperInstance);

            for (String role : allDeclaredRoles) {
                if (roleToSubjectMap.containsKey(role)) {
                    Set<Principal> principals = roleToSubjectMap.get(role).getPrincipals();

                    List<String> groups = getGroups(principals, null);
                    for (String group : groups) {
                        if (!groupToRoles.containsKey(group)) {
                            groupToRoles.put(group, new ArrayList<>());
                        }
                        groupToRoles.get(group).add(role);
                    }

                    if ("**".equals(role) && !groups.isEmpty()) {
                        // JACC spec 3.2 states:
                        //
                        // "For the any "authenticated user role", "**", and unless an application specific mapping has
                        // been established for this role,
                        // the provider must ensure that all permissions added to the role are granted to any
                        // authenticated user."
                        //
                        // Here we check for the "unless" part mentioned above. If we're dealing with the "**" role here
                        // and groups is not
                        // empty, then there's an application specific mapping and "**" maps only to those groups, not
                        // to any authenticated user.
                        anyAuthenticatedUserRoleMapped = true;
                    }
                }
            }

            return true;

        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException
                | InvocationTargetException e) {
            return false;
        }
    }


    // --- WebLogic -----------------------------------------------------------------------------------------------------

    private boolean tryWebLogic(String contextID, Collection<String> allDeclaredRoles) {

        try {

            // See http://docs.oracle.com/cd/E21764_01/apirefs.1111/e13941/weblogic/security/jacc/RoleMapperFactory.html
            Class<?> roleMapperFactoryClass = Class.forName("weblogic.security.jacc.RoleMapperFactory");

            // RoleMapperFactory implementation class always seems to be the value of what is passed on the commandline
            // via the -Dweblogic.security.jacc.RoleMapperFactory.provider option.
            // See http://docs.oracle.com/cd/E57014_01/wls/SCPRG/server_prot.htm
            Object roleMapperFactoryInstance = roleMapperFactoryClass.getMethod("getRoleMapperFactory")
                                                                     .invoke(null);

            // See http://docs.oracle.com/cd/E21764_01/apirefs.1111/e13941/weblogic/security/jacc/RoleMapperFactory.html#getRoleMapperForContextID(java.lang.String)
            Object roleMapperInstance = roleMapperFactoryClass.getMethod("getRoleMapperForContextID", String.class)
                                                              .invoke(roleMapperFactoryInstance, contextID);

            // This seems really awkward; the Map contains BOTH group names and usernames, without ANY way to
            // distinguish between the two.
            // If a user now has a name that happens to be a role as well, we have an issue :X
            @SuppressWarnings("unchecked")
            Map<String,String[]> roleToPrincipalNamesMap = (Map<String,String[]>) Class.forName("weblogic.security.jacc.simpleprovider.RoleMapperImpl")
                                                                                       .getMethod("getRolesToPrincipalNames")
                                                                                       .invoke(roleMapperInstance);

            for (String role : allDeclaredRoles) {
                if (roleToPrincipalNamesMap.containsKey(role)) {

                    String[] groupsOrUserNames = roleToPrincipalNamesMap.get(role);

                    for (String groupOrUserName : groupsOrUserNames) {
                        // Ignore the fact that the collection also contains usernames and hope
                        // that there are no usernames in the application with the same name as a group
                        if (!groupToRoles.containsKey(groupOrUserName)) {
                            groupToRoles.put(groupOrUserName,new ArrayList<>());
                        }
                        groupToRoles.get(groupOrUserName).add(role);
                    }

                    if ( "**".equals(role) && groupsOrUserNames.length > 0 ) {
                        // JACC spec 3.2 states: [...]
                        anyAuthenticatedUserRoleMapped = true;
                    }
                }
            }

            return true;

        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException
                | InvocationTargetException e) {
            return false;
        }
    }


    // --- Geronimo ----------------------------------------------------------------------------------------

    private static Object geronimoPolicyConfigurationFactoryInstance;
    private static ConcurrentMap<String, Map<Principal, Set<String>>> geronimoContextToRoleMapping;

    public static void onFactoryCreated() {
        tryInitGeronimo();
    }

    private static void tryInitGeronimo() {
        try {
            // Geronimo 3.0.1 contains a protection mechanism to ensure only a Geronimo policy provider is installed.
            // This protection can be beat by creating an instance of GeronimoPolicyConfigurationFactory once. This instance
            // will statically register itself with an internal Geronimo class
            geronimoPolicyConfigurationFactoryInstance = Class.forName("org.apache.geronimo.security.jacc.mappingprovider.GeronimoPolicyConfigurationFactory").getDeclaredConstructor().newInstance();
            geronimoContextToRoleMapping = new ConcurrentHashMap<>();
        } catch (Exception e) {
            // ignore
        }
    }

    public static void onPolicyConfigurationCreated(final String contextID) {

        // Are we dealing with Geronimo?
        if (geronimoPolicyConfigurationFactoryInstance != null) {

            // PrincipalRoleConfiguration

            try {
                Class<?> geronimoPolicyConfigurationClass = Class.forName("org.apache.geronimo.security.jacc.mappingprovider.GeronimoPolicyConfiguration");

                Object geronimoPolicyConfigurationProxy =
                        Proxy.newProxyInstance(
                                DefaultRoleMapper.class.getClassLoader(),
                                new Class[] {geronimoPolicyConfigurationClass},
                                new InvocationHandler() {
                                    @Override @SuppressWarnings("unchecked")
                                    public Object invoke(Object proxy, Method method, Object[] args) {
                                        // Take special action on the following method:
                                        // void setPrincipalRoleMapping(Map<Principal, Set<String>> principalRoleMap) throws PolicyContextException;
                                        if (method.getName().equals("setPrincipalRoleMapping")) {
                                            geronimoContextToRoleMapping.put(contextID, (Map<Principal,Set<String>>) args[0]);
                                        }
                                        return null;
                                    }
                                });

                // Set the proxy on the GeronimoPolicyConfigurationFactory so it will call us back later with the role mapping via the following method:

                // public void setPolicyConfiguration(String contextID, GeronimoPolicyConfiguration configuration) {
                Class.forName("org.apache.geronimo.security.jacc.mappingprovider.GeronimoPolicyConfigurationFactory")
                        .getMethod("setPolicyConfiguration", String.class, geronimoPolicyConfigurationClass)
                        .invoke(geronimoPolicyConfigurationFactoryInstance, contextID, geronimoPolicyConfigurationProxy);


            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                // Ignore
            }
        }
    }

    private boolean tryGeronimo(String contextID, Collection<String> allDeclaredRoles) {
        if (geronimoContextToRoleMapping != null) {

            if (geronimoContextToRoleMapping.containsKey(contextID)) {
                Map<Principal, Set<String>> principalsToRoles = geronimoContextToRoleMapping.get(contextID);

                for (Map.Entry<Principal, Set<String>> entry : principalsToRoles.entrySet()) {

                    // Convert the principal that's used as the key in the Map to a list of zero or more groups.
                    // (for Geronimo we know that using the default role mapper it's always zero or one group)
                    for (String group : principalToGroups(entry.getKey())) {
                        if (!groupToRoles.containsKey(group)) {
                            groupToRoles.put(group, new ArrayList<>());
                        }
                        groupToRoles.get(group).addAll(entry.getValue());

                        if (entry.getValue().contains("**")) {
                            // JACC spec 3.2 states: [...]
                            anyAuthenticatedUserRoleMapped = true;
                        }
                    }
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Extracts the groups from the vendor specific principals.
     *
     * @param principals the primary entities to look in for groups
     * @param subject the fall back to use for finding groups, may be null
     * @return a list of (non-mapped) groups
     */
    @SuppressWarnings({"unchecked","rawtypes"})
    public static List<String> getGroups(Iterable<Principal> principals, Subject subject) {
        final List<String> groups = new ArrayList<>();

        for (Principal principal : principals) {
            if (principalToGroups(principal,groups)) {
                // return value of true means we're done early. This can be used
                // when we know there's only 1 principal holding all the groups
                return groups;
            }
        }

        if (subject == null) {
            return groups;
        }

        Set<Principal> privatePrincipals = subject.getPrivateCredentials(Principal.class);
        for (Principal principal : privatePrincipals) {
            if (principalToGroups(principal, groups)) {
                // return value of true means we're done early. This can be used
                // when we know there's only 1 principal holding all the groups
                return groups;
            }
        }

        // --- WebSphere ?? -------------------------------------------------
        Set<Hashtable> tables = subject.getPrivateCredentials(Hashtable.class);
        if ( ! tables.isEmpty() ) {
//            Hashtable table = tables.iterator().next();
            return (List<String>) tables.iterator().next().getOrDefault("com.ibm.wsspi.security.cred.groups",List.of());
        }

        // Not found --> Empty
        return groups;
    }

    public static List<String> principalToGroups(Principal principal) {
        List<String> groups = new ArrayList<>();
        principalToGroups(principal,groups);
        return groups;
    }

    /**
     * Fill group list with extracted group from Principal
     */
    public static boolean principalToGroups(Principal principal, List<String> groups) {
        switch (principal.getClass().getName()) {

            case "org.glassfish.security.common.Group":                                 // GlassFish & Payara
            case "org.apache.geronimo.security.realm.providers.GeronimoGroupPrincipal": // Geronimo
            case "weblogic.security.principal.WLSGroupImpl":                            // WebLogic
            case "jeus.security.resource.GroupPrincipalImpl":                           // JEUS
                groups.add(principal.getName());
                break;

            case "org.apache.openejb.core.security.AbstractSecurityService$Group":      // TomEE 1
            case "org.jboss.security.SimpleGroup":                                      // JBoss EAP/WildFly
                if (principal.getName().equals("Roles") && principal.getClass().getName().equals("org.jboss.security.SimpleGroup")) {

                    try {
                        @SuppressWarnings("unchecked")
                        Enumeration<? extends Principal> groupMembers = (Enumeration<? extends Principal>)
                            Class.forName("org.jboss.security.SimpleGroup")
                                 .getMethod("members")
                                 .invoke(principal);

                        addEnumerationToList( groups , groupMembers , Principal::getName );

                        //groupMembers.asIterator().forEachRemaining( p -> groups.add( p.getName() ) );

//                        for (Principal groupPrincipal : list(groupMembers)) {
//                            groups.add(groupPrincipal.getName());
//                        }

                    } catch (Exception e) {

                    }

                    // Should only be one group holding the roles, so can exit the loop
                    // early
                    return true;
                }
            case "org.apache.tomee.catalina.TomcatSecurityService$TomcatUser": // TomEE 2
                try {
                    addArrayToList( groups ,
                            (String[]) Class.forName("org.apache.catalina.realm.GenericPrincipal")
                                .getMethod("getRoles")
                                .invoke(
                                     Class.forName("org.apache.tomee.catalina.TomcatSecurityService$TomcatUser")
                                          .getMethod("getTomcatPrincipal")
                                          .invoke(principal)));

                } catch (Exception e) {

                }
                break;

            case "org.apache.catalina.realm.GenericPrincipal":      // Tomcat
                try {

                    addArrayToList(
                            groups ,
                            (String[]) Class.forName("org.apache.catalina.realm.GenericPrincipal")
                                            .getMethod("getRoles")
                                            .invoke(principal)
                            );

                } catch (Exception e) {

                }
        }

        return false;
    }




    // --- Utils -------------------------------------------------------------------------

    /**
     * Null safe Collections.addAll
     */
    public static <T> void addArrayToList( List<T> list , T[] array ) {
        if (array != null && array.length != 0) Collections.addAll(list, array);
    }

    public static <T> void addEnumerationToList(List<T> list , Enumeration<T> enumeration  ) {
        if ( enumeration != null ) enumeration.asIterator().forEachRemaining(list::add);
    }

    public static <T,E> void addEnumerationToList(List<T> list , Enumeration<E> enumeration , Function<E,T> extractValue ) {
        if ( enumeration != null ) enumeration.asIterator().forEachRemaining( elem -> list.add( extractValue.apply(elem) ) );
    }

    public static boolean existsClass( String className ) {
        try {
            Class.forName(className);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

}