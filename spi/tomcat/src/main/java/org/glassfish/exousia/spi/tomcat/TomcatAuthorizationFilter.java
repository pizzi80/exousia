/*
 * Copyright (c) 2020, 2021 OmniFaces. All rights reserved.
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
package org.glassfish.exousia.spi.tomcat;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.glassfish.exousia.AuthorizationService;
import org.glassfish.exousia.constraints.WebResourceCollection;

import javax.security.auth.Subject;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.CONFIDENTIAL;
import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.NONE;
import static org.apache.catalina.authenticator.Constants.REQ_JASPIC_SUBJECT_NOTE;
import static org.glassfish.exousia.AuthorizationService.getServletContextId;

/**
 * Tomcat Authorization Filter and Request Listener
 * Runtime bridge from Tomcat request ad exousia auth check
 * During Filter initialization all Tomcat's roles are collected and converted to Exousia model
 *
 * @author Arjan Tijms
 */
@WebListener("TomcatAuthorizationListener")
//@WebFilter( filterName = TomcatAuthorizationFilterName , displayName = TomcatAuthorizationFilterName )
public class TomcatAuthorizationFilter /*extends HttpFilter*/ implements ServletRequestListener , ServletContextListener {

//    private static final long serialVersionUID = -1070693477269008527L;

//    public static final String TomcatAuthorizationFilterName = "TomcatAuthorizationFilter";

    static final Logger logger = Logger.getLogger(TomcatAuthorizationFilter.class.getName());

    public static ThreadLocal<HttpServletRequest> localServletRequest = new ThreadLocal<>();

//    @Override
//    public void init() {
//        ServletContext servletContext = getFilterConfig().getServletContext();
//
//        logger.info( "init "+servletContext+ " contextID: " + getServletContextId(servletContext) );
//
//        AuthorizationService.setThreadContextId(servletContext);
//
//        // Initialize the AuthorizationService, which is a front-end for Jakarta Authorization.
//        // It specifically tells Jakarta Authorization how to get the current request, and the current subject
//        AuthorizationService authorizationService = new AuthorizationService(
//            servletContext,
//            () -> getSubject(localServletRequest.get())
//        );
//
//        authorizationService.setRequestSupplier( () -> localServletRequest.get() );
//
//
//        // Get all the security constraints from Tomcat
//        StandardRoot root = (StandardRoot) servletContext.getAttribute("org.apache.catalina.resources");
//        Context context = root.getContext();
//        SecurityConstraint[] constraints = context.findConstraints();
//        Set<String> declaredRoles = Set.of(context.findSecurityRoles());
//        boolean isDenyUncoveredHttpMethods = root.getContext().getDenyUncoveredHttpMethods();
//
//        // Copy all the security constraints that Tomcat has collected to the Jakarta Authorization
//        // repository as well. That way Jakarta Authorization can work with the same data as Tomcat
//        // internally does.
//        authorizationService.addConstraintsToPolicy(
//                convertTomcatConstraintsToExousia(constraints),
//                declaredRoles,
//                isDenyUncoveredHttpMethods,
//                Map.of()
//        );
//
//
//
//    }


    // --- ServletRequestListener -----------------------------------------------------------------------

    @Override
    public void requestInitialized(ServletRequestEvent event) {

        logger.info( "requestInitialized "+event.getServletContext().getContextPath() );

        // Sets the initial request.
        // Note that we should actually have the request used before every filter and Servlet that will be executed.
        localServletRequest.set((HttpServletRequest)event.getServletRequest());

        // Sets the context ID in the current thread. The context ID is a unique name for the current web application and
        // is used by Jakarta Authorization and Exousia.
        AuthorizationService.setThreadContextId(event.getServletContext());
    }

    @Override
    public void requestDestroyed(ServletRequestEvent event) {
        logger.info( "requestDestroyed "+event.getServletContext().getContextPath() );
        localServletRequest.remove();
    }

    // --- ServletContextListener ----------------------------------------------------------------------------

    @Override
    public void contextInitialized(ServletContextEvent event) {
        // noop
        logger.info( "contextInitialized "+event.getServletContext().getContextPath() );

        ServletContext servletContext = event.getServletContext();

        logger.info( "init "+servletContext+ " contextID: " + getServletContextId(servletContext) );

        AuthorizationService.setThreadContextId(servletContext);

        // Initialize the AuthorizationService, which is a front-end for Jakarta Authorization.
        // It specifically tells Jakarta Authorization how to get the current request, and the current subject
        AuthorizationService authorizationService = new AuthorizationService(
                servletContext,
                () -> getSubject(localServletRequest.get())
        );

        authorizationService.setRequestSupplier( () -> localServletRequest.get() );


        // Get all the security constraints from Tomcat
        StandardRoot root = (StandardRoot) servletContext.getAttribute("org.apache.catalina.resources");
        Context context = root.getContext();
        SecurityConstraint[] constraints = context.findConstraints();
        Set<String> declaredRoles = Set.of(context.findSecurityRoles());
        boolean isDenyUncoveredHttpMethods = root.getContext().getDenyUncoveredHttpMethods();

        // Copy all the security constraints that Tomcat has collected to the Jakarta Authorization
        // repository as well. That way Jakarta Authorization can work with the same data as Tomcat
        // internally does.
        authorizationService.addConstraintsToPolicy(
                convertTomcatConstraintsToExousia(constraints),
                declaredRoles,
                isDenyUncoveredHttpMethods,
                Map.of()
        );
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        logger.info( "contextDestroyed "+event.getServletContext().getContextPath() );

        String appId = getServletContextId(event.getServletContext());
        if ( appId != null && appId.length() > 0 ) AuthorizationService.deletePolicy(appId);
    }



    // --- Utility methods for Tomcat to Exousia constraint conversion ---------------------------------------------------------------------------

    /**
     * Transforms the security constraints (web.xml, annotations, and programmatic) from the Tomcat types to Exousia types.
     */
    private static List<org.glassfish.exousia.constraints.SecurityConstraint> convertTomcatConstraintsToExousia(org.apache.tomcat.util.descriptor.web.SecurityConstraint[] tomcatConstraints) {
        if (tomcatConstraints == null || tomcatConstraints.length == 0) return null;

        List<org.glassfish.exousia.constraints.SecurityConstraint> exousiaConstraints = new ArrayList<>();

        for (SecurityConstraint tomcatConstraint : tomcatConstraints) {

            // Tomcat Security Constraint Collection => List<WebResourceCollection>
            List<WebResourceCollection> exousiaWebResourceCollections = new ArrayList<>();
            for (SecurityCollection tomcatSecurityCollection : tomcatConstraint.findCollections())
                exousiaWebResourceCollections.add( toExousiaSecurityCollection(tomcatSecurityCollection) );

            // (TomcatConstraint,List<WebResourceCollection>) => Exousia SecurityConstraint
            exousiaConstraints.add( toExousiaSecurityConstraint(tomcatConstraint,exousiaWebResourceCollections) );
        }

        return exousiaConstraints;
    }


    /**
     * Create an Exousia {@link org.glassfish.exousia.constraints.SecurityConstraint}
     * from a Tomcat Security Constraints and a List of {@link WebResourceCollection}
     */
    private static org.glassfish.exousia.constraints.SecurityConstraint toExousiaSecurityConstraint(SecurityConstraint tomcatConstraint, List<WebResourceCollection> exousiaWebResourceCollections) {
        return new org.glassfish.exousia.constraints.SecurityConstraint(
                exousiaWebResourceCollections,
                Set.of(tomcatConstraint.findAuthRoles()),
                "confidential".equalsIgnoreCase(tomcatConstraint.getUserConstraint()) ? CONFIDENTIAL : NONE
        );
    }


    /**
     * Tomcat SecurityCollection -> Exousia WebResourceCollection
     */
    public static WebResourceCollection toExousiaSecurityCollection(SecurityCollection tomcatSecurityCollection ) {
        return new WebResourceCollection(
                tomcatSecurityCollection.findPatterns(),
                tomcatSecurityCollection.findMethods(),
                tomcatSecurityCollection.findOmittedMethods()
        );
    }


    /**
     * Gets the authenticated Subject (if any) from the Tomcat specific location inside the HttpServletRequest instance.
     *
     * @param httpServletRequest the instance to get the Subject from
     * @return the Subject if the caller authenticated via Jakarta Authentication (JASPIC), otherwise null
     */
    private static Subject getSubject(HttpServletRequest httpServletRequest) {
        return (Subject) getRequest(unwrapFully(httpServletRequest)).getNote(REQ_JASPIC_SUBJECT_NOTE);
    }

    @SuppressWarnings("unchecked")
    private static <T extends ServletRequest> T unwrapFully(ServletRequest request) {
        ServletRequest currentRequest = request;
        while (currentRequest instanceof ServletRequestWrapper) {
            ServletRequestWrapper wrapper = (ServletRequestWrapper) currentRequest;
            currentRequest = wrapper.getRequest();
        }
        return (T) currentRequest;
    }

    private static Request getRequest(RequestFacade facade) {
        if ( facade == null ) return null;                      // request is null??
        try {
            Field requestField = RequestFacade.class.getDeclaredField("request");
            requestField.setAccessible(true);

            return (Request) requestField.get(facade);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }

    }

}
