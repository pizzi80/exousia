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
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

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
@WebListener
//@WebFilter( filterName = TomcatAuthorizationFilterName , displayName = TomcatAuthorizationFilterName )
public class TomcatAuthorizationFilter /*extends HttpFilter*/ implements ServletContextListener , ServletRequestListener {

    static final Logger logger = Logger.getLogger(TomcatAuthorizationFilter.class.getName());

    public static ThreadLocal<HttpServletRequest> localServletRequest = new ThreadLocal<>();

    // --- ServletContextListener ----------------------------------------------------------------------------

    @Override
    public void contextInitialized(ServletContextEvent event) {

        ServletContext servletContext = event.getServletContext();

        logger.info( "init AppId: " + getServletContextId(servletContext) );

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
        String appId = getServletContextId(event.getServletContext());
        logger.info( "contextDestroyed "+appId );
        AuthorizationService.deletePolicy(appId);   // if ( appId != null && appId.length() > 0 )
        localServletRequest.remove();               // it's ok?
    }

    // --- Filter ----------------------------------------------------------------------------------------

//    private static final long serialVersionUID = -1070693477269008527L;
//    public static final String TomcatAuthorizationFilterName = "TomcatAuthorizationFilter";
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
//    }


    // --- ServletRequestListener -----------------------------------------------------------------------

    @Override
    public void requestInitialized(ServletRequestEvent event) {

        //logger.info( "requestInitialized "+event.getServletContext().getContextPath() );

        // Sets the initial request.
        // Note that we should actually have the request used before every filter and Servlet that will be executed.
        localServletRequest.set((HttpServletRequest)event.getServletRequest());

        // Sets the context ID in the current thread. The context ID is a unique name for the current web application and
        // is used by Jakarta Authorization and Exousia.
//        AuthorizationService.setThreadContextId(event.getServletContext());
    }

    @Override
    public void requestDestroyed(ServletRequestEvent event) {
        //logger.info( "requestDestroyed "+event.getServletContext().getContextPath() );
        localServletRequest.remove();
    }


    // --- Utility methods for Tomcat to Exousia constraint model conversion ---------------------------------------------------------------------------

    /**
     * Transforms the security constraints (web.xml, annotations, and programmatic) from the Tomcat types to Exousia types.
     */
    private static List<org.glassfish.exousia.constraints.SecurityConstraint> convertTomcatConstraintsToExousia(org.apache.tomcat.util.descriptor.web.SecurityConstraint[] tomcatConstraints) {
        if (tomcatConstraints == null || tomcatConstraints.length == 0) return null;

        List<org.glassfish.exousia.constraints.SecurityConstraint> exousiaConstraints = new ArrayList<>();

        for (SecurityConstraint tomcatConstraint : tomcatConstraints) {

            // Tomcat Security Constraint Collection => List<WebResourceCollection>
            List<WebResourceCollection> webResourceCollections =  Arrays.stream(tomcatConstraint.findCollections())
                                                                        .map(TomcatAuthorizationFilter::toWebResourceCollection)
                                                                        .collect(Collectors.toList());

            // (TomcatConstraint,List<WebResourceCollection>) => Exousia SecurityConstraint
            exousiaConstraints.add( toExousiaSecurityConstraint(tomcatConstraint,webResourceCollections) );
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
    public static WebResourceCollection toWebResourceCollection(SecurityCollection tomcatSecurityCollection) {
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
        if ( httpServletRequest != null ) {
            if (httpServletRequest instanceof Request) {
                logger.fine("Subject retrieved directly from Request");
                return (Subject) ((Request)httpServletRequest).getNote(REQ_JASPIC_SUBJECT_NOTE);
            }
            logger.fine("Subject retrieved with unwrapFully and reflection");
            return (Subject) getRequest(unwrapFully(httpServletRequest)).getNote(REQ_JASPIC_SUBJECT_NOTE);
        }
        return null;
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
        try {
            Field requestField = RequestFacade.class.getDeclaredField("request");
            requestField.setAccessible(true);

            return (Request) requestField.get(facade);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

}
