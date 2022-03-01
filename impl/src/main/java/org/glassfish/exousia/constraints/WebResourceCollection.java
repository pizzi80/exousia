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
package org.glassfish.exousia.constraints;

import java.util.Collection;
import java.util.Set;

import static java.util.Collections.unmodifiableSet;

public class WebResourceCollection {

    private final Set<String> urlPatterns;
    private final Set<String> httpMethods;
    private final Set<String> httpMethodOmissions;

    public WebResourceCollection(String... urlPatterns) {
        this(Set.of(urlPatterns));
    }

    public WebResourceCollection(Collection<String> urlPatterns) {
        this( Set.copyOf(urlPatterns) , Set.of(), Set.of());
    }

    public WebResourceCollection(Set<String> urlPatterns, Set<String> httpMethods) {
        this(urlPatterns, httpMethods, Set.of());
    }

    public WebResourceCollection(String[] urlPatterns, String[] httpMethods, String[] httpMethodOmissions) {
        this( Set.of(urlPatterns) , Set.of(httpMethods) , Set.of(httpMethodOmissions) );
    }

    private WebResourceCollection(Collection<String> urlPatterns, Collection<String> httpMethods, Collection<String> httpMethodOmissions) {
        this(Set.copyOf(urlPatterns), Set.copyOf(httpMethods), Set.copyOf(httpMethodOmissions) );
    }

    public WebResourceCollection(Set<String> urlPatterns, Set<String> httpMethods, Set<String> httpMethodOmissions) {
        this.urlPatterns = unmodifiableSet(urlPatterns);
        this.httpMethods = unmodifiableSet(httpMethods);
        this.httpMethodOmissions = unmodifiableSet(httpMethodOmissions);
    }

    // --- GETTERS -----------------------------------------------------------------------------

    public Set<String> getUrlPatterns() {
        return urlPatterns;
    }
    public Set<String> getHttpMethods() {
        return httpMethods;
    }
    public Set<String> getHttpMethodOmissions() {
        return httpMethodOmissions;
    }

}