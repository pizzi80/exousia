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

/**
 * This package contains an alternative authorization module (policy provider).
 * 
 * <p>
 * Like the default authorization module in <code>org.omnifaces.exousia.modules.def</code> this
 * is also an in-memory module, but with a greater emphasis on locking its operations.
 * 
 * <p>
 * Furthermore, the different approach to implementing essentially the same algorithm / requirements
 * may be of educational value.
 * 
 * 
 */
package org.omnifaces.exousia.modules.locked;