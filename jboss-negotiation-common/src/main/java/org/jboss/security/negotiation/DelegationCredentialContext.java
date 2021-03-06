/*
 * Copyright © 2012  Red Hat Middleware, LLC. or third-party contributors as indicated 
 * by the @author tags or express copyright attribution statements applied by the 
 * authors. All third-party contributions are distributed under license by Red Hat 
 * Middleware LLC.
 *
 * This copyrighted material is made available to anyone wishing to use, modify, copy, 
 * or redistribute it subject to the terms and conditions of the GNU Lesser General 
 * Public License, v. 2.1. This program is distributed in the hope that it will be 
 * useful, but WITHOUT A WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for 
 * more details. You should have received a copy of the GNU Lesser General Public License, 
 * v.2.1 along with this distribution; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

package org.jboss.security.negotiation;

import org.ietf.jgss.GSSCredential;

/**
 * A context to allow access to the underlying DelegationCredential is applicable.
 * 
 * Note: This class is a public API and all subsequent changes MUST be backwards compatible.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 24th July 2012
 * @version $Revision$
 */
public class DelegationCredentialContext
{
   
   protected static ThreadLocal<GSSCredential> currentCredential = new ThreadLocal<GSSCredential>();
   
   public static GSSCredential getDelegCredential() {
      return currentCredential.get();
   }      

}
