/*
 * JBoss, Home of Professional Open Source.
 * 
 * Copyright 2007, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.security.negotiation.toolkit;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.Principal;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.jboss.security.SecurityAssociation;

/**
 * A simple servlet to be secured and output information on the
 * authenticated user. 
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class SecuredServlet extends HttpServlet
{

   private static final long serialVersionUID = 4708999345009728352L;

   private static final Logger log = Logger.getLogger(SecuredServlet.class);

   @Override
   protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      log.info(String.valueOf(req.getUserPrincipal()));

      PrintWriter writer = resp.getWriter();

      writer.println("<html>");
      writer.println("  <head>");
      writer.println("    <title>Negotiation Toolkit</title>");
      writer.println("  </head>");
      writer.println("  <body>");
      writer.println("    <h1>Negotiation Toolkit</h1>");
      writer.println("    <h2>Secured</h2>");

      writer.println("    <h5>User Principal</h5>");
      writeObject(req.getUserPrincipal(), writer);

      writer.println("    <h5>Caller Principal</h5>");
      writeObject(SecurityAssociation.getCallerPrincipal(), writer);

      writer.println("    <h5>Subject</h5>");
      writeObject(SecurityAssociation.getSubject(), writer);

      writer.println("  </body>");
      writer.println("</html>");
      writer.flush();
   }

   private void writeObject(final Object obj, final PrintWriter writer) throws IOException
   {
      ByteArrayInputStream bais = new ByteArrayInputStream(String.valueOf(obj).getBytes());
      InputStreamReader isr = new InputStreamReader(bais);
      BufferedReader br = new BufferedReader(isr);

      writer.println("<code>");
      String currentLine;
      while ((currentLine = br.readLine()) != null)
      {
         writer.print(currentLine);
         writer.println("<br>");
      }
      writer.println("</code>");
   }

   @Override
   protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      // Handle POST the same as GET.
      doGet(req, resp);
   }

}