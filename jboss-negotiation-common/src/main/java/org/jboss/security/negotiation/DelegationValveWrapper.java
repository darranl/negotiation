/*
 * JBoss, Home of Professional Open Source.
 *
 * Copyright 2013, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.negotiation;

import java.io.IOException;

import static org.jboss.security.negotiation.NegotiationAuthenticator.DELEGATION_CREDENTIAL;
import javax.servlet.ServletException;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.Session;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.ietf.jgss.GSSCredential;
import org.jboss.servlet.http.HttpEvent;

/**
 * A factory to wrap valves with a wrapper which will set the Credential to use for delegation.
 *
 * @author darran.lofthouse@jboss.com
 */
class DelegationValveWrapper {

    static Valve wrap(final Valve valve) {
        if (valve instanceof Lifecycle) {
            return new LifecycleValveWrapper(valve);
        } else {
            return new ValveWrapper(valve);
        }

    }

    private static class DelegationCredentialManager extends DelegationCredentialContext {

        private static void setDelegationCredential(final GSSCredential credential) {
            currentCredential.set(credential);
        }

        private static void removeDelegationCredential() {
            currentCredential.remove();
        }

    }

    private static class ValveWrapper implements Valve {

        private final Valve nextValve;

        private ValveWrapper(final Valve nextValve) {
            this.nextValve = nextValve;
        }

        public String getInfo() {
            return nextValve.getInfo();
        }

        public Valve getNext() {
            return nextValve.getNext();
        }

        public void setNext(Valve valve) {
            nextValve.setNext(valve);

        }

        public void backgroundProcess() {
            nextValve.backgroundProcess();
        }

        public void invoke(Request request, Response response) throws IOException, ServletException {
            Session session = request.getSessionInternal();
            GSSCredential credential = (GSSCredential) session.getNote(DELEGATION_CREDENTIAL);
            try {
                DelegationCredentialManager.setDelegationCredential(credential);
                nextValve.invoke(request, response);
            } finally {
                DelegationCredentialManager.removeDelegationCredential();
            }
        }

        public void event(Request request, Response response, HttpEvent event) throws IOException, ServletException {
            nextValve.event(request, response, event);
        }
    }

    private static class LifecycleValveWrapper extends ValveWrapper implements Lifecycle {

        private final Lifecycle nextValve;

        private LifecycleValveWrapper(final Valve valve) {
            super(valve);
            this.nextValve = (Lifecycle) valve;
        }

        public void addLifecycleListener(LifecycleListener listener) {
            nextValve.addLifecycleListener(listener);
        }

        public LifecycleListener[] findLifecycleListeners() {
            return nextValve.findLifecycleListeners();
        }

        public void removeLifecycleListener(LifecycleListener listener) {
            nextValve.removeLifecycleListener(listener);
        }

        public void start() throws LifecycleException {
            nextValve.start();
        }

        public void stop() throws LifecycleException {
            nextValve.stop();
        }

    }

}