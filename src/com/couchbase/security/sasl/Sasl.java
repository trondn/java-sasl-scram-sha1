/*
 *      Copyright 2016 Couchbase, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

package com.couchbase.security.sasl;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.util.Map;

/**
 * This is just a wrapper for creating a SaslClient.
 * <p/>
 * I didn't bother spending time figuring out how to register new
 * providers in the crypto framework, but that's what you should
 * do and then just nuke this class
 */
public class Sasl {
    public static SaslClient createSaslClient(String[] mechanisms,
                                              String authorizationId,
                                              String protocol,
                                              String serverName,
                                              Map<String, ?> props,
                                              CallbackHandler cbh) throws
                                                                   SaslException {
        for (String mech : mechanisms) {
            String[] mechs = new String[]{mech};

            // First try to see if the Java Runtime system have a class that supports this
            SaslClient ret;

            ret = javax.security.sasl.Sasl
                    .createSaslClient(mechs, authorizationId, protocol,
                                      serverName, props, cbh);
            if (ret == null) {
                // Try our own implementations
                FactoryImpl factory = new FactoryImpl();
                ret = factory.createSaslClient(mechs, authorizationId,
                                               protocol, serverName, props,
                                               cbh);
            }
            if (ret != null) {
                return ret;
            }
        }

        return null;
    }

    public static SaslServer createSaslServer(String mechanism,
                                              String protocol,
                                              String serverName,
                                              Map<String, ?> props,
                                              CallbackHandler cbh) throws
                                                                   SaslException {
        SaslServer ret;

        ret = javax.security.sasl.Sasl
                .createSaslServer(mechanism, protocol, serverName, props, cbh);
        if (ret == null) {
            // Try our own implementations
            FactoryImpl factory = new FactoryImpl();
            ret = factory.createSaslServer(mechanism, protocol, serverName,
                                           props, cbh);
        }
        return ret;
    }
}
