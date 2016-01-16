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

import com.couchbase.security.sasl.scram.ScramSha1Client;
import com.couchbase.security.sasl.scram.ScramSha1Server;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.*;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * The SaslClientFactory supporting SCRAM-SHA1 CRAM-MD5 and PLAIN
 * authentication methos
 */
public class FactoryImpl implements SaslClientFactory, SaslServerFactory {
    private static final String[] supportedMechanisms = new String[]{ScramSha1Client.NAME};

    @Override
    public SaslClient createSaslClient(String[] mechanisms,
                                       String authorizationId,
                                       String protocol,
                                       String serverName,
                                       Map<String, ?> props,
                                       CallbackHandler cbh) throws SaslException {
        boolean found = false;
        for (String m : mechanisms) {
            if (m.equals(ScramSha1Client.NAME)) {
                found = true;
            }
        }

        if (!found) {
            return null;
        }

        if (authorizationId != null) {
            throw new SaslException("authorizationId is not supported (yet)");
        }

        if (cbh == null) {
            throw new SaslException("Callback handler must be set");
        }

        // protocol, servername and props is currently being ignored...

        try {
            return new ScramSha1Client(cbh);
        } catch (NoSuchAlgorithmException e) {
            // The JAVA runtime don't support all the algorithms we need
            return null;
        }
    }

    @Override
    public SaslServer createSaslServer(String mechanism,
                                       String protocol,
                                       String serverName,
                                       Map<String, ?> props,
                                       CallbackHandler cbh) throws SaslException {
        if (!mechanism.equals(ScramSha1Server.NAME)) {
            return null;
        }
        // protocol, serverName and props is not being used
        try {
            return new ScramSha1Server(cbh);
        } catch (NoSuchAlgorithmException e) {
            // The JAVA runtime don't support all the algorithms we need
            return null;
        }
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        // @todo look at the properties we should nuke off
        return supportedMechanisms;
    }
}
