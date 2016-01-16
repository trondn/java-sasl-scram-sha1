/*
 *     Copyright 2016 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

import com.couchbase.security.sasl.Sasl;

import javax.security.auth.callback.*;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;

/**
 * Test program used to test the SHA1 implementation ;-)
 */
public class Main implements CallbackHandler {
    private void test() {
        String[] mechs = {"SCRAM-SHA1"};

        try {
            SaslClient client = Sasl.createSaslClient(mechs, null, "couchbase",
                                                      "127.0.0.1", null, this);
            SaslServer server = Sasl.createSaslServer(mechs[0], "couchbase",
                                                      "127.0.0.1", null, this);

            byte[] array = new byte[0];
            while ((array = client.evaluateChallenge(array)).length > 0) {
                System.out.println("C: " + new String(array));

                array = server.evaluateResponse(array);
                System.out.println("S: " + new String(array));
            }

            if (!client.isComplete() || !server.isComplete()) {
                System.err.println("client or server doesn't think " +
                                           "they're done");
            }
        } catch (SaslException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String argv[]) {
        Main o = new Main();
        o.test();

        System.exit(0);
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException,
                                                    UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                ((NameCallback) callback).setName("user");
            } else if (callback instanceof PasswordCallback) {
                ((PasswordCallback) callback)
                        .setPassword("pencil".toCharArray());
            } else {
                throw new AuthenticationException(
                        "SASLClient requested unsupported callback: " + callback);
            }
        }
    }
}


