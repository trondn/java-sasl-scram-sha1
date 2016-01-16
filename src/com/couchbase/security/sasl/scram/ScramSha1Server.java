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

package com.couchbase.security.sasl.scram;

import com.couchbase.security.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.*;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is a minimum implementation of a server supporting
 * SCRAM-SHA1.
 * <p/>
 * I've not tried to make it fast, optimal etc ;-)
 */
public class ScramSha1Server implements SaslServer {
    public static final String NAME = "SCRAM-SHA1";
    private final CallbackHandler callbacks;
    private final MessageDigest digest;
    private String client_first_message;
    private String client_first_message_bare;
    private String username;
    private String clientNonce;
    private final String serverNonce;
    private byte[] salt;
    private int iterationCount;
    private String server_first_message;
    private String client_final_message_without_proof;
    private byte[] saltedPassword;
    private final int digestSize;

    public ScramSha1Server(CallbackHandler cbh) throws
                                                NoSuchAlgorithmException {
        callbacks = cbh;
        digest = MessageDigest.getInstance("SHA-1");
        digestSize = 20;


        // Create a random nonce. This should be random printable characters
        // and the easiest way to get that is probably just using Base64
        // encoding of the random bytes...
        SecureRandom random = new SecureRandom();
        byte[] random_nonce = new byte[21];
        random.nextBytes(random_nonce);
        serverNonce = Base64.encode(random_nonce);

        // The following values is used in the RFC, so you may just use them
        // and verify that we generate the same data as the RFC
//        serverNonce = "3rfcNHYJY1ZVvWVs7j";
        salt = Base64.decode("QSXCR+Q6sek8bf92");
        iterationCount = 4096;
    }

    @Override
    public String getMechanismName() {
        return NAME;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        if (client_first_message == null) {
            // the "client-first-message" message should contain a gs2-header
            //   gs2-bind-flag,[authzid],client-first-message-bare
            client_first_message = new String(response);

            // according to the RFC the client should not send 'y' unless the
            // server advertised SCRAM-SHA[n]-PLUS (which we don't)
            if (!client_first_message.startsWith("n,")) {
                // We don't support the p= to do channel bindings (that should
                // be advertised with SCRAM-SHA[n]-PLUS)
                throw new SaslException("Invalid gs2 header");
            }

            // next up is an optional authzid which we completely ignore...
            int idx = client_first_message.indexOf(',', 2);
            if (idx == -1) {
                throw new SaslException("Invalid gs2 header");
            }

            client_first_message_bare = client_first_message.substring(idx + 1);

            HashMap<String, String> attributes = new HashMap<String, String>();
            decodeAttributes(attributes, client_first_message_bare);

            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                switch (entry.getKey().charAt(0)) {
                    case 'n':
                        username = entry.getValue();
                        break;
                    case 'r':
                        clientNonce = entry.getValue();
                        break;
                    default:
                        throw new IllegalArgumentException(
                                "Invalid key supplied in the client_first_message_bare");
                }
            }

            if (username.isEmpty() || clientNonce.isEmpty()) {
                // mandatory fields!!!
                throw new IllegalArgumentException(
                        "username and client nonce is mandatory in client_first_message_bare");
            }

            // The user name and password should be looked up somewhere ;-)
            if (!username.equals("user")) {
                System.err.println(username);
                throw new IllegalArgumentException(
                        "This is just a test implementation.. will only work for user-pencil combination");
            }
            generateSaltedPassword();
            // End fixed hardcoded stuff :)

            String nonce = clientNonce + serverNonce;

            // build up the server-first-message
            StringWriter writer = new StringWriter();
            writer.append("r=");
            writer.append(nonce);
            writer.append(",s=");
            writer.append(Base64.encode(salt));
            writer.append(",i=");
            writer.append(Integer.toString(iterationCount));

            server_first_message = writer.toString();
            return server_first_message.getBytes();
        } else if (client_final_message_without_proof == null) {

            String client_final_message = new String(response);
            HashMap<String, String> attributes = new HashMap<String, String>();
            decodeAttributes(attributes, client_final_message);

            if (!attributes.containsKey("p")) {
                throw new IllegalArgumentException(
                        "client-final-message does not contain client proof");
            }

            int idx = client_final_message.indexOf(",p=");
            client_final_message_without_proof =
                    client_final_message.substring(0, idx);

            // Generate the server signature
            byte[] serverSignature = getServerSignature();

            StringWriter writer = new StringWriter();
            writer.append("v=");
            writer.append(Base64.encode(serverSignature));

            // validate the client proof to see if we're getting the same value...
            String my_clientProof = Base64.encode(getClientProof());
            if (!my_clientProof.equals(attributes.get("p"))) {
                writer.append(",e=failed");
            }

            return writer.toString().getBytes();
        }

        throw new SaslException("Invalid state!!");
    }

    @Override
    public boolean isComplete() {
        return client_final_message_without_proof != null;
    }

    @Override
    public String getAuthorizationID() {
        return null;
    }

    @Override
    public byte[] unwrap(byte[] incoming,
                         int offset,
                         int len) throws SaslException {
        return new byte[0];
    }

    @Override
    public byte[] wrap(byte[] outgoing,
                       int offset,
                       int len) throws SaslException {
        return new byte[0];
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        return null;
    }

    @Override
    public void dispose() throws SaslException {

    }

    private byte[] HMAC(byte[] key,
                        byte[] data) {
        final Mac mac;

        try {
            mac = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }

        final SecretKeySpec secretKey =
                new SecretKeySpec(key, mac.getAlgorithm());
        try {
            mac.init(secretKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(data);
    }

    private byte[] pbkdf2(final char[] password,
                          final byte[] salt,
                          int iterations) {
        try {
            // keysize is in bytes, but the PBEKeySpec expects bits ;)
            PBEKeySpec spec =
                    new PBEKeySpec(password, salt, iterations, 20 * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA1");
            return skf.generateSecret(spec).getEncoded();
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private void generateSaltedPassword() throws SaslException {
        final PasswordCallback passwordCallback =
                new PasswordCallback("Password", false);
        try {
            callbacks.handle(new Callback[]{passwordCallback});
        } catch (IOException e) {
            throw new SaslException("Missing callback fetch password");
        } catch (UnsupportedCallbackException e) {
            throw new SaslException("Missing callback fetch password");
        }

        final char[] pw = passwordCallback.getPassword();
        if (pw == null) {
            throw new SaslException("Password can't be null");
        }

        saltedPassword =
                pbkdf2(pw, salt, iterationCount);
        passwordCallback.clearPassword();
    }


    /**
     * Generate the Server Signature. It is computed as:
     * <p/>
     * SaltedPassword  := Hi(Normalize(password), salt, i)
     * ServerKey       := HMAC(SaltedPassword, "Server Key")
     * ServerSignature := HMAC(ServerKey, AuthMessage)
     */
    private byte[] getServerSignature() {
        byte[] serverKey = HMAC(saltedPassword, "Server Key".getBytes());
        return HMAC(serverKey, getAuthMessage().getBytes());
    }

    /**
     * Generate the Client Proof. It is computed as:
     * <p/>
     * SaltedPassword  := Hi(Normalize(password), salt, i)
     * ClientKey       := HMAC(SaltedPassword, "Client Key")
     * StoredKey       := H(ClientKey)
     * AuthMessage     := client-first-message-bare + "," +
     * server-first-message + "," +
     * client-final-message-without-proof
     * ClientSignature := HMAC(StoredKey, AuthMessage)
     * ClientProof     := ClientKey XOR ClientSignature
     */
    private byte[] getClientProof() {
        byte[] clientKey = HMAC(saltedPassword, "Client Key".getBytes());
        byte[] storedKey = digest.digest(clientKey);
        byte[] clientSignature = HMAC(storedKey, getAuthMessage().getBytes());
        byte[] clientProof = new byte[digestSize];

        for (int ii = 0; ii < digestSize; ++ii) {
            clientProof[ii] = (byte) (clientKey[ii] ^ clientSignature[ii]);
        }

        return clientProof;
    }

    private void decodeAttributes(HashMap<String, String> attributes,
                                  String string) {
        String[] tokens = string.split(",");
        for (String token : tokens) {
            int idx = token.indexOf('=');
            if (idx != 1) {
                throw new IllegalArgumentException(
                        "the input string is not according to the spec");
            }
            String key = token.substring(0, 1);
            if (attributes.containsKey(key)) {
                throw new IllegalArgumentException(
                        "The key " + key + " is specified multiple times");
            }
            attributes.put(key, token.substring(2));
        }
    }

    /**
     * Get the AUTH message (as specified in the RFC)
     */
    private String getAuthMessage() {
        if (client_first_message_bare == null) {
            throw new RuntimeException(
                    "can't call getAuthMessage without client_first_message_bare is set");
        }
        if (server_first_message == null) {
            throw new RuntimeException(
                    "can't call getAuthMessage without server_first_message is set");
        }
        if (client_final_message_without_proof == null) {
            throw new RuntimeException(
                    "can't call getAuthMessage without client_final_message_without_proof is set");
        }
        return client_first_message_bare + "," + server_first_message + "," +
                client_final_message_without_proof;
    }
}
