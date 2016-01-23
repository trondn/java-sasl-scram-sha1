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
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.*;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

/**
 * Minimal implementation of a SCRAM-SHA512, SCRAM-SHA256 and SCRAM-SHA1 SASL
 * Client (The server interface does not try to look up the user information
 * anyware and is hardcoded to use "user" as the username, and "pencil" as
 * the password). I picked the values from the RFC
 * https://www.ietf.org/rfc/rfc5802.txt so that I could compare the output
 * with that while I was testing ;-)
 *
 * Please note that the implementation does not try to be super efficient
 * (with respect to memory or CPU), I'm just trying to make it work correctly
 * according to the RFC. We're not doing SASLPrep on the username/password
 * in this version, because I didn't have time to look into that ;-)
 *
 * @author Trond Norbye
 * @version 1.0
 */
public class ShaImpl implements SaslClient, SaslServer {
    private final String name;
    private final String hmacAlgorithm;
    private final boolean client;
    private final CallbackHandler callbacks;
    private final MessageDigest digest;
    private String username;
    private String clientNonce;
    private String serverNonce;
    private byte[] salt;
    private byte[] saltedPassword;
    private int iterationCount;
    private String client_first_message;
    private String client_first_message_bare;
    private String client_final_message_without_proof;
    private String server_first_message;
    private String server_final_message;
    private String nonce;

    public ShaImpl(boolean client, CallbackHandler cbh, int sha) throws
                                                                 NoSuchAlgorithmException {
        this.client = client;

        callbacks = cbh;
        switch (sha) {
            case 512:
                digest = MessageDigest.getInstance("SHA-512");
                name = "SCRAM-SHA512";
                hmacAlgorithm = "HmacSHA512";
                break;
            case 256:
                digest = MessageDigest.getInstance("SHA-256");
                name = "SCRAM-SHA256";
                hmacAlgorithm = "HmacSHA256";
                break;
            case 1:
                digest = MessageDigest.getInstance("SHA-1");
                name = "SCRAM-SHA1";
                hmacAlgorithm = "HmacSHA1";
                break;
            default:
                throw new RuntimeException("Invalid SHA version specified");
        }


        // Create a random nonce. This should be random printable characters
        // and the easiest way to get that is probably just using Base64
        // encoding of the random bytes...
        SecureRandom random = new SecureRandom();

        if (client) {
            // Create a random nonce. This should be random printable characters
            // and the easiest way to get that is probably just using Base64
            // encoding of the random bytes...
            byte[] random_nonce = new byte[21];
            random.nextBytes(random_nonce);
            clientNonce = Base64.encode(random_nonce);

            // The following value is used in the RFC, so you may just use them
            // and verify that we generate the same data as the RFC
            // clientNonce = "fyko+d2lbbFgONRv9qkxdawL";
        } else {
            byte[] random_nonce = new byte[21];
            random.nextBytes(random_nonce);
            serverNonce = Base64.encode(random_nonce);

            // The following value is used in the RFC, so you may just use them
            // and verify that we generate the same data as the RFC
            // serverNonce = "3rfcNHYJY1ZVvWVs7j";
            iterationCount = 4096;
        }
    }

    @Override
    public String getMechanismName() {
        return name;
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
            if (!username.equals(getUserName())) {
                System.err.println(username);
                throw new IllegalArgumentException(
                        "This is just a test implementation.. will only work for user-pencil combination");
            }
            // And the salt should be picked from the user database..
            salt = Base64.decode("QSXCR+Q6sek8bf92");
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
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        if (client_first_message == null) {
            if (challenge.length != 0) {
                throw new SaslException("Initial challenge should be " +
                                                "without input data");
            }
            StringWriter writer = new StringWriter();
            writer.append("n,,"); // the gs2-header..
            writer.append("n=");
            writer.append(getUserName());
            writer.append(",r=");
            writer.append(clientNonce);

            client_first_message = writer.toString();
            client_first_message_bare = client_first_message.substring(3);
            return client_first_message.getBytes();
        } else if (server_first_message == null) {
            server_first_message = new String(challenge);

            HashMap<String, String> attributes = new HashMap<String, String>();
            decodeAttributes(attributes, server_first_message);

            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                switch (entry.getKey().charAt(0)) {
                    case 'r':
                        nonce = entry.getValue();
                        break;
                    case 's':
                        salt = Base64.decode(entry.getValue());
                        break;
                    case 'i':
                        iterationCount = Integer.parseInt(entry.getValue());
                        break;

                    default:
                        throw new IllegalArgumentException(
                                "Invalid key supplied in the server_first_message");
                }
            }

            // validate that all of the mandatory parameters was present!!
            if (!attributes.containsKey("r") ||
                    !attributes.containsKey("s") ||
                    !attributes.containsKey("i")) {
                throw new IllegalArgumentException(
                        "missing mandatory key in server_first_message");
            }

            // We have the salt, time to generate the salted password
            generateSaltedPassword();

            // Ok so we have salted hased password :D
            StringWriter writer = new StringWriter();
            writer.append("c=biws,"); // base64 encoding of "n,,"
            writer.append("r=");
            writer.append(nonce);
            client_final_message_without_proof = writer.toString();
            writer.append(",p=");
            writer.append(Base64.encode(getClientProof()));

            String client_final_message = writer.toString();
            return client_final_message.getBytes();
        } else if (server_final_message == null) {
            server_final_message = new String(challenge);

            HashMap<String, String> attributes = new HashMap<String, String>();
            decodeAttributes(attributes, server_final_message);

            if (attributes.containsKey("e")) {
                throw new SaslException("Authentication failure: " +
                                                attributes.get("e"));
            }

            if (!attributes.containsKey("v")) {
                throw new SaslException("Syntax error from the server");
            }

            String myServerSignature = Base64.encode(getServerSignature());
            if (!myServerSignature.equals(attributes.get("v"))) {
                throw new SaslException("Server signature is incorrect");
            }

            return new byte[0];
        }

        throw new SaslException("Can't evaluate challenge on a session" +
                                        " which is complete");
    }

    @Override
    public boolean isComplete() {
        if (client) {
            return server_final_message != null;
        } else {
            return client_final_message_without_proof != null;
        }
    }

    /**
     * We don't support using authorization id's...
     *
     * @return
     */
    @Override
    public String getAuthorizationID() {
        return null;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws
                                                               SaslException {
        return new byte[0];
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws
                                                             SaslException {
        return new byte[0];
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        return null;
    }

    @Override
    public void dispose() throws SaslException {

    }

    private String getUserName() throws SaslException {
        final NameCallback nameCallback = new NameCallback("Username");
        try {
            callbacks.handle(new Callback[]{nameCallback});
        } catch (IOException e) {
            throw new SaslException("Missing callback fetch username");
        } catch (UnsupportedCallbackException e) {
            throw new SaslException("Missing callback fetch username");
        }

        final String name = nameCallback.getName();
        if (name == null || name.isEmpty()) {
            throw new SaslException("Missing username");
        }

        // @todo according to the spec we should run this through SASLPrep
        //       but we've got so many restrictions on bucket names already
        //       so a valid bucket name may be passed without any
        //       modifications. Yes, we'll get auth failures if we pass
        //       illegal characters here :D
        return name;
    }

    /**
     * Generate the HMAC with the given SHA algorithm
     */
    private byte[] HMAC(byte[] key,
                        byte[] data) {
        final Mac mac;

        try {
            mac = Mac.getInstance(hmacAlgorithm);
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

    /**
     * Generate the hash of the function.. Unfortunately we couldn't use
     * the one provided by the Java framework because it didn't support
     * others than SHA1. See https://www.ietf.org/rfc/rfc5802.txt (page 6)
     * for how it is generated.
     *
     * @param password   The password to use
     * @param salt       The salt used to salt the hash function
     * @param iterations The number of iterations to sue
     * @return The pbkdf2 version of the password
     */
    private byte[] pbkdf2(final String password,
                          final byte[] salt,
                          int iterations) {
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            // We shuld run the SASLPrep on the password, but we have
            // restrictions on the keys allowed in the password so we
            // don't really have to ;-)
            Key key = new SecretKeySpec(password.getBytes(), hmacAlgorithm);
            mac.init(key);
            mac.update(salt);
            // Append INT(1)
            mac.update("\00\00\00\01".getBytes());
            byte[] Un = mac.doFinal();
            mac.update(Un);
            byte[] Uprev = mac.doFinal();
            xor(Un, Uprev);

            for (int i = 2; i < iterations; ++i) {
                mac.update(Uprev);
                Uprev = mac.doFinal();
                xor(Un, Uprev);
            }

            return Un;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    /**
     * XOR the two arrays and store the result in the first one
     *
     * @param result Where to store the result
     * @param other  The other array to xor with
     */
    private void xor(byte[] result, byte[] other) {
        for (int ii = 0; ii < result.length; ++ii) {
            result[ii] = (byte) (result[ii] ^ other[ii]);
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

        // We shuld run the SASLPrep on the password, but we have
        // restrictions on the keys allowed in the password so we
        // don't really have to ;-)
        String password = new String(pw);

        saltedPassword = pbkdf2(password, salt, iterationCount);
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

        xor(clientKey, clientSignature);
        return clientKey;
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
