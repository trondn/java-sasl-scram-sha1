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

package com.couchbase.security.sasl.test;

import com.couchbase.security.sasl.Sasl;

import javax.security.auth.callback.*;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

/**
 * Test program used to test the SCRAM-SHAx implementations ;-)
 */
public class Main implements CallbackHandler {
    private void sendPacket(Socket socket, int opcode, String key, byte[] payload) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(24);
        header.rewind();
        header.put((byte)(0x80 & 0xff));
        header.put((byte)(opcode & 0xff));
        header.putShort((short)(key.length() & 0xffff));
        header.put((byte)0); // extlen
        header.put((byte)0); // datatype
        header.putShort((short)0); // vbucket
        header.putInt(key.length() + payload.length);
        OutputStream out = socket.getOutputStream();
        out.write(header.array());
        out.write(key.getBytes());
        out.write(payload);
    }

    private final static int SASL_LIST_MECH = 0x20;
    private final static int SASL_AUTH = 0x21;
    private final static int SASL_STEP = 0x22;


    private void sendSaslAuth(Socket socket,
                             String mechanism,
                             byte[] payload) throws IOException {
        sendPacket(socket, SASL_AUTH, mechanism, payload);
    }

    private void sendSaslStep(Socket socket,
                              String mechanism,
                              byte[] payload) throws IOException {
        sendPacket(socket, SASL_STEP, mechanism, payload);
    }

    private String saslListMech(InetSocketAddress address) {
        try {
            Socket socket = new Socket();
            socket.connect(address);
            sendPacket(socket, SASL_LIST_MECH, "", new byte[0]);
            ByteBuffer response = readResponse(socket);

            if (response.getInt(6) != 0) {
                throw new RuntimeException("LIST MECH failed: " + response.getInt(6));
            }

            response.position(24);
            byte[] mech = new byte[response.getInt(8)];
            response.get(mech);

            return new String(mech);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return "PLAIN";
    }

    private ByteBuffer readResponse(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] header = new byte[24];
        if (in.read(header) != 24) {
            throw new RuntimeException("Incomplete read");
        }

        ByteBuffer buffer = ByteBuffer.wrap(header);
        int bodylength = buffer.getInt(8);
        byte[] payload = new byte[bodylength];
        if (in.read(payload) != bodylength) {
            throw new RuntimeException("Incomplete read");
        }

        ByteBuffer ret = ByteBuffer.allocate(24 + bodylength);
        ret.rewind();
        ret.put(header);
        ret.put(payload);
        return ret;
    }

    private void testServer(String mechanism, SocketAddress address){
        System.out.println("Testing mechanism: " + mechanism);

        try {
            Socket socket = new Socket();
            socket.connect(address);

            String[] mechs = {mechanism};

            SaslClient client = Sasl.createSaslClient(mechs, null, "couchbase",
                        "127.0.0.1", null, this);

            if (client == null) {
                System.err.println("Failed to create client");
                return;
            }

            byte[] array = new byte[0];
            if (client.hasInitialResponse()) {
                array = client.evaluateChallenge(array);
            }

            sendSaslAuth(socket, mechanism, array);
            do {
                ByteBuffer response = readResponse(socket);
                short status = response.getShort(6);
                if (status != 0 && status != 0x21) {
                    throw new RuntimeException("SASL AUTH failed with" +
                            Integer.toHexString(status) + " (" + mechanism + ")");
                }

                int bodyLength = response.getInt(8);
                if (bodyLength > 0) {
                    array = new byte[bodyLength];
                    response.position(24);
                    response.get(array, 0, bodyLength);

                    array = client.evaluateChallenge(array);
                }

                if (status == 0x21) {
                    // the server is expecting something
                    sendSaslStep(socket, mechanism, array);
                } else {
                    if (!client.isComplete()) {
                     throw new RuntimeException("I expected the client to be done.. " +
                             "the server is not waiting");
                    }
                }
            } while (!client.isComplete());

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void test(String scram) {
        String[] mechs = {scram, "CRAM-MD5", "PLAIN"};

        try {
            SaslClient client = Sasl.createSaslClient(mechs, null, "couchbase",
                    "127.0.0.1", null, this);
            SaslServer server = Sasl.createSaslServer(mechs[0], "couchbase",
                    "127.0.0.1", null, this);

            if (client == null) {
                System.err.println("Failed to create client");
                return;
            }

            if (server == null) {
                System.err.println("Failed to create server");
                return;
            }

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
        o.test("SCRAM-SHA1");
        o.test("SCRAM-SHA256");
        o.test("SCRAM-SHA512");


        // If you've started a couchbase server with cluster-run and have a bucket named foo with password
        // pencil the following things should also work...
        String serverMechs = o.saslListMech( new InetSocketAddress("localhost", 12000));
        String[] mechs = serverMechs.split(" ");
        for (String m : mechs) {
            o.testServer(m, new InetSocketAddress("localhost", 12000));
        }

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
