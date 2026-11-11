// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ghidramsc;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 4-byte big-endian length-prefix framing for the plugin TCP protocol.
 *
 * Each message on the wire is:
 *   [4 bytes: uint32 BE length N] [N bytes: UTF-8 JSON body]
 *
 * This class provides static helpers to read and write framed messages
 * over raw InputStreams / OutputStreams.
 */
public final class JsonRpcFraming {

    private JsonRpcFraming() { /* utility class */ }

    /**
     * Read one length-prefixed frame from the stream.
     *
     * @return the UTF-8 decoded body, or null on clean EOF.
     * @throws IOException on I/O error or truncated frame.
     */
    public static String readFrame(InputStream in) throws IOException {
        DataInputStream din = (in instanceof DataInputStream)
            ? (DataInputStream) in
            : new DataInputStream(in);

        // Read 4-byte length header.  readInt throws EOFException on
        // clean EOF mid-header -- we convert that to null.
        int length;
        try {
            length = din.readInt();
        } catch (java.io.EOFException e) {
            return null;
        }

        if (length < 0) {
            throw new IOException("Invalid frame length: " + length);
        }

        byte[] buf = new byte[length];
        din.readFully(buf);
        return new String(buf, StandardCharsets.UTF_8);
    }

    /**
     * Write one length-prefixed frame to the stream.
     *
     * @param message the UTF-8 JSON string to send.
     * @param out     the output stream.
     * @throws IOException on I/O error.
     */
    public static void writeFrame(String message, OutputStream out) throws IOException {
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        DataOutputStream dout = (out instanceof DataOutputStream)
            ? (DataOutputStream) out
            : new DataOutputStream(out);

        dout.writeInt(body.length);
        dout.write(body);
        dout.flush();
    }
}
