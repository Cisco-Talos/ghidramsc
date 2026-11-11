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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class JsonRpcFramingTest {

    @Test
    void roundTripsUtf8UsingByteLength() throws Exception {
        String message = "{\"command\":\"ping\",\"note\":\"café ☕\"}";
        ByteArrayOutputStream wire = new ByteArrayOutputStream();

        JsonRpcFraming.writeFrame(message, wire);

        byte[] bytes = wire.toByteArray();
        assertEquals(message.getBytes(StandardCharsets.UTF_8).length,
            new DataInputStream(new ByteArrayInputStream(bytes)).readInt());
        assertEquals(message,
            JsonRpcFraming.readFrame(new ByteArrayInputStream(bytes)));
    }

    @Test
    void cleanEofReturnsNull() throws Exception {
        assertNull(JsonRpcFraming.readFrame(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    void negativeLengthIsRejected() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        new DataOutputStream(wire).writeInt(-1);

        IOException error = assertThrows(IOException.class,
            () -> JsonRpcFraming.readFrame(
                new ByteArrayInputStream(wire.toByteArray())));

        assertEquals("Invalid frame length: -1", error.getMessage());
    }

    @Test
    void truncatedBodyIsRejected() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(wire);
        out.writeInt(5);
        out.write(new byte[] { 1, 2 });

        assertThrows(IOException.class, () -> JsonRpcFraming.readFrame(
            new ByteArrayInputStream(wire.toByteArray())));
    }
}
