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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ListenerLifecycleTest {

    @Test
    void successfulListenerHasAttributableStartAndOneRealStop() {
        ListenerLifecycle lifecycle = new ListenerLifecycle("instance-a", 1234);

        assertEquals(
            "GhidraMSC listener instance=instance-a pid=1234 port=18100"
                + " event=listening bound=true max_clients=8",
            lifecycle.listening(18100, 8));
        assertEquals(
            "GhidraMSC listener instance=instance-a pid=1234 port=18100"
                + " event=listener_stopped bound=false had_listener=true",
            lifecycle.stopped(18100));
        assertTrue(lifecycle.stopped(18100)
            .contains("event=disposed_without_listener"));
    }

    @Test
    void bindFailureAndDisposalNeverClaimListenerShutdown() {
        ListenerLifecycle first = new ListenerLifecycle("instance-a", 1234);
        ListenerLifecycle second = new ListenerLifecycle("instance-b", 1234);
        first.listening(18100, 8);

        String failed = second.bindFailed(18100);
        String disposed = second.stopped(18100);
        assertEquals(
            "GhidraMSC listener instance=instance-b pid=1234 port=18100"
                + " event=bind_failed bound=false",
            failed);
        assertEquals(
            "GhidraMSC listener instance=instance-b pid=1234 port=18100"
                + " event=disposed_without_listener bound=false"
                + " had_listener=false",
            disposed);
        assertNotEquals(first.stopped(18100), disposed);
    }
}
