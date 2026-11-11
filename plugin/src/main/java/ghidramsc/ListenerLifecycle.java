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

import java.util.UUID;

/** Tracks the listener owned by one plugin instance for attributable logs. */
final class ListenerLifecycle {

    private final String instanceId;
    private final long pid;
    private boolean bound;

    ListenerLifecycle() {
        this(UUID.randomUUID().toString(), ProcessHandle.current().pid());
    }

    ListenerLifecycle(String instanceId, long pid) {
        this.instanceId = instanceId;
        this.pid = pid;
    }

    synchronized String listening(int port, int maxClients) {
        bound = true;
        return prefix(port) + " event=listening bound=true max_clients="
            + maxClients;
    }

    synchronized String bindFailed(int port) {
        return prefix(port) + " event=bind_failed bound=" + bound;
    }

    synchronized String stopped(int port) {
        boolean hadListener = bound;
        bound = false;
        return prefix(port) + (hadListener
            ? " event=listener_stopped bound=false had_listener=true"
            : " event=disposed_without_listener bound=false had_listener=false");
    }

    private String prefix(int port) {
        return "GhidraMSC listener instance=" + instanceId + " pid=" + pid
            + " port=" + port;
    }
}
