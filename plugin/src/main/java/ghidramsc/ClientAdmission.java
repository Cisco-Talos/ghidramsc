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

/** Single atomic admission mechanism for plugin client sockets. */
final class ClientAdmission {

    static final class Decision {
        private final boolean admitted;
        private final int maxClients;

        private Decision(boolean admitted, int maxClients) {
            this.admitted = admitted;
            this.maxClients = maxClients;
        }

        boolean isAdmitted() {
            return admitted;
        }

        int getMaxClients() {
            return maxClients;
        }
    }

    static final int DEFAULT_MAX_CLIENTS = 12;

    private int activeClients;
    private int maxClients;

    ClientAdmission() {
        this(DEFAULT_MAX_CLIENTS);
    }

    ClientAdmission(int maxClients) {
        if (maxClients < 1) {
            throw new IllegalArgumentException("maxClients must be positive");
        }
        this.maxClients = maxClients;
    }

    synchronized Decision tryAcquire() {
        if (activeClients >= maxClients) {
            return new Decision(false, maxClients);
        }
        activeClients++;
        return new Decision(true, maxClients);
    }

    synchronized void release() {
        if (activeClients <= 0) {
            throw new IllegalStateException("No admitted client to release");
        }
        activeClients--;
    }

    synchronized int configure(int requestedMaxClients) {
        if (requestedMaxClients < 1) {
            throw new IllegalArgumentException("max_clients must be positive");
        }
        maxClients = requestedMaxClients;
        return maxClients;
    }

    synchronized int getMaxClients() {
        return maxClients;
    }

    synchronized int getActiveClients() {
        return activeClients;
    }
}
