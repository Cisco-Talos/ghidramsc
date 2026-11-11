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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.VersionException;

import org.junit.jupiter.api.Test;

class ProgramOpenPreflightTest {

    @Test
    void upgradableProgramReturnsActionableModalContext() {
        DomainFile file = domainFile(new VersionException(
            "old program", VersionException.OLDER_VERSION, true), null);

        GhidraMSCPlugin.ProgramOpenBlockedException error = assertThrows(
            GhidraMSCPlugin.ProgramOpenBlockedException.class,
            () -> GhidraMSCPlugin.preflightProgramVersion(
                file, this, "nested/legacy.bin"));

        assertTrue(error.getMessage().contains("nested/legacy.bin"));
        assertTrue(error.getMessage().contains("Upgrade Program Data?"));
        assertTrue(error.getMessage().contains("same plugin connection"));
    }

    @Test
    void successfulProbeReleasesItsConsumer() {
        AtomicBoolean released = new AtomicBoolean();
        DomainObject probe = (Program) Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] { Program.class },
            (proxy, method, args) -> {
                if ("release".equals(method.getName())) {
                    assertEquals(this, args[0]);
                    released.set(true);
                }
                return defaultValue(method.getReturnType());
            });
        DomainFile file = domainFile(null, probe);

        GhidraMSCPlugin.preflightProgramVersion(
            file, this, "current.bin");

        assertTrue(released.get());
    }

    private static DomainFile domainFile(
            VersionException failure, DomainObject result) {
        return (DomainFile) Proxy.newProxyInstance(
            DomainFile.class.getClassLoader(),
            new Class<?>[] { DomainFile.class },
            (proxy, method, args) -> {
                if ("getDomainObject".equals(method.getName())) {
                    assertEquals(false, args[1]);
                    assertEquals(false, args[2]);
                    if (failure != null) {
                        throw failure;
                    }
                    return result;
                }
                return defaultValue(method.getReturnType());
            });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        return 0;
    }
}
