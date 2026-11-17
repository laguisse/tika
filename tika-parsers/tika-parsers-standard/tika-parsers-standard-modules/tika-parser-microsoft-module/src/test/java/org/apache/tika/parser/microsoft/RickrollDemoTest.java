/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tika.parser.microsoft;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * IFT3913 - Tâche 3 : test qui échoue volontairement afin de démontrer le
 * rickroll déclenché dans le CI. À ne jamais fusionner dans la branche main.
 */
public class RickrollDemoTest {

    @Test
    public void testNeverGonnaGiveYouUp() {
        int attendu = 1;
        int obtenu = 2;
        assertEquals(attendu, obtenu,
                "Échec volontaire : ce test sert à déclencher le rickroll dans le CI");
    }
}
