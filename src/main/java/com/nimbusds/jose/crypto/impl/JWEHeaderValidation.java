/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;


/**
 * JWE header validation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2023-09-10
 */
public class JWEHeaderValidation {


        /**
         * Gets the JWE algorithm of the specified header and ensure it is not
         * {@code null}.
         *
         * @param jweHeader The JWE header. Must not be {@code null}.
         *
         * @return The JWE algorithm.
         *
         * @throws JOSEException If the JWE {@code alg} header parameter is
         *                       {@code null}.
         */
        public static JWEAlgorithm getAlgorithmAndEnsureNotNull(final JWEHeader jweHeader)
                throws JOSEException {

                JWEAlgorithm alg = jweHeader.getAlgorithm();
                if (alg == null) {
                        throw new JOSEException("The algorithm \"alg\" header parameter must not be null");
                }
                return alg;
        }


        private JWEHeaderValidation() {}
}
