/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.ECDH1PU;
import com.nimbusds.jose.crypto.impl.ECDH1PUCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman encrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects} for curves using an OKP JWK.
 * Expects a public {@link OctetKeyPair} key with {@code "crv"} X25519.
 *
 * <p>See <a href="https://tools.ietf.org/html/rfc8037">RFC 8037</a>
 * for more information.
 *
 * <p>See also {@link ECDH1PUEncrypter} for ECDH on other curves.
 *
 * <p>Public Key Authenticated Encryption for JOSE
 * <a href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">ECDH-1PU</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link Curve#X25519}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Direct key
 * agreement mode:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#XC20P}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Key wrapping
 * mode:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 * </ul>
 *
 * @author Alexander Martynov
 * @author Egor Puzanov
 * @version 2023-05-17
 */
@ThreadSafe
public class ECDH1PUX25519Encrypter extends ECDH1PUCryptoProvider implements JWEEncrypter {


    /**
     * The public key.
     */
    private final OctetKeyPair publicKey;

    /**
     * The private key.
     */
    private final OctetKeyPair privateKey;

    /**
     * Creates a new Curve25519 Elliptic Curve Diffie-Hellman encrypter.
     *
     * @param privateKey The private key. Must not be {@code null}.
     * @param publicKey The public key. Must not be {@code null}.
     *
     * @throws JOSEException If the key subtype is not supported.
     */
    public ECDH1PUX25519Encrypter(final OctetKeyPair privateKey, final OctetKeyPair publicKey)
            throws JOSEException {

        this(privateKey, publicKey, null);
    }

    /**
     * Creates a new Curve25519 Elliptic Curve Diffie-Hellman encrypter.
     *
     * @param privateKey The private key. Must not be {@code null}.
     * @param publicKey The public key. Must not be {@code null}.
     * @param contentEncryptionKey The content encryption key (CEK) to use.
     *                             If specified its algorithm must be "AES"
     *                             and its length must match the expected
     *                             for the JWE encryption method ("enc").
     *                             If {@code null} a CEK will be generated
     *                             for each JWE.
     *
     * @throws JOSEException If the key subtype is not supported.
     */
    public ECDH1PUX25519Encrypter(final OctetKeyPair privateKey,
                                  final OctetKeyPair publicKey,
                                  final SecretKey contentEncryptionKey
                                  )
            throws JOSEException {

        super(publicKey.getCurve(), contentEncryptionKey);

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public Set<Curve> supportedEllipticCurves() {

        return Collections.singleton(Curve.X25519);
    }


    /**
     * Returns the public key.
     *
     * @return The public key.
     */
    public OctetKeyPair getPublicKey() {

        return publicKey;
    }

    /**
     * Returns the private key.
     *
     * @return The private key.
     */
    public OctetKeyPair getPrivateKey() {

        return privateKey;
    }


    /**
     * Encrypts the specified clear text of a {@link JWEObject JWE object}.
     *
     * @param header    The JSON Web Encryption (JWE) header. Must specify
     *                  a supported JWE algorithm and method. Must not be
     *                  {@code null}.
     * @param clearText The clear text to encrypt. Must not be {@code null}.
     *
     * @return The resulting JWE crypto parts.
     *
     * @throws JOSEException If the JWE algorithm or method is not
     *                       supported or if encryption failed for some
     *                       other internal reason.
     */
    @Deprecated
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
        throws JOSEException {

        return encrypt(header, clearText, AAD.compute(header));
    }


    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText, final byte[] aad)
            throws JOSEException {

        final OctetKeyPair ephemeralPrivateKey = new OctetKeyPairGenerator(getCurve()).generate();
        final OctetKeyPair ephemeralPublicKey = ephemeralPrivateKey.toPublicJWK();

        // Add the ephemeral public EC key to the header
        JWEHeader updatedHeader = new JWEHeader.Builder(header).
                ephemeralPublicKey(ephemeralPublicKey).
                build();

        SecretKey Z = ECDH1PU.deriveSenderZ(
                privateKey,
                publicKey,
                ephemeralPrivateKey
        );

        // for JWEObject we need update the AAD as well
        final byte[] updatedAAD = Arrays.equals(AAD.compute(header), aad) ? AAD.compute(updatedHeader) : aad;

        return encryptWithZ(updatedHeader, Z, clearText, updatedAAD);
    }
}
