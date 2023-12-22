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
import net.jcip.annotations.ThreadSafe;
import org.bouncycastle.crypto.AEADOperatorFactory;
import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputAEADDecryptor;
import org.bouncycastle.crypto.OutputAEADEncryptor;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.fips.FipsAES;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;


/**
 * Legacy AES/GSM/NoPadding encryption and decryption methods. Uses the
 * BouncyCastle.org API. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @author Axel Nennker
 * @version 2015-11-15
 */
@ThreadSafe
public class LegacyAESGCM {


	/**
	 * The standard authentication tag length (128 bits).
	 */
	public static final int AUTH_TAG_BIT_LENGTH = 128;


	/**
	 * Encrypts the specified plain text using AES/GCM/NoPadding.
	 *
	 * @param secretKey The AES key. Must not be {@code null}.
	 * @param plainText The plain text. Must not be {@code null}.
	 * @param iv        The initialisation vector (IV). Must not be
	 *                  {@code null}.
	 * @param authData  The authenticated data. Must not be {@code null}.
	 *
	 * @return The authenticated cipher text.
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static AuthenticatedCipherText encrypt(final SecretKey secretKey,
												  final byte[] iv,
												  final byte[] plainText,
												  final byte[] authData)
			throws JOSEException {

		// Initialise AES/GCM cipher for encryption
		FipsAES.AuthParameters parameters = FipsAES.GCM.withIV(iv).withMACSize(AUTH_TAG_BIT_LENGTH);
		SymmetricKey key = new SymmetricSecretKey(parameters, secretKey.getEncoded());
		AEADOperatorFactory<FipsAES.AuthParameters> factory = new FipsAES.AEADOperatorFactory();
		OutputAEADEncryptor<FipsAES.AuthParameters> encryptor = factory.createOutputAEADEncryptor(key, parameters);

		// Prepare output buffer
		int outputLength = encryptor.getMaxOutputSize(plainText.length);
		ByteArrayOutputStream output = new ByteArrayOutputStream(outputLength);

		// Produce cipher text
		CipherOutputStream encryptingStream = encryptor.getEncryptingStream(output);
		encryptor.getAADStream().update(authData);
		encryptingStream.update(plainText);
		try {
			encryptingStream.close();
		} catch (InvalidCipherTextException e) {
			throw new JOSEException("Couldn't generate GCM authentication tag: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new JOSEException("I/O error", e);
		}
		byte[] cipherTextAndTag = output.toByteArray();

		// Split output into cipher text and authentication tag
		int authTagLength = AUTH_TAG_BIT_LENGTH / 8;
		byte[] cipherText = new byte[cipherTextAndTag.length - authTagLength];
		System.arraycopy(cipherTextAndTag, 0, cipherText, 0, cipherText.length);

		// Produce authentication tag
		byte[] authTag = encryptor.getMAC();

		return new AuthenticatedCipherText(cipherText, authTag);
	}


	/**
	 * Decrypts the specified cipher text using AES/GCM/NoPadding.
	 *
	 * @param secretKey  The AES key. Must not be {@code null}.
	 * @param iv         The initialisation vector (IV). Must not be
	 *                   {@code null}.
	 * @param cipherText The cipher text. Must not be {@code null}.
	 * @param authData   The authenticated data. Must not be {@code null}.
	 * @param authTag    The authentication tag. Must not be {@code null}.
	 *
	 * @return The decrypted plain text.
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static byte[] decrypt(final SecretKey secretKey,
								 final byte[] iv,
								 final byte[] cipherText,
								 final byte[] authData,
								 final byte[] authTag)
			throws JOSEException {

		// Initialise AES/GCM cipher for decryption
		FipsAES.AuthParameters parameters = FipsAES.GCM.withIV(iv).withMACSize(AUTH_TAG_BIT_LENGTH);
		SymmetricKey key = new SymmetricSecretKey(parameters, secretKey.getEncoded());
		AEADOperatorFactory<FipsAES.AuthParameters> factory = new FipsAES.AEADOperatorFactory();
		OutputAEADDecryptor<FipsAES.AuthParameters> decryptor = factory.createOutputAEADDecryptor(key, parameters);

		// Join cipher text and authentication tag to produce cipher input
		byte[] input = new byte[cipherText.length + authTag.length];

		System.arraycopy(cipherText, 0, input, 0, cipherText.length);
		System.arraycopy(authTag, 0, input, cipherText.length, authTag.length);

		// Prepare output buffer
		int outputLength = decryptor.getMaxOutputSize(input.length);
		ByteArrayOutputStream output = new ByteArrayOutputStream(outputLength);

		// Decrypt
		decryptor.getAADStream().update(authData);
		CipherOutputStream decryptingStream = decryptor.getDecryptingStream(output);
		decryptingStream.update(input);
		try {
			decryptingStream.close();
		} catch (InvalidCipherTextException e) {
			throw new JOSEException("Couldn't validate GCM authentication tag: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new JOSEException("I/O error", e);
		}

		return output.toByteArray();
	}


	/**
	 * Prevents public instantiation.
	 */
	private LegacyAESGCM() { }
}