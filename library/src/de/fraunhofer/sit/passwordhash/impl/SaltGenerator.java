package de.fraunhofer.sit.passwordhash.impl;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SaltGenerator {

	private static final String ALGORITHM_NAME_CIPHER = "DES/ECB/NoPadding";

	private static final byte[] SCRAMBLER_KEY = new byte[] {
		(byte)0x4F, (byte)0x27, (byte)0x8B, (byte)0x51,
		(byte)0x88, (byte)0x8C, (byte)0x1E, (byte)0xE2 
	};

	private static class SecureRandomHolder {
		public static final SecureRandom INSTANCE;
		static {
			try {
				INSTANCE = SecureRandom.getInstanceStrong();
			} catch (final NoSuchAlgorithmException e) {
				throw new Error("Failed to create secure random generator!", e);
			}
		}
	}

	private static class CipherHolder {
		public static final Cipher INSTANCE;
		static {
			try {
				INSTANCE = Cipher.getInstance(ALGORITHM_NAME_CIPHER);
				INSTANCE.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(SCRAMBLER_KEY, "DES"));
			} catch (final GeneralSecurityException e) {
				throw new Error("Failed to create Cipher instance!", e);
			}
		}
	}

	private static final Object mutex = new Object();
	private static long lastTimestamp = -1L;

	private SaltGenerator() {
		throw new IllegalAccessError();
	}

	public static byte[] generateSalt(final int size) {
		if (size < 12) {
			throw new IllegalArgumentException("Salt size is too small!");
		}

		final byte[] saltArray = new byte[size];
		SecureRandomHolder.INSTANCE.nextBytes(saltArray);
		ByteBuffer.wrap(saltArray).putLong(0, nextTimestamp());

		synchronized(CipherHolder.INSTANCE) {
			try {
				CipherHolder.INSTANCE.doFinal(saltArray, 0, Long.BYTES, saltArray, 0);
			} catch (final GeneralSecurityException e) {
				throw new RuntimeException("Failed to encrypt salt!", e);
			}
		}

		return saltArray;
	}

	private static long nextTimestamp() {
		for (;;) {
			synchronized(mutex) {
				long timestamp = System.nanoTime();
				if (timestamp > lastTimestamp) {
					return (lastTimestamp = timestamp);
				}
			}
			Thread.yield();
		}
	}
}
