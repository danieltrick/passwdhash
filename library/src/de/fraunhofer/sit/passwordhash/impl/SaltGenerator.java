package de.fraunhofer.sit.passwordhash.impl;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SaltGenerator {

	private static final String ALGORITHM_NAME_CIPHER = "DES/ECB/NoPadding";

	private static final byte[] SCRAMBLER_KEY = new byte[] {
		(byte)0x4F, (byte)0x27, (byte)0x8B, (byte)0x51,
		(byte)0x88, (byte)0x8C, (byte)0x1E, (byte)0xE2 
	};

	private static class RandomHolder {
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
	private static long lastTimestamp = Instant.EPOCH.toEpochMilli();

	private SaltGenerator() {
		throw new IllegalAccessError();
	}

	public static byte[] generateSalt(final int size) {
		if (size < 1) {
			throw new IllegalArgumentException("Salt size is too small!");
		}

		final int blocks = Math.addExact(size, Integer.BYTES - 1) / Integer.BYTES;
		final ByteBuffer buffer = ByteBuffer.allocate(Math.multiplyExact(Integer.BYTES, blocks));

		buffer.putLong(nextTimestamp());

		while (buffer.remaining() >= Integer.BYTES) {
			buffer.putInt(RandomHolder.INSTANCE.nextInt());
		}

		final byte[] saltArray = buffer.array();

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
		synchronized(mutex) {
			long timestamp = Instant.now().toEpochMilli();
			while (timestamp == lastTimestamp) {
				Thread.yield();
				timestamp = Instant.now().toEpochMilli();
			}
			return lastTimestamp = timestamp;
		}
	}
}
