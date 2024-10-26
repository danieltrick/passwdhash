package de.fraunhofer.sit.passwordhash.utils;

import java.util.Arrays;

import javax.crypto.SecretKey;

public final class KeyHolder implements SecretKey {
	public byte[] bytes;

	private static final long serialVersionUID = 1L;

	public KeyHolder(final int keySize) {
		bytes = new byte[keySize];
	}

	@Override
	public String getAlgorithm() {
		return "Rijndael";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		return bytes;
	}

	@Override
	public void destroy() {
		Arrays.fill(bytes, (byte) 0);
	}
}
