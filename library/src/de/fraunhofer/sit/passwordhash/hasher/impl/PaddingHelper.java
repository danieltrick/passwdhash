package de.fraunhofer.sit.passwordhash.hasher.impl;

import java.util.Arrays;

public class PaddingHelper {

	public static byte[] addPadding(final int blockSize, final byte[] plainData) {
		if (plainData == null) {
			throw new NullPointerException("plainData");
		}
		if ((blockSize < 0) || (blockSize > 0x7F)) {
			throw new IllegalArgumentException("Invalid block size!");
		}

		final int paddingBytes = blockSize - (plainData.length % blockSize);
		final byte[] paddedData = Arrays.copyOf(plainData, plainData.length + paddingBytes);
		final byte byteValue = (byte) paddingBytes;

		for (int iPos = plainData.length; iPos < paddedData.length; ++iPos) {
			paddedData[iPos] = byteValue;
		}

		return paddedData;
	}
}
