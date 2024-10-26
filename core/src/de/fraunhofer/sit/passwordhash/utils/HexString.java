package de.fraunhofer.sit.passwordhash.utils;

import java.util.Arrays;

public class HexString {

	private HexString() {
		throw new UnsupportedOperationException();
	}

	private static final char[] HEX_ARRAY = "0123456789ABCDEFabcdef".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		if (bytes == null) {
			throw new NullPointerException("byte array must not be null!");
		}

		final StringBuilder hexChars = new StringBuilder(Math.multiplyExact(bytes.length, 2));

		for (final byte b : bytes) {
			hexChars.append(HEX_ARRAY[(b & 0xFF) >>> 4]);
			hexChars.append(HEX_ARRAY[(b & 0xFF) & 0xF]);
		}

		return hexChars.toString();
	}

	public static byte[] hexToBytes(final String hexString) {
		if (hexString == null) {
			throw new NullPointerException("byte array must not be null!");
		}

		final String trimmedString = hexString.trim();
		final int length;
		if (((length = trimmedString.length()) % 2) != 0) {
			throw new IllegalArgumentException("length of hex string must be a multiple of two!");
		}

		final byte[] bytes = new byte[length / 2];
		int posIn = 0, posOut = 0;

		while (posIn < length) {
			final int valueHi = parseHexChar(trimmedString.charAt(posIn++));
			final int valueLo = parseHexChar(trimmedString.charAt(posIn++));
			if ((valueHi < 0) || (valueLo < 0)) {
				throw new IllegalArgumentException("invalid hex character encountered!");
			}
			bytes[posOut++] = (byte)((valueHi << 4) | valueLo);
		}

		return bytes;
	}

	private static int parseHexChar(final char c) {
		final int value = Arrays.binarySearch(HEX_ARRAY, c);
		if (value > 15) {
			return value - 6; /*lower case*/
		}
		return value;
	}
}
