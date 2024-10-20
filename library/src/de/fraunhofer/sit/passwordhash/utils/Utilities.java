package de.fraunhofer.sit.passwordhash.utils;

import java.util.Arrays;
import java.util.Locale;

public class Utilities {

	private Utilities() {
		throw new UnsupportedOperationException();
	}

	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

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

		final char[] hexChars = hexString.trim().toUpperCase(Locale.US).toCharArray();
		if ((hexChars.length % 2) != 0) {
			throw new IllegalArgumentException("length of hex string must be a multiple of two!");
		}

		final byte[] bytes = new byte[hexChars.length / 2];
		int posIn = 0, posOut = 0;

		while (posIn < hexChars.length) {
			final int valueHi = Arrays.binarySearch(HEX_ARRAY, hexChars[posIn++]);
			final int valueLo = Arrays.binarySearch(HEX_ARRAY, hexChars[posIn++]);
			if ((valueHi < 0) || (valueLo < 0)) {
				throw new IllegalArgumentException("invalid hex character encountered!");
			}
			bytes[posOut++] = (byte)((valueHi << 4) | valueLo);
		}

		return bytes;
	}

	public static int addSaturating(final int a, final int b) {
		try {
			return Math.addExact(a, b);
		} catch (final ArithmeticException e) {
			return Integer.MAX_VALUE;
		}
	}

	public static long addSaturating(final long a, final long b) {
		try {
			return Math.addExact(a, b);
		} catch (final ArithmeticException e) {
			return Long.MAX_VALUE;
		}
	}

	public static int multiplySaturating(final int a, final int b) {
		try {
			return Math.multiplyExact(a, b);
		} catch (final ArithmeticException e) {
			return Integer.MAX_VALUE;
		}
	}
}
