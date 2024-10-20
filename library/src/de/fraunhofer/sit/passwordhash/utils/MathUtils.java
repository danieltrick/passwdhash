package de.fraunhofer.sit.passwordhash.utils;

public class MathUtils {

	private MathUtils() {
		throw new UnsupportedOperationException();
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

	public static long multiplySaturating(final long a, final long b) {
		try {
			return Math.multiplyExact(a, b);
		} catch (final ArithmeticException e) {
			return Integer.MAX_VALUE;
		}
	}
}
