package de.fraunhofer.sit.passwordhash.impl;

import java.math.BigInteger;

public class PrimeFinder {

	private static final long BIGGEST_LONG_PRIME = 9223372036854775783L;
	
	public static long findPrime(final long initialValue) {
		if (initialValue < 0L) {
			throw new IllegalArgumentException("Initial value must not be negative!");
		}

		if (initialValue >= BIGGEST_LONG_PRIME) {
			return BIGGEST_LONG_PRIME;
		}

		BigInteger value = BigInteger.valueOf(Math.max(2L, initialValue));
		while (!value.isProbablePrime(Integer.MAX_VALUE)) {
			value = value.nextProbablePrime();
		}

		return value.longValueExact();
	}
}
