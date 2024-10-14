package de.fraunhofer.sit.passwordhash.hasher;

public interface PasswordHasher {

	byte[] compute(final String text, final byte[] salt);
	byte[] compute(final byte[] data, final byte[] salt);

	byte[] generateSalt();
}
