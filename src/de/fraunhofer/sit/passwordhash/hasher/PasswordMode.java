package de.fraunhofer.sit.passwordhash.hasher;

public enum PasswordMode {
	AES(1L);

	public final long id;

	PasswordMode(final long id) {
		this.id = id;
	}

	public static PasswordMode parseId(final long id) {
		for (final PasswordMode mode : PasswordMode.values()) {
			if (Long.compareUnsigned(id, mode.id) == 0) {
				return mode;
			}
		}
		throw new IllegalArgumentException("Invalid mode!");
	}
}
