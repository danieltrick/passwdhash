package de.fraunhofer.sit.passwordhash.cli.example;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;
import de.fraunhofer.sit.passwordhash.utils.HexString;

public class Main {

	private static final String PASSWORD = "PL6aZOztoVYUyi9";

	public static void example1() {
		final String hash= PasswordManager.create(PASSWORD);
		System.out.println("Encoded hash: \"" + hash + '"');

		final boolean isValid = PasswordManager.verify(PASSWORD, hash);
		System.out.println("Verification: " + isValid);
	}

	public static void example2() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
		final byte[] salt = hasher.generateSalt();
		final byte[] hash = hasher.compute(PASSWORD, salt);
		
		System.out.println("Salt value: " + HexString.bytesToHex(salt));
		System.out.println("Hash value: " + HexString.bytesToHex(hash));
	}

	public static void main(String[] args) {
		example1();
		example2();
	}
}
