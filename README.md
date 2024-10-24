# Password Hash

A secure password hashing library for Java, based on repeated application of ciphers.

## Supported ciphers:

| **Mode**                | **Description**                                |
| ----------------------- | ---------------------------------------------- |
| `PasswordMode.AES`      | AES-256 cipher (Rijndael)                      |
| `PasswordMode.ChaCha20` | ChaCha20 stream ciphers by Daniel J. Bernstein |

## Getting started

### Using the "high level" API:

```java
private static final String PASSWORD = "PL6aZOztoVYUyi9";

public static void main(String[] args) {
	// Create a new hash from password, includes a new unique salt
	final String hash = PasswordManager.create(PASSWORD);
	System.out.println("Encoded hash: \"" + hash + "\"");

	// Verify a password, using an existing salted hash value
	final boolean isValid = PasswordManager.verify(PASSWORD, hash);
	System.out.println("Verification: " + isValid);
}
```

Example output:
```
Encoded hash: "1:C9pFHRXS4hjEM9NH8YvM6g:L5o8hV-YLLdrwV-4j0rXgVF7vL5n3W-7znxXDgJlHEw"
Verification: true
```

### Using the "low level" API:

```java
public static void main(String[] args) {
	// Create a new "AES" PasswordHasher instance
	final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

	// Generate a fresh salt value, the result is guaranteed to be unique
	final byte[] salt = hasher.generateSalt();
	System.out.println("Salt value: " + HexString.bytesToHex(salt));

	// Compute the hash value from the given password and the given salt
	final byte[] hash = hasher.compute(PASSWORD, salt);
	System.out.println("Hash value: " + HexString.bytesToHex(hash));
}
```

Example output:
```
Salt value: E48EFAD261EDC601C81466AEB7C7A181
Hash value: 8601ED4EACDEA9AEE9B7B98FD2C472C340477A439DE4F1047CB573152A34169E
```

## License

This work is released under the [**3-Clause BSD License**](https://opensource.org/license/bsd-3-clause) (SPDX short identifier: `BSD-3-Clause`).
