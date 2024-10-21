# Password Hash

A secure password hashing library for Java.

## Getting started

### Using the "high level" API:

```java
private static final String PASSWORD = "PL6aZOztoVYUyi9";

public static void main(String[] args) {
	final String hash = PasswordManager.create(PASSWORD);
	System.out.println("Encoded hash: \"" + hash + "\"");

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
	final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
	final byte[] salt = hasher.generateSalt();
	final byte[] hash = hasher.compute(PASSWORD, salt);

	System.out.println("Salt value: " + HexString.bytesToHex(salt));
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
