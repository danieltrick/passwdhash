package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;

public class PasswordHasherTest_ChaCha20 {

	private static final byte[] SALT_0 = hexToBytes("000000000000000000000000");
	private static final byte[] SALT_1 = hexToBytes("555555555555555555555555");
	private static final byte[] SALT_2 = hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAA");
	private static final byte[] SALT_3 = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFF");

	private static final String MESSAGE_EMPTY = "";
	private static final String MESSAGE_ST024 = "abc";
	private static final String MESSAGE_ST344 = "The quick brown fox jumps over the lazy dog";
	private static final String MESSAGE_ST352 = "The quick brown fox jumps over the lazy dog.";
	private static final String MESSAGE_ST448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private static final String MESSAGE_ST896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	private static final byte[] EXPECTED_EMPTY_0 = hexToBytes("E5E80EDC857971429F579E18BAE76B574DE895F16FCBC9F56D2320A6D26FA691");
	private static final byte[] EXPECTED_EMPTY_1 = hexToBytes("4F9E4EB8990894FB9310931859DD6B4EDB0B86652ECCE1D3C071ECA045548F8E");
	private static final byte[] EXPECTED_EMPTY_2 = hexToBytes("CFC9A4AE077ECFCC7420B978F240C15C9B26E720F39B4DFCE002507AA2DC1BA6");
	private static final byte[] EXPECTED_EMPTY_3 = hexToBytes("E8A52A5DE910E099D4CA4C2F6BD88AC3DD4482B5C5862FB095A73DF76EA88876");

	private static final byte[] EXPECTED_ST024_0 = hexToBytes("42FA216596F1C6200FAAFB1BE6C4B102E447D2FCC67C1331B25992066F3C3412");
	private static final byte[] EXPECTED_ST024_1 = hexToBytes("AEEAEEA72DE4690E8C163FF2878B8821213A38B4141DB1417B83E5E29F7AEBA6");
	private static final byte[] EXPECTED_ST024_2 = hexToBytes("838D0C4FA45F92C6AC49F235BE07B782D6B8204FB94ADE03B2284853139E6FBD");
	private static final byte[] EXPECTED_ST024_3 = hexToBytes("5187E442B62D34EEDD961121934F17961718795516669B4128941AA455061525");

	private static final byte[] EXPECTED_ST344_0 = hexToBytes("64B49D6240381A244DFEB6A9A0B5C1D1150C741B8BA760F89A9C519AD79D7A2D");
	private static final byte[] EXPECTED_ST344_1 = hexToBytes("AB03844230DF36366C5AC0798AC5232B67D8A9E9B6163A69F3F625BF6172391E");
	private static final byte[] EXPECTED_ST344_2 = hexToBytes("501912B2B0FC62BBEA7F0E74B1A226B935BC555343758F3CF0FCDA84973D9B8D");
	private static final byte[] EXPECTED_ST344_3 = hexToBytes("0540AA178CF83923AEBFB849595D780620763DC79FDA354B589FD3F47EECBAA3");

	private static final byte[] EXPECTED_ST352_0 = hexToBytes("72C60D0C0FB4DDBDC269D9F7DC333948A054DCADFDE88178A24FA0D620EC2072");
	private static final byte[] EXPECTED_ST352_1 = hexToBytes("B2C0A1B954868191E0BA963B615C9C80C7E416F49B6DAE3725C8B101983D747D");
	private static final byte[] EXPECTED_ST352_2 = hexToBytes("A942950F51DFCB3DDB1B9F0938DC7E2C3BA9EA31AAEE2EBA6AF1CA6CABACC0B7");
	private static final byte[] EXPECTED_ST352_3 = hexToBytes("E6C9D1C0100503526AB7E7AE8709C0E9DB47A3B627D655ED06C216424D0E884B");

	private static final byte[] EXPECTED_ST448_0 = hexToBytes("FDCB2797EA6544BABF642356BAB9CFBF1C07B79294CD2D5A34C82A60EE066738");
	private static final byte[] EXPECTED_ST448_1 = hexToBytes("9550F27E920D0A2AA954C53D592E3F3D1093763CB3B62B72B7C7A5CABF9580D6");
	private static final byte[] EXPECTED_ST448_2 = hexToBytes("62A8A01DF1C4610F6BF0CB52C639DC0B4A5817838A62166D3BD163EE725ACA4A");
	private static final byte[] EXPECTED_ST448_3 = hexToBytes("42068C050C91759CD58C2D98613A286706CF53BF88BFAB00F5F45C94F0F44781");

	private static final byte[] EXPECTED_ST896_0 = hexToBytes("A4A58BE4069158BCF1B88884EB82BBFAD73D5CA64716A16B4F071809D2602240");
	private static final byte[] EXPECTED_ST896_1 = hexToBytes("C9E64F43C71905282D13CF62016AD9FC2EA4C68D0C7AB3EAC56778EF182B4763");
	private static final byte[] EXPECTED_ST896_2 = hexToBytes("38E00D37B6A3EBA1978A962109B5121AEC41DC299EA2B5FD4554619200CCB976");
	private static final byte[] EXPECTED_ST896_3 = hexToBytes("576A4660F06483DDB0565D395DA9685E9016D221495EC8D4BFA8D93962E96AA7");

	@Test
	void testHashEmpty() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_EMPTY, SALT_0, EXPECTED_EMPTY_0);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_1, EXPECTED_EMPTY_1);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_2, EXPECTED_EMPTY_2);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_3, EXPECTED_EMPTY_3);
		}
	}

	@Test
	void testHashST024() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST024, SALT_0, EXPECTED_ST024_0);
			doTestHash(hasher, MESSAGE_ST024, SALT_1, EXPECTED_ST024_1);
			doTestHash(hasher, MESSAGE_ST024, SALT_2, EXPECTED_ST024_2);
			doTestHash(hasher, MESSAGE_ST024, SALT_3, EXPECTED_ST024_3);
		}
	}

	@Test
	void testHashST344() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST344, SALT_0, EXPECTED_ST344_0);
			doTestHash(hasher, MESSAGE_ST344, SALT_1, EXPECTED_ST344_1);
			doTestHash(hasher, MESSAGE_ST344, SALT_2, EXPECTED_ST344_2);
			doTestHash(hasher, MESSAGE_ST344, SALT_3, EXPECTED_ST344_3);
		}
	}

	@Test
	void testHashST352() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST352, SALT_0, EXPECTED_ST352_0);
			doTestHash(hasher, MESSAGE_ST352, SALT_1, EXPECTED_ST352_1);
			doTestHash(hasher, MESSAGE_ST352, SALT_2, EXPECTED_ST352_2);
			doTestHash(hasher, MESSAGE_ST352, SALT_3, EXPECTED_ST352_3);
		}
	}

	@Test
	void testHashST448() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST448, SALT_0, EXPECTED_ST448_0);
			doTestHash(hasher, MESSAGE_ST448, SALT_1, EXPECTED_ST448_1);
			doTestHash(hasher, MESSAGE_ST448, SALT_2, EXPECTED_ST448_2);
			doTestHash(hasher, MESSAGE_ST448, SALT_3, EXPECTED_ST448_3);
		}
	}

	@Test
	void testHashST896() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST896, SALT_0, EXPECTED_ST896_0);
			doTestHash(hasher, MESSAGE_ST896, SALT_1, EXPECTED_ST896_1);
			doTestHash(hasher, MESSAGE_ST896, SALT_2, EXPECTED_ST896_2);
			doTestHash(hasher, MESSAGE_ST896, SALT_3, EXPECTED_ST896_3);
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.ChaCha20);
		assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	private static void doTestHash(final PasswordHasher hasher, final String message, final byte[] salt, final byte[] expected) {
		assertNotNull(message);
		assertNotNull(salt);
		assertNotNull(expected);

		assertTrue(salt.length == 12);
		assertTrue(expected.length == 32);

		final byte[] computed = hasher.compute(message, salt);
		System.out.printf("%s <-- \"%s\"%n", bytesToHex(computed), message);

		assertArrayEquals(expected, computed);
	}

	@AfterEach
	public void finalizerFunction() {
		System.out.println();
	}
}
