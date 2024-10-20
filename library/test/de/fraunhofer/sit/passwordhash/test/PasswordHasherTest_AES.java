package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;

public class PasswordHasherTest_AES {

	private static final byte[] SALT_0 = hexToBytes("00000000000000000000000000000000");
	private static final byte[] SALT_1 = hexToBytes("55555555555555555555555555555555");
	private static final byte[] SALT_2 = hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	private static final byte[] SALT_3 = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	private static final String MESSAGE_EMPTY = "";
	private static final String MESSAGE_ST024 = "abc";
	private static final String MESSAGE_ST344 = "The quick brown fox jumps over the lazy dog";
	private static final String MESSAGE_ST352 = "The quick brown fox jumps over the lazy dog.";
	private static final String MESSAGE_ST448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private static final String MESSAGE_ST896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	private static final byte[] EXPECTED_EMPTY_0 = hexToBytes("53650C538B2F88292A57D5E1E06FD6E04D7E966331234A1931BBFC492C48F9B2");
	private static final byte[] EXPECTED_EMPTY_1 = hexToBytes("E5FBDD0A392856A4E223D612E82180FE864F8CCDF9425A5524D2DEA4845803F1");
	private static final byte[] EXPECTED_EMPTY_2 = hexToBytes("1897BD09B0C9B83EB9765EBF55DB72D0B788E41F7B9944B8568163E0072698AF");
	private static final byte[] EXPECTED_EMPTY_3 = hexToBytes("3807A197D8E378B3E59547CB45ED5B6BCA6D70F9EC1C9D181B2ED5FA998D0DDE");

	private static final byte[] EXPECTED_ST024_0 = hexToBytes("B2959A7F691D72CEEE8E58E6F465071CEF0691E692683074FAFD35797F44E098");
	private static final byte[] EXPECTED_ST024_1 = hexToBytes("1994D31E1FEFD35739878B60F236E11A0473FE1CEAEEF727C1485C1D4232718B");
	private static final byte[] EXPECTED_ST024_2 = hexToBytes("A3393E20F4508ACDC333BD7D248A5B4C5787E1DC9C869B258C2003C4BC3AD3A2");
	private static final byte[] EXPECTED_ST024_3 = hexToBytes("E661CB85BD25C3CEC50D484AC0FCC9DD8A4FCE2276DCC361B0A35AAED704E492");

	private static final byte[] EXPECTED_ST344_0 = hexToBytes("BE2F3A4C2CFA1E88E715A695B5F56393DBC61FD508056E894883707ACAE4A14A");
	private static final byte[] EXPECTED_ST344_1 = hexToBytes("F8D462362D5A24EAA136BD03242BA45C3823B82E7ABBC567C93ED68B30B5E913");
	private static final byte[] EXPECTED_ST344_2 = hexToBytes("2CAE093195EE4B919CFEB1B3D3B8734B1F42A120A583D663DBBE474A3FC8DE42");
	private static final byte[] EXPECTED_ST344_3 = hexToBytes("070096D8FD8251715EC77AFB9591E953DA6BCC2B0D5390467E9076FC4F74760F");

	private static final byte[] EXPECTED_ST352_0 = hexToBytes("BA75233D1D7D34F4D25A51173B5CD6C16D94116811DAFD33C79B4F6B39C1A460");
	private static final byte[] EXPECTED_ST352_1 = hexToBytes("9C51BFCD2E909F47E0A50298F48FED1A4F212F9E59357C8073CE4F7D9754DF4C");
	private static final byte[] EXPECTED_ST352_2 = hexToBytes("8D7B1DAB0D617D40D38AE1FD4E6C89A18E092DBC901772143EA76262646AB96E");
	private static final byte[] EXPECTED_ST352_3 = hexToBytes("283BD939F699B5C3D42B6C89D7C192F56A0E2FBB12804BCB98DD1D2E85DF8057");

	private static final byte[] EXPECTED_ST448_0 = hexToBytes("FBE5095EC67EE766DC4A43227330DBB936011F35A6400FA30B8C7B316476976A");
	private static final byte[] EXPECTED_ST448_1 = hexToBytes("A9E637A09C87F13BDBE890E9F42C9AE8DFFB25569F1316AB35BB49B9183F34A9");
	private static final byte[] EXPECTED_ST448_2 = hexToBytes("2C799269564324E1BA3AE6E94BDEB0863CD6C0B76A311673179C45CAEC2B6591");
	private static final byte[] EXPECTED_ST448_3 = hexToBytes("EC3171ECEBD7534059B1F8AB972C58C1D2DB944B9D3739A1574969B04B1289E8");

	private static final byte[] EXPECTED_ST896_0 = hexToBytes("EF20E985813558021A0EF5AA159D0BF46E37F780CF46A8E1EA66C40E00422315");
	private static final byte[] EXPECTED_ST896_1 = hexToBytes("614EAA53C53D17FCF56447B81AE8BC63B1F09F5D13818A8372EBE50185E02C6D");
	private static final byte[] EXPECTED_ST896_2 = hexToBytes("BFAD9FB61A8A466A46301C1702E43D68E8B8BFA4BD12CFF72D7CF42E631811F7");
	private static final byte[] EXPECTED_ST896_3 = hexToBytes("D5666BCEAA6960D06D945BB6C4011E3871EB677D22B8E53AF6376A8571A9E6AA");

	@Test
	void testHashEmpty() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_EMPTY, SALT_0, EXPECTED_EMPTY_0);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_1, EXPECTED_EMPTY_1);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_2, EXPECTED_EMPTY_2);
			doTestHash(hasher, MESSAGE_EMPTY, SALT_3, EXPECTED_EMPTY_3);
		}
	}

	@Test
	void testHashST024() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST024, SALT_0, EXPECTED_ST024_0);
			doTestHash(hasher, MESSAGE_ST024, SALT_1, EXPECTED_ST024_1);
			doTestHash(hasher, MESSAGE_ST024, SALT_2, EXPECTED_ST024_2);
			doTestHash(hasher, MESSAGE_ST024, SALT_3, EXPECTED_ST024_3);
		}
	}

	@Test
	void testHashST344() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST344, SALT_0, EXPECTED_ST344_0);
			doTestHash(hasher, MESSAGE_ST344, SALT_1, EXPECTED_ST344_1);
			doTestHash(hasher, MESSAGE_ST344, SALT_2, EXPECTED_ST344_2);
			doTestHash(hasher, MESSAGE_ST344, SALT_3, EXPECTED_ST344_3);
		}
	}

	@Test
	void testHashST352() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST352, SALT_0, EXPECTED_ST352_0);
			doTestHash(hasher, MESSAGE_ST352, SALT_1, EXPECTED_ST352_1);
			doTestHash(hasher, MESSAGE_ST352, SALT_2, EXPECTED_ST352_2);
			doTestHash(hasher, MESSAGE_ST352, SALT_3, EXPECTED_ST352_3);
		}
	}

	@Test
	void testHashST448() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST448, SALT_0, EXPECTED_ST448_0);
			doTestHash(hasher, MESSAGE_ST448, SALT_1, EXPECTED_ST448_1);
			doTestHash(hasher, MESSAGE_ST448, SALT_2, EXPECTED_ST448_2);
			doTestHash(hasher, MESSAGE_ST448, SALT_3, EXPECTED_ST448_3);
		}
	}

	@Test
	void testHashST896() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 3; ++iteration) {
			doTestHash(hasher, MESSAGE_ST896, SALT_0, EXPECTED_ST896_0);
			doTestHash(hasher, MESSAGE_ST896, SALT_1, EXPECTED_ST896_1);
			doTestHash(hasher, MESSAGE_ST896, SALT_2, EXPECTED_ST896_2);
			doTestHash(hasher, MESSAGE_ST896, SALT_3, EXPECTED_ST896_3);
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
		Assert.assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	private static void doTestHash(final PasswordHasher hasher, final String message, final byte[] salt, final byte[] expected) {
		Assert.assertNotNull(message);
		Assert.assertNotNull(salt);
		Assert.assertNotNull(expected);

		Assert.assertTrue(salt.length == 16);
		Assert.assertTrue(expected.length == 32);

		final byte[] computed = hasher.compute(message, salt);
		System.out.printf("%s <- \"%s\"%n", bytesToHex(computed), message);

		Assert.assertArrayEquals(expected, computed);
	}
}
