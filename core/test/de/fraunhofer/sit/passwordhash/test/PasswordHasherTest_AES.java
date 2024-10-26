package de.fraunhofer.sit.passwordhash.test;

import static de.fraunhofer.sit.passwordhash.utils.HexString.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;

public class PasswordHasherTest_AES extends PasswordHasherTest {

	protected final byte[] SALT_0 = hexToBytes("00000000000000000000000000000000");
	protected final byte[] SALT_1 = hexToBytes("55555555555555555555555555555555");
	protected final byte[] SALT_2 = hexToBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	protected final byte[] SALT_3 = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	private final byte[] EXPECTED_EMPTY_0 = hexToBytes("4C8F4A2C23D460D23D5FC458432D151839FC1EA508C07FAE5E2E1B2C199107ED");
	private final byte[] EXPECTED_EMPTY_1 = hexToBytes("9AF87058E92DA624624741A6CAAC8D329993E41932D8B56E3AB916E1B3E43776");
	private final byte[] EXPECTED_EMPTY_2 = hexToBytes("AC1C7D59FECEC17DB3D977FF01969B8602F28D28815F8504FA8DE6F9C8D0B5CE");
	private final byte[] EXPECTED_EMPTY_3 = hexToBytes("B7D81CC2FD5E5AFCAE71AB53E101A983F736D15D5752CBB31EA434CC34E52C5E");

	private final byte[] EXPECTED_ST024_0 = hexToBytes("B2365D3B45FF3014F764F5A847A0470BCAF13FC23230B25EB67EA31B83FD9BF2");
	private final byte[] EXPECTED_ST024_1 = hexToBytes("C9919411DC7FFF3B613597C6CCF937B16848A3B70C75F2CB1D754DF7D8D5DD1E");
	private final byte[] EXPECTED_ST024_2 = hexToBytes("9D06F3FE8121A8355308DE7AD31A01B879EC50E73349E56E34ACA86396C40E58");
	private final byte[] EXPECTED_ST024_3 = hexToBytes("00A36E8CC079A82FA2E6033794A24A928ABB4EF496AEC0F1AA9E56633729E9C0");

	private final byte[] EXPECTED_ST344_0 = hexToBytes("F7F517834F6456B8C39F455D9A1F9A853A36FF4C2A1C2905F14BE811FAA7A3A2");
	private final byte[] EXPECTED_ST344_1 = hexToBytes("95C469AC2DE8EDEF8414224F777027733C1B6CDD18C234ECB11AB87B7C5E1F1D");
	private final byte[] EXPECTED_ST344_2 = hexToBytes("606F75AA664EA4222F06C245167807CA8B7E52CDDC68378BC0E95A68D4C41929");
	private final byte[] EXPECTED_ST344_3 = hexToBytes("12461F5E1C637DA15260CFEA563A91865C67E353338FDF5D7FD6F15508465BC9");

	private final byte[] EXPECTED_ST352_0 = hexToBytes("56A5C311875F2A7BB4664CDD586799D4592850E294BC9F8663D5E6F095EA34FB");
	private final byte[] EXPECTED_ST352_1 = hexToBytes("EC56C238FEAA6C3A46C101E422783DE812838EBCE84E9A310CCDF1ADF4A15C19");
	private final byte[] EXPECTED_ST352_2 = hexToBytes("5F2E24659EF00416870772ACA49B46A3CCD13602C46FF9DF8C456DC0CA9BBB8D");
	private final byte[] EXPECTED_ST352_3 = hexToBytes("47CE39BC8EB8CCA884FC62E774BFA1BBEB517FF8B469FCC7076BB327AA5654D6");

	private final byte[] EXPECTED_ST448_0 = hexToBytes("7A6A8B761ADA72D7155BC4382D71D6A503A8AF84D9C2C01B25375A41BADD414C");
	private final byte[] EXPECTED_ST448_1 = hexToBytes("13C94D99FD910DE21DECC2C696D8D4E6E5A5B7D23094AD299B243BA99D974665");
	private final byte[] EXPECTED_ST448_2 = hexToBytes("05F6E03BE2EED450F1DDB9372332C171CE49B88494167EE06BA8EABF19C3AA11");
	private final byte[] EXPECTED_ST448_3 = hexToBytes("B57105BBBFD1F275ACFB2022B14C3A5B4166EFA0688838A000A5C3ADE9FBD956");

	private final byte[] EXPECTED_ST896_0 = hexToBytes("BC46549B52990F9B62D0C91955D8E0132B6FDBC06E7EA4AFE1DB7BCDF3FAC72D");
	private final byte[] EXPECTED_ST896_1 = hexToBytes("6C4F2D72C0241AAE9999748A9F338F91B0E68018F5C1AA0BB9DFCA9CDF1725B5");
	private final byte[] EXPECTED_ST896_2 = hexToBytes("9CAF1EF74DFF9B17247DB4CB70068AF14C323CA052D6B69EFB5DC8B7041B504E");
	private final byte[] EXPECTED_ST896_3 = hexToBytes("4FDBFCA244C0DD5150983E971DD79C2036D04CF9E5938B8254A4E127FE6D4D19");

	@RepeatedTest(4)
	void testHashEmpty(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_0, EXPECTED_EMPTY_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_1, EXPECTED_EMPTY_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_2, EXPECTED_EMPTY_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_EMPTY, SALT_3, EXPECTED_EMPTY_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST024(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST024, SALT_0, EXPECTED_ST024_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST024, SALT_1, EXPECTED_ST024_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST024, SALT_2, EXPECTED_ST024_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST024, SALT_3, EXPECTED_ST024_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST344(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST344, SALT_0, EXPECTED_ST344_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST344, SALT_1, EXPECTED_ST344_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST344, SALT_2, EXPECTED_ST344_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST344, SALT_3, EXPECTED_ST344_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST352(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST352, SALT_0, EXPECTED_ST352_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST352, SALT_1, EXPECTED_ST352_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST352, SALT_2, EXPECTED_ST352_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST352, SALT_3, EXPECTED_ST352_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST448(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST448, SALT_0, EXPECTED_ST448_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST448, SALT_1, EXPECTED_ST448_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST448, SALT_2, EXPECTED_ST448_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST448, SALT_3, EXPECTED_ST448_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@RepeatedTest(4)
	void testHashST896(final RepetitionInfo info) {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);

		for (int iteration = 0; iteration < 2; ++iteration) {
			switch (info.getCurrentRepetition()) {
			case 1:
				doTestHash(hasher, MESSAGE_ST896, SALT_0, EXPECTED_ST896_0);
				break;
			case 2:
				doTestHash(hasher, MESSAGE_ST896, SALT_1, EXPECTED_ST896_1);
				break;
			case 3:
				doTestHash(hasher, MESSAGE_ST896, SALT_2, EXPECTED_ST896_2);
				break;
			case 4:
				doTestHash(hasher, MESSAGE_ST896, SALT_3, EXPECTED_ST896_3);
				break;
			default:
				fail(); /* not supposed to happen! */
			}
		}
	}

	@Test
	public void testInvalidArgs() {
		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES);
		assertThrows(IllegalArgumentException.class, () -> hasher.compute(MESSAGE_EMPTY, new byte[15]));
	}

	@AfterEach
	public void finalizerFunction() {
		System.out.println();
	}
}
