import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Scanner;

public class Chall {

	private final static String BANNER = """
			--------
			> Options:
			  1. Sign message
			  2. Verify signature
			  3. Quit
			> Enter number:""";

	private final static String TARGET_MSG = "Welcome_to_IERAE_DAYS_2023!!";

	private final static String FLAG = System.getenv("FLAG");

	private static KeyPair generateKey() throws GeneralSecurityException {
		// Create "key pair generator" with elliptic curve algorithm
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

		// Use secp384r1 parameter explicitly. Detailed parameters:
		// https://neuromancer.sk/std/nist/P-384
		final ECGenParameterSpec ec_spec = new ECGenParameterSpec("secp384r1");

		kpg.initialize(ec_spec, new SecureRandom());
		return kpg.generateKeyPair();
	}

	private static Optional<byte[]> sign(final String msg, final PrivateKey priv_key) throws GeneralSecurityException {
		// Getting flag is not easy
		if (msg.contains("IERAE")) {
			System.out.println("> Sorry, we cannot give you signatures :P");
			return Optional.empty();
		}

		final Signature sig = Signature.getInstance("SHA256WithECDSAInP1363Format");
		sig.initSign(priv_key, new SecureRandom());
		sig.update(msg.getBytes());

		return Optional.of(sig.sign());
	}

	private static boolean verify(final String msg, final String signature, final PublicKey pub_key)
			throws GeneralSecurityException {
		if (signature.isEmpty()) {
			return false;
		}

		try {
			final Signature sig = Signature.getInstance("SHA256WithECDSAInP1363Format");
			sig.initVerify(pub_key);
			sig.update(msg.getBytes());
			return sig.verify(HexFormat.of().parseHex(signature));
		} catch (final IllegalArgumentException e) {
			// To avoid odd length signature
			return false;
		}
	}

	public static void main(final String[] args) {
		assert System.getProperty("java.version").equals("17.0.2");

		try (final Scanner scan = new Scanner(System.in)) {
			final KeyPair keys = Chall.generateKey();

			final PublicKey pub_key = keys.getPublic();
			final PrivateKey priv_key = keys.getPrivate();
			System.out.println("> Here is your public (verification) key:");
			System.out.println(pub_key);

			while (true) {
				System.out.println(Chall.BANNER);
				int num;
				try {
					num = Integer.parseInt(scan.nextLine());
				} catch (final NumberFormatException ex) {
					System.out.println("> Invalid number. Try Again");
					continue;
				}

				switch (num) {
				case 1 -> {
					System.out.println("> Enter message:");
					final String your_msg = scan.nextLine();
					Chall.sign(your_msg, priv_key)
							.ifPresent(sig -> System.out.printf("> Signature: %s\n", HexFormat.of().formatHex(sig)));
				}
				case 2 -> {
					System.out.println("> Enter message:");
					final String your_msg = scan.nextLine();

					System.out.println("> Enter signature (Hex format):");
					final String your_signature = scan.nextLine();

					if (Chall.verify(your_msg, your_signature, pub_key)) {
						System.out.println("> Valid signature!");
						if (your_msg.equals(Chall.TARGET_MSG)) {
							System.out.printf("> Congraturations! %s\n", Chall.FLAG);
							System.exit(0);
						}
					} else {
						System.out.println("> Invalid signature");
					}
				}
				default -> {
					System.out.println("> bye!");
					System.exit(0);
				}
				}
			}
		} catch (final GeneralSecurityException e) {
			System.out.println(e);
			System.exit(1);
		}
	}
}