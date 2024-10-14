package de.fraunhofer.sit.passwordhash;

import static de.fraunhofer.sit.passwordhash.utils.Utilities.bytesToHex;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.sun.jna.platform.win32.Kernel32;

import de.fraunhofer.sit.passwordhash.hasher.PasswordHasher;
import de.fraunhofer.sit.passwordhash.hasher.PasswordManager;
import de.fraunhofer.sit.passwordhash.hasher.PasswordMode;
import de.fraunhofer.sit.passwordhash.utils.SqlHashSet;

public class Main {

	private static final int threadCount = Runtime.getRuntime().availableProcessors();
	private static final ExecutorService executor = Executors.newFixedThreadPool(Math.addExact(threadCount, 1));
	private static final AtomicBoolean collision = new AtomicBoolean(false);

	private static final long ROUNDS = 9999L;

	public static void main(String[] args) throws IOException {
		if ((args.length < 1) || args[0].isEmpty()) {
			System.out.println("Error: Required argument is missing!");
			return;
		}

		final SqlHashSet set = new SqlHashSet();
		final BlockingQueue<String> queue = new LinkedBlockingQueue<String>(Math.multiplyExact(4, threadCount));

		final PasswordHasher hasher = PasswordManager.getInstance(PasswordMode.AES, ROUNDS);
		final byte[][] salts = new byte[][] {
			hasher.generateSalt(), hasher.generateSalt(), hasher.generateSalt()
		};

		executor.submit(new ReaderTask(queue, args[0]));

		for (int threadId = 0; threadId < threadCount; ++threadId) {
			executor.submit(new HasherTask(set, queue, salts));
		}

		executor.shutdown();

		try {
			while (!executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS));
		} catch (InterruptedException e) {
			System.out.println("Process interrupted !!!");
		}

		System.out.println((!collision.get()) ? "All done. Goodbye!" : "Failure !!!");
	}

	private static class ReaderTask implements Runnable {
		final String inputFile;
		final BlockingQueue<String> queue;
	
		public ReaderTask(final BlockingQueue<String> queue, final String inputFile) {
			this.queue = Objects.requireNonNull(queue);
			this.inputFile = Objects.requireNonNull(inputFile);
		}
		
		@Override
		public void run() {
			try (final FileInputStream input = new FileInputStream(inputFile)) {
				try (final BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
					String line;
					while ((!Thread.interrupted()) && ((line = reader.readLine()) != null)) {
						if (!(line = line.trim()).isEmpty()) {
							queue.put(line);
						}
					}
				}
				for (int threadId = 0; threadId < threadCount; ++threadId) {
					queue.put("");
				}
			} catch (final InterruptedException e) {
			} catch (final Exception e) {
				e.printStackTrace();
				executor.shutdownNow();
			}
		}
	}

	private static class HasherTask implements Runnable {
		private final BlockingQueue<String> queue;
		private final byte[][] salts;
		private final SqlHashSet set;
		private final PasswordHasher hasher;

		public HasherTask(final SqlHashSet set, final BlockingQueue<String> queue, final byte[][] salts) {
			this.queue = Objects.requireNonNull(queue);
			this.salts = Objects.requireNonNull(salts);
			this.set = Objects.requireNonNull(set);
			this.hasher = PasswordManager.getInstance(PasswordMode.AES, ROUNDS);
		}

		@Override
		public void run() {
			try {
				try {
					final Kernel32 kernel32 = Kernel32.INSTANCE;
					kernel32.SetThreadPriority(kernel32.GetCurrentThread(), Kernel32.THREAD_PRIORITY_LOWEST);
				} catch (Exception e) {}

				String line;
				long size;
				while (!(line = queue.take()).isEmpty()) {
					for (final byte[] salt : salts) {
						final byte[] hashValue = hasher.compute(line, salt);
						if ((size = set.add(hashValue)) < 0L) {
							if (collision.compareAndSet(false, true)) {
								System.out.println("Collision detected! [key: \"" + line + "\"]");
								executor.shutdownNow();
							}
							throw new InterruptedException("Interrupted!");
						}
						System.out.printf("[%,d] %s <-- \"%s\"%n", size, bytesToHex(hashValue), line);
					}
				}
			} catch (final InterruptedException e) {
			} catch (final Exception e) {
				e.printStackTrace();
				executor.shutdownNow();
			}
		}
	}
}
