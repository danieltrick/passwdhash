package de.fraunhofer.sit.passwordhash.cli;

import static de.fraunhofer.sit.passwordhash.utils.HexString.bytesToHex;
import static de.fraunhofer.sit.passwordhash.utils.MathUtils.addSaturating;
import static de.fraunhofer.sit.passwordhash.utils.MathUtils.multiplySaturating;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import de.fraunhofer.sit.passwordhash.PasswordHasher;
import de.fraunhofer.sit.passwordhash.PasswordManager;
import de.fraunhofer.sit.passwordhash.PasswordMode;
import de.fraunhofer.sit.passwordhash.Version;
import de.fraunhofer.sit.passwordhash.cli.utils.CloseableSet;
import de.fraunhofer.sit.passwordhash.cli.utils.SqlHashSet;

public class Main {

	private static final long hashRounds = parseLong(System.getProperty("passwdhash.rounds"), -1L);
	private static final int processorCount = Runtime.getRuntime().availableProcessors();
	private static final int threadCount = Math.max(1, parseInt(System.getProperty("passwdhash.threads"), processorCount));
	private static final ExecutorService executor = Executors.newFixedThreadPool(addSaturating(threadCount, 2));
	private static final PasswordMode mode = parseMode(System.getProperty("passwdhash.mode"), PasswordManager.DEFAULT);

	private static volatile boolean collision = false;

	public static void main(String[] args) throws IOException {
		System.out.printf("Password Hash v%s%n", getVersionString(Version.MAJOR, Version.MINOR, Version.PATCH));

		if ((args.length < 1) || args[0].isEmpty()) {
			System.out.println("Error: Required argument is missing!");
			return;
		}

		final int queueSize = multiplySaturating(8, threadCount);
		final BlockingQueue<String> queue_src = new LinkedBlockingQueue<String>(queueSize);
		final BlockingQueue<Entry<String, byte[]>> queue_dst = new LinkedBlockingQueue<Entry<String, byte[]>>(queueSize);

		final PasswordHasher hasher = PasswordManager.getInstance(mode, hashRounds);
		final byte[][] salts = new byte[][] {
			hasher.generateSalt(), hasher.generateSalt(), hasher.generateSalt()
		};

		executor.submit(new ReaderTask(queue_src, args[0]));
		executor.submit(new WriterTask(queue_dst));

		for (int threadId = 0; threadId < threadCount; ++threadId) {
			executor.submit(new HasherTask(queue_src, queue_dst, salts));
		}

		executor.shutdown();

		try {
			while (!executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS));
		} catch (InterruptedException e) {
			System.out.println("Process interrupted !!!");
		}

		System.out.println((!collision) ? "All done. Goodbye!" : "Failure !!!");
	}

	private static class ReaderTask implements Runnable {
		private final String inputFile;
		private final BlockingQueue<String> queue;
	
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
			} catch (final Throwable e) {
				e.printStackTrace();
				executor.shutdownNow();
			}
		}
	}

	private static class HasherTask implements Runnable {
		private static final AtomicInteger pending = new AtomicInteger(0);

		private final BlockingQueue<String> queue_src;
		private final BlockingQueue<Entry<String, byte[]>> queue_dst;
		private final byte[][] salts;
		private final PasswordHasher hasher;

		public HasherTask(final BlockingQueue<String> queue_src, final BlockingQueue<Entry<String, byte[]>> queue_dst, final byte[][] salts) {
			this.queue_src = Objects.requireNonNull(queue_src);
			this.queue_dst = Objects.requireNonNull(queue_dst);
			this.salts = Objects.requireNonNull(salts);
			this.hasher = PasswordManager.getInstance(mode, hashRounds);
			pending.incrementAndGet();
		}

		@Override
		public void run() {
			try {
				String line;
				while (!(line = queue_src.take()).isEmpty()) {
					for (final byte[] salt : salts) {
						final byte[] hashValue = hasher.compute(line, salt);
						queue_dst.put(new SimpleImmutableEntry<String, byte[]>(line, hashValue));
					}
				}

				if (pending.decrementAndGet() == 0) {
					queue_dst.put(new SimpleImmutableEntry<String, byte[]>("", null));
				}
			} catch (final InterruptedException e) {
			} catch (final Throwable e) {
				e.printStackTrace();
				executor.shutdownNow();
			}
		}
	}

	private static class WriterTask implements Runnable {
		private final BlockingQueue<Entry<String, byte[]>> queue;
	
		public WriterTask(final BlockingQueue<Entry<String, byte[]>> queue) throws IOException {
			this.queue = Objects.requireNonNull(queue);
		}

		@Override
		public void run() {
			try (final CloseableSet<byte[]> set = new SqlHashSet()) {
				while (!Thread.interrupted()) {
					final Entry<String, byte[]> currentEntry = queue.take();
					final String key = currentEntry.getKey();
					final byte[] hashValue = currentEntry.getValue();

					if (key.isEmpty() || (hashValue == null) || (hashValue.length < 1)) {
						break;
					}

					final boolean addedFlag = set.add(hashValue);
					System.out.printf("[%,d] %s <-- \"%s\"%n", set.longSize(), bytesToHex(hashValue), key);

					if (!addedFlag) {
						System.out.println("Collision detected! [key: \"" + key + "\"]");
						collision = true;
						executor.shutdownNow();
						return;
					}
				}
			} catch (final InterruptedException e) {
			} catch (final Throwable e) {
				e.printStackTrace();
				executor.shutdownNow();
			}
		}
	}

	private static int parseInt(final String property, final int defaultValue) {
		if (property != null) {
			final String propertyTrimmed = property.trim();
			if (!propertyTrimmed.isEmpty()) {
				try {
					final int value = Integer.parseInt(propertyTrimmed);
					if (value < 0) {
						throw new NumberFormatException("Negative numbers are not allowed!");
					}
					return value;
				} catch (final NumberFormatException e) {
					throw new IllegalArgumentException("Invalid number: \"" + propertyTrimmed + '"', e);
				}
			}
		}

		return defaultValue;
	}

	private static long parseLong(final String property, final long defaultValue) {
		if (property != null) {
			final String propertyTrimmed = property.trim();
			if (!propertyTrimmed.isEmpty()) {
				try {
					final long value = Long.parseLong(propertyTrimmed);
					if (value < 0L) {
						throw new NumberFormatException("Negative numbers are not allowed!");
					}
					return value;
				} catch (final NumberFormatException e) {
					throw new IllegalArgumentException("Invalid number: \"" + propertyTrimmed + '"', e);
				}
			}
		}

		return defaultValue;
	}

	private static PasswordMode parseMode(final String property, final PasswordMode defaultValue) {
		if (property != null) {
			final String propertyTrimmed = property.trim();
			if (!propertyTrimmed.isEmpty()) {
				final PasswordMode[] modes = PasswordMode.values();
				for (final PasswordMode mode : modes) {
					if (mode.name().equalsIgnoreCase(propertyTrimmed)) {
						return mode;
					}
				}
				try {
					final long value = Long.parseLong(propertyTrimmed);
					if (value > 0L) {
						for (final PasswordMode mode : modes) {
							if (mode.id == value) {
								return mode;
							}
						}
					}
				} catch (final NumberFormatException e) { }
				throw new IllegalArgumentException("Invalid mode: \"" + propertyTrimmed + '"');
			}
		}

		return defaultValue;
	}

	private static String getVersionString(final int major, final int minor, final int patch) {
		if (patch > 0) {
			return String.format("%d.%02d-%d", major, minor, patch);
		} else {			
			return String.format("%d.%02d", major, minor);
		}
	}
}
