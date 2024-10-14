package de.fraunhofer.sit.passwordhash.utils;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;

public class SqlHashSet implements AutoCloseable {

	private final AtomicBoolean closed = new AtomicBoolean(false);
	private final Connection connection;
	private final PreparedStatement statementInsrt;
	private final PreparedStatement statementClear;

	private long size = 0L;

	static {
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (final ClassNotFoundException e) {
			throw new Error(e);
		}
	}

	public SqlHashSet() throws IOException {
		try {
			connection = DriverManager.getConnection("jdbc:sqlite::memory:");
		} catch (final SQLException e) {
			throw new IOException("Failed to create SQLite connection!", e);
		}

		try {
			try (final Statement statement = connection.createStatement()) {
				statement.executeUpdate("CREATE TABLE htable (hash BLOB PRIMARY KEY) WITHOUT ROWID;");
			}
			statementInsrt = connection.prepareStatement("INSERT INTO htable (hash) VALUES (?);");
			statementClear = connection.prepareStatement("DELETE FROM htable;");
		} catch (final SQLException e) {
			try {
				connection.close();
			} catch (SQLException e2) { }
			throw new IOException("Failed to initialize SQLite table!", e);
		}
	}

	public long add(final byte[] key) throws IOException {
		if (key == null) {
			throw new NullPointerException("key");
		}
		if (key.length < 1) {
			throw new IllegalArgumentException("key must not be empty!");
		}

		checkState();

		synchronized (connection) {
			try {
				statementInsrt.setBytes(1, key);
				if (statementInsrt.executeUpdate() != 1) {
					throw new IOException("SQLite update operation returned unexpected result!");
				}
				return (size = Math.addExact(size, 1L));
			} catch (final SQLiteException e) {
				final SQLiteErrorCode errorCode = ((SQLiteException)e).getResultCode();
				if (errorCode.equals(SQLiteErrorCode.SQLITE_CONSTRAINT_PRIMARYKEY) || errorCode.equals(SQLiteErrorCode.SQLITE_CONSTRAINT_UNIQUE)) {
					return -1L;
				}
				throw new IOException("Failed to update DB table!", e);
			} catch (final SQLException e) {
				throw new IOException("Failed to update DB table!", e);
			}
		}
	}

	public void clear() throws IOException {
		checkState();

		synchronized (connection) {
			if (size > 0) {
				try {
					statementClear.executeUpdate();
					size = 0L;
				} catch (final SQLException e) {
					throw new IOException("Failed to clear DB table!", e);
				}
			}
		}
	}

	public long size() {
		checkState();

		synchronized (connection) {
			return size;
		}
	}

	private void checkState() {
		if (closed.get()) {
			throw new IllegalStateException("Connection already closed!");
		}
	}

	@Override
	public void close() {
		if (closed.compareAndSet(false, true)) {
			synchronized (connection) {
				safeClose(statementInsrt);
				safeClose(statementClear);
				safeClose(connection);
			}
		}
	}

	private static void safeClose(final AutoCloseable instance) {
		if (instance != null) {
			try {
				instance.close();
			} catch (Exception e) { }
		}
	}
}
