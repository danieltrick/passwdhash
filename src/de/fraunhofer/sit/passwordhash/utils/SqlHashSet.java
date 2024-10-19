package de.fraunhofer.sit.passwordhash.utils;

import static de.fraunhofer.sit.passwordhash.utils.Utilities.addSaturating;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.Iterator;

import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;

public class SqlHashSet implements CloseableSet<byte[]> {

	private final Connection connection;
	private final PreparedStatement statementInsrt;
	private final PreparedStatement statementCount;
	private final PreparedStatement statementClear;

	private long size = 0L;
	private volatile boolean closed = false;

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
			statementCount = connection.prepareStatement("SELECT COUNT(hash) from htable;");
			statementClear = connection.prepareStatement("DELETE FROM htable;");
		} catch (final SQLException e) {
			try {
				connection.close();
			} catch (SQLException e2) { }
			throw new IOException("Failed to initialize SQLite table!", e);
		}
	}

	@Override
	public boolean add(final byte[] key) {
		if (key == null) {
			throw new NullPointerException("key");
		}
		if (key.length < 1) {
			throw new IllegalArgumentException("key must not be empty!");
		}

		checkState();

		try {
			statementInsrt.setBytes(1, key);
			if (statementInsrt.executeUpdate() != 1) {
				throw new UncheckedIOException(new IOException("SQLite update operation returned unexpected result!"));
			}
			size = addSaturating(size, 1L);
			return true;
		} catch (final SQLiteException e) {
			final SQLiteErrorCode errorCode = ((SQLiteException)e).getResultCode();
			if (errorCode.equals(SQLiteErrorCode.SQLITE_CONSTRAINT_PRIMARYKEY) || errorCode.equals(SQLiteErrorCode.SQLITE_CONSTRAINT_UNIQUE)) {
				return false;
			}
			throw new UncheckedIOException(new IOException("Failed to update DB table!", e));
		} catch (final SQLException e) {
			throw new UncheckedIOException(new IOException("Failed to update DB table!", e));
		}
	}

	@Override
	public int size() {
		checkState();
		return (size <= Integer.MAX_VALUE) ? ((int)size) : Integer.MAX_VALUE;
	}

	@Override
	public long longSize() {
		checkState();
		return size;
	}

	@Override
	public long count() {
		checkState();

		try (final ResultSet result = statementCount.executeQuery()) {
			if (result.next()) {
				return result.getLong(1);
			} else {
				throw new SQLException("No result available!");
			}
		} catch (final SQLException e) {
			throw new UncheckedIOException(new IOException ("Faild to count rows in DB table!", e));
		}
	}

	@Override
	public void clear() {
		checkState();

		if (size > 0) {
			try {
				statementClear.executeUpdate();
				size = 0L;
			} catch (final SQLException e) {
				throw new UncheckedIOException(new IOException ("Failed to clear DB table!", e));
			}
		}
	}

	@Override
	public void close() {
		if (!closed) {
			closed = true;
			safeClose(statementInsrt);
			safeClose(statementCount);
			safeClose(statementClear);
			safeClose(connection);
		}
	}

	@Override
	public boolean isEmpty() {
		checkState();
		return (size == 0L);
	}

	@Override
	public boolean contains(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<byte[]> iterator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object[] toArray() {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> T[] toArray(T[] a) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean addAll(Collection<? extends byte[]> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}
	
	private void checkState() {
		if (closed) {
			throw new IllegalStateException("Connection already closed!");
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
