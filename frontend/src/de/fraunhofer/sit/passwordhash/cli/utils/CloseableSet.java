package de.fraunhofer.sit.passwordhash.cli.utils;

import java.util.Set;

public interface CloseableSet<T> extends Set<T>, AutoCloseable {
	long longSize();
}
