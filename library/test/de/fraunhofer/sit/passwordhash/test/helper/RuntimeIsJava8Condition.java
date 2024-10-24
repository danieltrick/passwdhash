package de.fraunhofer.sit.passwordhash.test.helper;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

public class RuntimeIsJava8Condition implements ExecutionCondition {
	@Override
	public ConditionEvaluationResult evaluateExecutionCondition(final ExtensionContext context) {
		if (System.getProperty("java.version", "?").startsWith("1.")) {
			return ConditionEvaluationResult.disabled("Not supported on Java 8, or older!");
		}
		return ConditionEvaluationResult.enabled("Supported on this Java version.");
	}
}
