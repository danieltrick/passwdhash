package de.fraunhofer.sit.passwordhash.test.helper;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.junit.jupiter.api.extension.ExtendWith;

@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(RuntimeIsJava8Condition.class)
public @interface DisabledOnJava8 {

}
