package com.autolimit.identity;

import java.util.Optional;

@FunctionalInterface
public interface CallerIdentityResolver {

    Optional<CallerIdentity> resolve();

}
