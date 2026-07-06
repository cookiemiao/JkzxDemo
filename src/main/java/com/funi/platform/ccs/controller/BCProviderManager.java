package com.funi.platform.ccs.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class BCProviderManager {
    private static volatile boolean registered = false;

    public static synchronized void register() {
        if (!registered) {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            registered = true;
        }
    }
}

