package com.arqsz.burpgitleaks.utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for calculating entropy.
 *
 * LICENSE NOTICE:
 * The {@link #shannonEntropy(String)} method is a direct port of the logic
 * found in
 * the Gitleaks project (https://github.com/gitleaks/gitleaks).
 *
 * Original Source: detect/utils.go
 * Original Author: Zachary Rice
 * License: MIT License (see src/main/resources/GITLEAKS_LICENSE)
 *
 * Copyright (c) 2019 Zachary Rice
 */
public class Entropy {

    public static double shannonEntropy(String data) {
        if (data == null || data.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> charCounts = new HashMap<>();
        for (int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            charCounts.put(c, charCounts.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        double invLength = 1.0 / data.length();

        for (int count : charCounts.values()) {
            double freq = count * invLength;
            entropy -= freq * (Math.log(freq) / Math.log(2));
        }

        return entropy;
    }
}