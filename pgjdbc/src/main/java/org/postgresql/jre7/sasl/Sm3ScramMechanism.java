/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.jre7.sasl;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** Internal SM3 primitives shared by authentication and password encoding. */
public final class Sm3ScramMechanism {
  public static final String NAME = "SCRAM-SM3";
  public static final int KEY_LENGTH = 32;

  private Sm3ScramMechanism() {
  }

  public static byte[] digest(byte[] data) {
    SM3Digest digest = new SM3Digest();
    digest.update(data, 0, data.length);
    byte[] result = new byte[KEY_LENGTH];
    digest.doFinal(result, 0);
    return result;
  }

  public static byte[] hmac(byte[] key, byte[] data) {
    HMac mac = new HMac(new SM3Digest());
    mac.init(new KeyParameter(key));
    mac.update(data, 0, data.length);
    byte[] result = new byte[KEY_LENGTH];
    mac.doFinal(result, 0);
    return result;
  }

  public static byte[] saltedPassword(String password, byte[] salt, int iterations) {
    if (iterations < 1 || salt.length == 0) {
      throw new IllegalArgumentException("SM3 requires positive iterations and a nonempty salt");
    }
    byte[] bytes = PgSm3SaslPrep.prepare(password).getBytes(StandardCharsets.UTF_8);
    try {
      PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SM3Digest());
      generator.init(bytes, salt, iterations);
      return ((KeyParameter) generator.generateDerivedParameters(KEY_LENGTH * 8)).getKey();
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  public static String encode(char[] password, int iterations, byte[] salt) {
    byte[] salted = null;
    byte[] clientKey = null;
    byte[] storedKey = null;
    byte[] serverKey = null;
    try {
      salted = saltedPassword(String.valueOf(password), salt, iterations);
      clientKey = hmac(salted, "Client Key".getBytes(StandardCharsets.US_ASCII));
      storedKey = digest(clientKey);
      serverKey = hmac(salted, "Server Key".getBytes(StandardCharsets.US_ASCII));
      Base64.Encoder encoder = Base64.getEncoder();
      return NAME + "$" + iterations + ":" + encoder.encodeToString(salt)
          + "$" + encoder.encodeToString(storedKey) + ":" + encoder.encodeToString(serverKey);
    } finally {
      Arrays.fill(password, '\0');
      wipe(salted);
      wipe(clientKey);
      wipe(storedKey);
      wipe(serverKey);
    }
  }

  private static void wipe(byte @Nullable [] bytes) {
    if (bytes != null) {
      Arrays.fill(bytes, (byte) 0);
    }
  }
}
