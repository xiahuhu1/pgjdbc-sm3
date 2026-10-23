/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.jre7.sasl;

import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;
import org.postgresql.util.internal.Nullness;

import org.checkerframework.checker.nullness.qual.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** One non-channel-bound SCRAM-SM3 exchange. */
final class Sm3ScramSession {
  private final String nonce;
  private final String firstBare;
  private int phase;
  private byte @Nullable [] expectedSignature;

  Sm3ScramSession() {
    byte[] random = new byte[18];
    new SecureRandom().nextBytes(random);
    nonce = Base64.getEncoder().withoutPadding().encodeToString(random);
    firstBare = "n=*,r=" + nonce;
  }

  String clientFirst() throws PSQLException {
    require(phase == 0, "Duplicate SM3 initial message");
    phase = 1;
    return "n,," + firstBare;
  }

  String serverFirst(String message, String password) throws PSQLException {
    require(phase == 1, "Unexpected SM3 server-first message");
    byte[] salted = null;
    byte[] clientKey = null;
    byte[] storedKey = null;
    byte[] serverKey = null;
    byte[] proof = null;
    byte[] clientSignature = null;
    try {
      Map<Character, String> attrs = attributes(message);
      String[] fields = message.split(",", -1);
      require(fields.length >= 3 && fields[0].startsWith("r=")
          && fields[1].startsWith("s=") && fields[2].startsWith("i="),
          "Invalid SM3 server-first attribute order");
      String combined = attrs.get('r');
      require(combined != null && combined.startsWith(nonce) && combined.length() > nonce.length(),
          "Invalid SM3 server nonce");
      String count = attrs.get('i');
      require(count != null && count.matches("[1-9][0-9]*"), "Invalid SM3 iteration count");
      int iterations = Integer.parseInt(Nullness.castNonNull(count));
      String saltText = attrs.get('s');
      require(saltText != null, "Missing SM3 salt");
      byte[] salt = Base64.getDecoder().decode(Nullness.castNonNull(saltText));
      require(salt.length > 0, "Empty SM3 salt");
      String finalBare = "c=biws,r=" + combined;
      byte[] auth = (firstBare + "," + message + "," + finalBare)
          .getBytes(StandardCharsets.UTF_8);
      salted = Sm3ScramMechanism.saltedPassword(password, salt, iterations);
      clientKey = Sm3ScramMechanism.hmac(salted, ascii("Client Key"));
      storedKey = Sm3ScramMechanism.digest(clientKey);
      serverKey = Sm3ScramMechanism.hmac(salted, ascii("Server Key"));
      clientSignature = Sm3ScramMechanism.hmac(storedKey, auth);
      expectedSignature = Sm3ScramMechanism.hmac(serverKey, auth);
      proof = new byte[Sm3ScramMechanism.KEY_LENGTH];
      for (int i = 0; i < proof.length; i++) {
        proof[i] = (byte) (clientKey[i] ^ clientSignature[i]);
      }
      phase = 2;
      return finalBare + ",p=" + Base64.getEncoder().encodeToString(proof);
    } catch (IllegalArgumentException e) {
      throw new PSQLException("Invalid SM3 server-first message", PSQLState.CONNECTION_REJECTED, e);
    } finally {
      wipe(salted);
      wipe(clientKey);
      wipe(storedKey);
      wipe(serverKey);
      wipe(proof);
      wipe(clientSignature);
      if (phase != 2) {
        close();
      }
    }
  }

  void serverFinal(String message) throws PSQLException {
    require(phase == 2, "Unexpected SM3 server-final message");
    try {
      Map<Character, String> attrs = attributes(message);
      require(!attrs.containsKey('e'), "SM3 authentication rejected by server");
      String verifier = attrs.get('v');
      require(verifier != null && message.startsWith("v="), "Missing SM3 server signature");
      byte[] signature = Base64.getDecoder().decode(Nullness.castNonNull(verifier));
      require(signature.length == Sm3ScramMechanism.KEY_LENGTH
          && expectedSignature != null && MessageDigest.isEqual(expectedSignature, signature),
          "Invalid SM3 server signature");
      phase = 3;
    } catch (IllegalArgumentException e) {
      throw new PSQLException("Invalid SM3 server-final message", PSQLState.CONNECTION_REJECTED, e);
    } finally {
      wipe(expectedSignature);
      expectedSignature = null;
    }
  }

  boolean verified() {
    return phase == 3;
  }

  void close() {
    wipe(expectedSignature);
    expectedSignature = null;
    if (phase != 3) {
      phase = -1;
    }
  }

  private static Map<Character, String> attributes(String message) throws PSQLException {
    Map<Character, String> attrs = new LinkedHashMap<>();
    for (String field : message.split(",", -1)) {
      require(field.length() >= 3 && field.charAt(1) == '='
          && (field.charAt(0) >= 'a' && field.charAt(0) <= 'z'
          || field.charAt(0) >= 'A' && field.charAt(0) <= 'Z'), "Malformed SM3 attribute");
      char key = field.charAt(0);
      require(key != 'm' && !attrs.containsKey(key), "Unsupported or duplicate SM3 attribute");
      for (int i = 2; i < field.length(); i++) {
        char ch = field.charAt(i);
        require(ch >= 0x21 && ch <= 0x7e, "Invalid SM3 attribute value");
      }
      attrs.put(key, field.substring(2));
    }
    return attrs;
  }

  private static byte[] ascii(String text) {
    return text.getBytes(StandardCharsets.US_ASCII);
  }

  private static void require(boolean valid, String message) throws PSQLException {
    if (!valid) {
      throw new PSQLException(message, PSQLState.CONNECTION_REJECTED);
    }
  }

  private static void wipe(byte @Nullable [] bytes) {
    if (bytes != null) {
      Arrays.fill(bytes, (byte) 0);
    }
  }
}
