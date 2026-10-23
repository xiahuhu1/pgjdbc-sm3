/*
 * Copyright (c) 2026, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.jre7.sasl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.postgresql.util.PSQLException;
import org.postgresql.util.PasswordUtil;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Base64;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

class Sm3ScramTest {
  private static final byte[] SALT = ascii("0123456789abcdef");
  private static final String SALT_BASE64 = "MDEyMzQ1Njc4OWFiY2RlZg==";

  @Test
  void primitivesMatchIndependentVectors() {
    assertArrayEquals(hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        Sm3ScramMechanism.digest(ascii("abc")));
    assertArrayEquals(hex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        Sm3ScramMechanism.digest(ascii(
            "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")));
    assertArrayEquals(hex("bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398"),
        Sm3ScramMechanism.hmac(ascii("key"), ascii("The quick brown fox jumps over the lazy dog")));
    // PBKDF2 expected values came from Python hashlib.pbkdf2_hmac('sm3', ...).
    int[] iterations = {1, 2, 4096};
    String[] expected = {
        "4612f922a1fdcefaf4312fc6f8f3322b489cbf24f2ea361b44c2bd8fa2c6dcb0",
        "fee723a2bc966e11dffb66133f4e8df577383c78ade30e3298edbd3e54ed85b7",
        "b6e8f2074c87432b78f62e5ced980fdff89e86af2f693dab1638e2b3683045dd"
    };
    for (int i = 0; i < iterations.length; i++) {
      assertArrayEquals(hex(expected[i]),
          Sm3ScramMechanism.saltedPassword("password", ascii("salt"), iterations[i]));
    }
  }

  @Test
  void passwordVerifierMatchesPostgreSqlAndClearsPassword() {
    char[] password = "pencil".toCharArray();
    assertEquals("SCRAM-SM3$4096:" + SALT_BASE64
        + "$3VDRDUacXR3QJvQMpIW7O977W8zXPkExcnJhfTV9nDA="
        + ":wTnMk1YnOhilUCIQlRac05w8NNxo5uKKhAMLmAJk8sk=",
        PasswordUtil.encodeScramSm3(password, 4096, SALT));
    assertArrayEquals(new char[6], password);
    assertEquals("SCRAM-SHA-256$4096:" + SALT_BASE64
        + "$nQpbZ77WudtqufPwikHXGRt6g2QJ4zns8bZLw273DRM="
        + ":jn2amWP1q1h+jgjy0YTO14S6/F02SV7taipOeB7ef20=",
        PasswordUtil.encodeScramSha256("pencil".toCharArray(), 4096, SALT));
  }

  @Test
  void passwordIsClearedWhenEncodingFails() {
    char[] zeroIterations = "pencil".toCharArray();
    assertThrows(IllegalArgumentException.class,
        () -> PasswordUtil.encodeScramSm3(zeroIterations, 0, SALT));
    assertArrayEquals(new char[6], zeroIterations);
    char[] emptySalt = "pencil".toCharArray();
    assertThrows(IllegalArgumentException.class,
        () -> PasswordUtil.encodeScramSm3(emptySalt, 4096, new byte[0]));
    assertArrayEquals(new char[6], emptySalt);
    char[] invalidUtf16 = {'p', '\ud800'};
    assertThrows(IllegalArgumentException.class,
        () -> PasswordUtil.encodeScramSm3(invalidUtf16, 4096, SALT));
    assertArrayEquals(new char[2], invalidUtf16);
  }

  @Test
  void preparationMatchesPostgreSql17FallbackRules() {
    assertEquals("IX X", PgSm3SaslPrep.prepare("\u2168\u00a0X")); // U+2168, U+00A0 mapping.
    assertEquals("IX", PgSm3SaslPrep.prepare("\u2168")); // U+2168 NFKC expansion.
    assertEquals("user", PgSm3SaslPrep.prepare("u\u00adser"));
    assertEquals("a b", PgSm3SaslPrep.prepare("a\u200bb"));
    assertEquals(" ", PgSm3SaslPrep.prepare("\u1680"));
    assertEquals("a\u0007b", PgSm3SaslPrep.prepare("a\u0007b"));
    assertEquals("\u00ad", PgSm3SaslPrep.prepare("\u00ad"));
    assertEquals("\u0221", PgSm3SaslPrep.prepare("\u0221")); // Unassigned in Unicode 3.2.
    assertEquals("\u1d2c", PgSm3SaslPrep.prepare("\u1d2c")); // U+1D2C uses original input.
    assertEquals("\u05d0a\u05d0", PgSm3SaslPrep.prepare("\u05d0a\u05d0")); // Bidi failure.
    assertEquals("A", PgSm3SaslPrep.prepare("\ud835\udc00")); // U+1D400 NFKC expansion.
    assertThrows(IllegalArgumentException.class, () -> PgSm3SaslPrep.prepare("a\0b"));
    assertThrows(IllegalArgumentException.class,
        () -> PgSm3SaslPrep.prepare("\ud800")); // Unpaired high surrogate.
    assertThrows(IllegalArgumentException.class,
        () -> PgSm3SaslPrep.prepare("\udc00")); // Unpaired low surrogate.
  }

  @Test
  void exchangeVerifiesProofAndServerSignature() throws Exception {
    Sm3ScramSession session = new Sm3ScramSession();
    String first = session.clientFirst();
    assertTrue(first.startsWith("n,,n=*,r="));
    String nonce = first.substring("n,,n=*,r=".length());
    String serverFirst = serverFirst(nonce);
    String clientFinal = session.serverFirst(serverFirst, "pencil");
    assertFalse(session.verified());
    int proofStart = clientFinal.indexOf(",p=");
    assertTrue(proofStart > 0);
    String finalBare = clientFinal.substring(0, proofStart);
    byte[] authMessage = ascii(first.substring(3) + "," + serverFirst + "," + finalBare);
    // Fixed keys generated independently with Python hashlib/hmac, for this salt/password.
    byte[] clientKey = hex("8825debc08e2a44e024ad34179fb0af86e24374aa9a43ea1dd4d1f19e3ffe398");
    byte[] storedKey = hex("dd50d10d469c5d1dd026f40ca485bb3bdefb5bccd73e41317272617d357d9c30");
    byte[] serverKey = hex("c139cc9356273a18a550221095169cd39c3c34dc68e6e28a84030b980264f2c9");
    byte[] signature = referenceHmac(storedKey, authMessage);
    for (int i = 0; i < clientKey.length; i++) {
      clientKey[i] ^= signature[i];
    }
    assertEquals(Base64.getEncoder().encodeToString(clientKey),
        clientFinal.substring(proofStart + 3));
    assertEquals("c=biws,r=" + nonce + "SERVER", finalBare);
    session.serverFinal("v=" + Base64.getEncoder().encodeToString(
        referenceHmac(serverKey, authMessage)));
    assertTrue(session.verified());
    assertThrows(PSQLException.class, () -> session.serverFinal("v=AAAA"));
  }

  @Test
  void rejectsOutOfOrderAndRepeatedMessages() throws Exception {
    Sm3ScramSession beforeFirst = new Sm3ScramSession();
    assertThrows(PSQLException.class, () -> beforeFirst.serverFirst("r=x,s=eA==,i=1", "pencil"));
    assertThrows(PSQLException.class, () -> beforeFirst.serverFinal("v=AAAA"));
    Sm3ScramSession session = new Sm3ScramSession();
    String nonce = session.clientFirst().substring("n,,n=*,r=".length());
    assertThrows(PSQLException.class, session::clientFirst);
    session.serverFirst(serverFirst(nonce), "pencil");
    assertThrows(PSQLException.class, () -> session.serverFirst(serverFirst(nonce), "pencil"));
    session.close();
    assertFalse(session.verified());
    assertThrows(PSQLException.class, () -> session.serverFinal("v=AAAA"));
  }

  @Test
  void rejectsMalformedServerFirstMessages() throws Exception {
    String[] tails = {
        ",s=,i=4096", ",s=***,i=4096", ",s=" + SALT_BASE64 + ",i=0",
        ",s=" + SALT_BASE64 + ",i=-1", ",s=" + SALT_BASE64 + ",i=04096",
        ",s=" + SALT_BASE64 + ",i=2147483648", ",s=" + SALT_BASE64 + ",i=999999999999999999999",
        ",s=" + SALT_BASE64 + ",i=4096,i=4096", ",s=" + SALT_BASE64 + ",i=4096,m=ext",
        ",s=" + SALT_BASE64 + ",i=4096,x=\u00a0", ",s=" + SALT_BASE64 + ",i=4096,"
    };
    for (String tail : tails) {
      Sm3ScramSession session = new Sm3ScramSession();
      String nonce = session.clientFirst().substring("n,,n=*,r=".length());
      assertThrows(PSQLException.class, () -> session.serverFirst("r=" + nonce + "SERVER" + tail,
          "pencil"), tail);
      assertFalse(session.verified());
    }
    Sm3ScramSession wrongNonce = new Sm3ScramSession();
    wrongNonce.clientFirst();
    assertThrows(PSQLException.class, () -> wrongNonce.serverFirst(serverFirst("wrong"), "pencil"));
    Sm3ScramSession unextendedNonce = new Sm3ScramSession();
    String nonce = unextendedNonce.clientFirst().substring("n,,n=*,r=".length());
    assertThrows(PSQLException.class, () -> unextendedNonce.serverFirst(
        "r=" + nonce + ",s=" + SALT_BASE64 + ",i=4096", "pencil"));
  }

  @Test
  void rejectsForgedOrMalformedServerSignatures() throws Exception {
    String[] invalid = {"v=AAAA", "v=***", "e=invalid-proof", "x=extension", "v=AAAA,v=AAAA",
        "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "v=AAAA,e=invalid-proof"};
    for (String message : invalid) {
      Sm3ScramSession session = new Sm3ScramSession();
      String nonce = session.clientFirst().substring("n,,n=*,r=".length());
      session.serverFirst(serverFirst(nonce), "pencil");
      assertThrows(PSQLException.class, () -> session.serverFinal(message), message);
      assertFalse(session.verified());
    }
  }

  @Test
  void rejectsAuthenticationOkWithoutServerSignature() throws Exception {
    assertRejectedAuthenticationRequest(0, "SCRAM server signature was not verified");
  }

  @Test
  void rejectsChangingAuthenticationMethodDuringScram() throws Exception {
    assertRejectedAuthenticationRequest(3, "Unexpected request during SCRAM authentication");
  }

  private static void assertRejectedAuthenticationRequest(int request, String expected)
      throws Exception {
    try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
      listener.setSoTimeout(5000);
      FutureTask<Void> fakeServer = new FutureTask<>(() -> {
        try (Socket socket = listener.accept();
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
          socket.setSoTimeout(5000);
          int startupLength = input.readInt();
          assertTrue(startupLength >= 8 && startupLength < 65536);
          byte[] startup = new byte[startupLength - 4];
          input.readFully(startup);
          byte[] mechanisms = ascii("SCRAM-SM3\0\0");
          output.writeByte('R');
          output.writeInt(8 + mechanisms.length);
          output.writeInt(10);
          output.write(mechanisms);
          output.flush();
          assertEquals('p', input.readUnsignedByte());
          int firstLength = input.readInt();
          assertTrue(firstLength > 4 && firstLength < 65536);
          byte[] first = new byte[firstLength - 4];
          input.readFully(first);
          output.writeByte('R');
          output.writeInt(8);
          output.writeInt(request);
          output.flush();
        }
        return null;
      });
      Thread server = new Thread(fakeServer, "sm3-fake-server");
      server.setDaemon(true);
      server.start();
      String url = "jdbc:postgresql://127.0.0.1:" + listener.getLocalPort()
          + "/test?sslmode=disable&gssEncMode=disable&connectTimeout=3&socketTimeout=3";
      PSQLException error = assertThrows(PSQLException.class, () -> {
        try (Connection ignored = DriverManager.getConnection(url, "test", "pencil")) {
          // The server must never be accepted before signature verification.
        }
      });
      assertTrue(error.getMessage().contains(expected), error.getMessage());
      fakeServer.get(6, TimeUnit.SECONDS);
    }
  }

  private static String serverFirst(String nonce) {
    return "r=" + nonce + "SERVER,s=" + SALT_BASE64 + ",i=4096";
  }

  private static byte[] referenceHmac(byte[] key, byte[] data) {
    HMac mac = new HMac(new SM3Digest());
    mac.init(new KeyParameter(key));
    mac.update(data, 0, data.length);
    byte[] output = new byte[32];
    mac.doFinal(output, 0);
    return output;
  }

  private static byte[] ascii(String text) {
    return text.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] hex(String text) {
    byte[] output = new byte[text.length() / 2];
    for (int i = 0; i < output.length; i++) {
      output[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
    }
    return output;
  }
}
