/*
 * Copyright (c) 2017, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.jre7.sasl;

import static org.postgresql.util.internal.Nullness.castNonNull;

import org.postgresql.core.PGStream;
import org.postgresql.util.GT;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import com.ongres.scram.client.ScramClient;
import com.ongres.scram.client.ScramSession;
import com.ongres.scram.common.exception.ScramException;
import com.ongres.scram.common.exception.ScramInvalidServerSignatureException;
import com.ongres.scram.common.exception.ScramParseException;
import com.ongres.scram.common.exception.ScramServerErrorException;
import com.ongres.scram.common.stringprep.StringPreparations;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ScramAuthenticator {
  private static final Logger LOGGER = Logger.getLogger(ScramAuthenticator.class.getName());

  private final String user;
  private final String password;
  private final PGStream pgStream;
  private @Nullable Sm3ScramSession sm3Session;
  private boolean serverVerified;
  private @Nullable ScramClient scramClient;
  private @Nullable ScramSession scramSession;
  private ScramSession.@Nullable ClientFinalProcessor clientFinalProcessor;

  private interface BodySender {
    void sendBody(PGStream pgStream) throws IOException;
  }

  private void sendAuthenticationMessage(int bodyLength, BodySender bodySender)
      throws IOException {
    pgStream.sendChar('p');
    pgStream.sendInteger4(Integer.SIZE / Byte.SIZE + bodyLength);
    bodySender.sendBody(pgStream);
    pgStream.flush();
  }

  public ScramAuthenticator(String user, String password, PGStream pgStream) {
    this.user = user;
    this.password = password;
    this.pgStream = pgStream;
  }

  public void processServerMechanismsAndInit(int length) throws IOException, PSQLException {
    if (length < 2 || length > 65536) {
      throw new PSQLException("Invalid SASL mechanism list length", PSQLState.CONNECTION_REJECTED);
    }
    byte[] payload = pgStream.receive(length);
    List<String> mechanisms = new ArrayList<>();
    int start = 0;
    for (int i = 0; i < payload.length; i++) {
      if (payload[i] == 0) {
        if (i == start) {
          if (i != payload.length - 1) {
            throw new PSQLException("Invalid SASL mechanism list", PSQLState.CONNECTION_REJECTED);
          }
          break;
        }
        mechanisms.add(new String(payload, start, i - start, StandardCharsets.US_ASCII));
        start = i + 1;
      } else if (payload[i] < 0x21 || payload[i] > 0x7e) {
        throw new PSQLException("Invalid SASL mechanism name", PSQLState.CONNECTION_REJECTED);
      }
    }
    if (start != payload.length - 1 || payload[payload.length - 1] != 0 || mechanisms.isEmpty()) {
      throw new PSQLException("Invalid SASL mechanism list", PSQLState.CONNECTION_REJECTED);
    }
    if (mechanisms.contains(Sm3ScramMechanism.NAME)) {
      sm3Session = new Sm3ScramSession();
      LOGGER.log(Level.FINE, "Using SCRAM mechanism {0}", Sm3ScramMechanism.NAME);
      return;
    }

    ScramClient scramClient;
    try {
      scramClient = ScramClient
          .channelBinding(ScramClient.ChannelBinding.NO)
          .stringPreparation(StringPreparations.SASL_PREPARATION)
          .selectMechanismBasedOnServerAdvertised(mechanisms.toArray(new String[]{}))
          .setup();
    } catch (IllegalArgumentException e) {
      throw new PSQLException(
          GT.tr("Invalid or unsupported by client SCRAM mechanisms", e),
          PSQLState.CONNECTION_REJECTED
      );
    }
    if (LOGGER.isLoggable(Level.FINEST)) {
      LOGGER.log(Level.FINEST, " Using SCRAM mechanism {0}", scramClient.getScramMechanism().getName());
    }

    this.scramClient = scramClient;
    scramSession =
        scramClient.scramSession("*");   // Real username is ignored by server, uses startup one
  }

  public void sendScramClientFirstMessage() throws IOException, PSQLException {
    Sm3ScramSession sm3Session = this.sm3Session;
    if (sm3Session != null) {
      byte[] name = Sm3ScramMechanism.NAME.getBytes(StandardCharsets.US_ASCII);
      byte[] message = sm3Session.clientFirst().getBytes(StandardCharsets.UTF_8);
      sendAuthenticationMessage(name.length + 1 + 4 + message.length, stream -> {
        stream.send(name);
        stream.sendChar(0);
        stream.sendInteger4(message.length);
        stream.send(message);
      });
      return;
    }
    ScramSession scramSession = this.scramSession;
    String clientFirstMessage = castNonNull(scramSession).clientFirstMessage();
    LOGGER.log(Level.FINEST, " FE=> SASLInitialResponse( {0} )", clientFirstMessage);

    ScramClient scramClient = this.scramClient;
    String scramMechanismName = castNonNull(scramClient).getScramMechanism().getName();
    final byte[] scramMechanismNameBytes = scramMechanismName.getBytes(StandardCharsets.UTF_8);
    final byte[] clientFirstMessageBytes = clientFirstMessage.getBytes(StandardCharsets.UTF_8);
    sendAuthenticationMessage(
        (scramMechanismNameBytes.length + 1) + 4 + clientFirstMessageBytes.length,
        new BodySender() {
          @Override
          public void sendBody(PGStream pgStream) throws IOException {
            pgStream.send(scramMechanismNameBytes);
            pgStream.sendChar(0); // List terminated in '\0'
            pgStream.sendInteger4(clientFirstMessageBytes.length);
            pgStream.send(clientFirstMessageBytes);
          }
        }
    );
  }

  public void processServerFirstMessage(int length) throws IOException, PSQLException {
    checkMessageLength(length);
    String serverFirstMessage = pgStream.receiveString(length);
    Sm3ScramSession sm3Session = this.sm3Session;
    if (sm3Session != null) {
      byte[] message = sm3Session.serverFirst(serverFirstMessage, password)
          .getBytes(StandardCharsets.UTF_8);
      sendAuthenticationMessage(message.length, stream -> stream.send(message));
      return;
    }
    LOGGER.log(Level.FINEST, " <=BE AuthenticationSASLContinue( {0} )", serverFirstMessage);

    ScramSession scramSession = this.scramSession;
    if (scramSession == null) {
      throw new PSQLException(
          GT.tr("SCRAM session does not exist"),
          PSQLState.UNKNOWN_STATE
      );
    }

    ScramSession.ServerFirstProcessor serverFirstProcessor;
    try {
      serverFirstProcessor = scramSession.receiveServerFirstMessage(serverFirstMessage);
    } catch (ScramException e) {
      throw new PSQLException(
          GT.tr("Invalid server-first-message: {0}", serverFirstMessage),
          PSQLState.CONNECTION_REJECTED,
          e
      );
    }
    if (LOGGER.isLoggable(Level.FINEST)) {
      LOGGER.log(Level.FINEST,
                 " <=BE AuthenticationSASLContinue(salt={0}, iterations={1})",
                 new Object[]{serverFirstProcessor.getSalt(), serverFirstProcessor.getIteration()}
                 );
    }

    clientFinalProcessor = serverFirstProcessor.clientFinalProcessor(password);

    String clientFinalMessage = clientFinalProcessor.clientFinalMessage();
    LOGGER.log(Level.FINEST, " FE=> SASLResponse( {0} )", clientFinalMessage);

    final byte[] clientFinalMessageBytes = clientFinalMessage.getBytes(StandardCharsets.UTF_8);
    sendAuthenticationMessage(
        clientFinalMessageBytes.length,
        new BodySender() {
          @Override
          public void sendBody(PGStream pgStream) throws IOException {
            pgStream.send(clientFinalMessageBytes);
          }
        }
    );
  }

  public void verifyServerSignature(int length) throws IOException, PSQLException {
    checkMessageLength(length);
    String serverFinalMessage = pgStream.receiveString(length);
    Sm3ScramSession sm3Session = this.sm3Session;
    if (sm3Session != null) {
      sm3Session.serverFinal(serverFinalMessage);
      serverVerified = sm3Session.verified();
      return;
    }
    LOGGER.log(Level.FINEST, " <=BE AuthenticationSASLFinal( {0} )", serverFinalMessage);

    ScramSession.ClientFinalProcessor clientFinalProcessor = this.clientFinalProcessor;
    if (clientFinalProcessor == null) {
      throw new PSQLException(
          GT.tr("SCRAM client final processor does not exist"),
          PSQLState.UNKNOWN_STATE
      );
    }
    try {
      clientFinalProcessor.receiveServerFinalMessage(serverFinalMessage);
      serverVerified = true;
    } catch (ScramParseException e) {
      throw new PSQLException(
          GT.tr("Invalid server-final-message: {0}", serverFinalMessage),
          PSQLState.CONNECTION_REJECTED,
          e
      );
    } catch (ScramServerErrorException e) {
      throw new PSQLException(
          GT.tr("SCRAM authentication failed, server returned error: {0}",
              e.getError().getErrorMessage()),
          PSQLState.CONNECTION_REJECTED,
          e
      );
    } catch (ScramInvalidServerSignatureException e) {
      throw new PSQLException(
          GT.tr("Invalid server SCRAM signature"),
          PSQLState.CONNECTION_REJECTED,
          e
      );
    }
  }

  public boolean isComplete() {
    return serverVerified;
  }

  public void close() {
    Sm3ScramSession sm3Session = this.sm3Session;
    if (sm3Session != null) {
      sm3Session.close();
    }
  }

  private static void checkMessageLength(int length) throws PSQLException {
    if (length < 1 || length > 65536) {
      throw new PSQLException("Invalid SCRAM message length", PSQLState.CONNECTION_REJECTED);
    }
  }

}
