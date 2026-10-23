import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/** New physical connections only: prove the loaded driver, SM3 method and rejection. */
public final class Sm3Verify {
  public static void main(String[] args) throws Exception {
    String url = required("SM3_JDBC_URL");
    Properties properties = new Properties();
    properties.setProperty("user", required("SM3_DB_USER"));
    properties.setProperty("password", required("SM3_DB_PASSWORD"));
    properties.setProperty("connectTimeout", "10");
    Class<?> driver = Class.forName("org.postgresql.Driver");
    System.out.println("Driver JAR: " + driver.getProtectionDomain().getCodeSource().getLocation());
    try (Connection connection = DriverManager.getConnection(url, properties);
         Statement statement = connection.createStatement()) {
      System.out.println("Driver version: " + connection.getMetaData().getDriverVersion());
      try (ResultSet rs = statement.executeQuery(
          "SELECT current_user, system_user, current_database(), version()")) {
        rs.next();
        String authenticated = rs.getString(2);
        System.out.println("User: " + rs.getString(1));
        System.out.println("Authenticated identity: " + authenticated);
        System.out.println("Database: " + rs.getString(3));
        System.out.println("Server: " + rs.getString(4));
        if (authenticated == null || !authenticated.startsWith("scram-sm3:")) {
          throw new IllegalStateException("This connection did not authenticate with scram-sm3");
        }
      }
    }
    properties.setProperty("password", required("SM3_DB_PASSWORD") + "-intentional-wrong-password");
    try (Connection ignored = DriverManager.getConnection(url, properties)) {
      throw new IllegalStateException("Wrong password was accepted");
    } catch (SQLException expected) {
      if (!"28P01".equals(expected.getSQLState())) {
        throw expected;
      }
      System.out.println("Wrong password rejected: SQLSTATE " + expected.getSQLState());
    }
    System.out.println("SM3 verification PASS");
  }

  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException("Set environment variable " + name);
    }
    return value;
  }
}
