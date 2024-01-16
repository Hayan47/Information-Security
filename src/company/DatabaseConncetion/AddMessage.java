package company.DatabaseConncetion;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
public class AddMessage {
    public boolean addMessage(String name, String message) {
        String insertQuery = "INSERT INTO message (name, message) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/ISS1?user=root");
             PreparedStatement pstmt = conn.prepareStatement(insertQuery)) {

            pstmt.setString(1, name);
            pstmt.setString(2, message);

            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;

        } catch (SQLException e) {
            System.err.println("SQL error: " + e.getMessage());
            return false;
        }
    }
}
