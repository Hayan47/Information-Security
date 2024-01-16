package company.DatabaseConncetion;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
public class AddNumber {

    public boolean addNumber(String name, int number) {
        String sql = "UPDATE user SET number = ? WHERE name = ?";

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/ISS1?user=root");
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, number);
            pstmt.setString(2, name);

            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;

        } catch (SQLException e) {
            System.err.println("SQL error: " + e.getMessage());
            return false;
        }
    }
}
