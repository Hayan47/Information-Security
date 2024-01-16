package company.DatabaseConncetion;
import java.sql.*;

public class GetMarks {
    public String getMarks(String name) {
        String selectQuery = "SELECT marks FROM marks WHERE student_name = ?";

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/ISS1?user=root");
             PreparedStatement pstmt = conn.prepareStatement(selectQuery)) {

            pstmt.setString(1, name);

            ResultSet result = pstmt.executeQuery();
            if (result.next()) {
                return result.getString("marks");
            } else {
                return "Marks not found for student: " + name;
            }

        } catch (SQLException e) {
            System.err.println("SQL error: " + e.getMessage());
            return "Failed to retrieve marks";
        }
    }
}
