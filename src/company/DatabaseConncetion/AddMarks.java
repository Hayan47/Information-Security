package company.DatabaseConncetion;
import org.json.JSONObject;

import java.sql.*;

public class AddMarks {
    public String addMarks(String name, String marks) {
        String insertQuery = "INSERT INTO marks (student_name, marks) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/ISS1?user=root");
             PreparedStatement pstmt = conn.prepareStatement(insertQuery, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, name);
            pstmt.setString(2, marks);

            int affectedRows = pstmt.executeUpdate();
            ResultSet rs = pstmt.getGeneratedKeys();
            int id = -1;
            if (rs.next()) {
                id = rs.getInt(1);
            }

            // Select created_at for this id
            String selectQuery = "SELECT created_at FROM marks WHERE id = ?";
            PreparedStatement selectStmt = conn.prepareStatement(selectQuery);
            selectStmt.setInt(1, id);
            ResultSet result = selectStmt.executeQuery();
            Timestamp createdAt = null;
            if (result.next()) {
                createdAt = result.getTimestamp("created_at");
            }

            JSONObject response = new JSONObject();
            String createdAtString = createdAt.toString();
            response.put("id", id);
            response.put("createdAt", createdAtString);

            return response.toString();

        } catch (SQLException e) {
            System.err.println("SQL error: " + e.getMessage());
            return "Failed to add marks";
        }
    }
}
