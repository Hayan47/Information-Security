package company;

import java.sql.*;

public class Login {
    String name, password, role;

    public Login(String name, String password, String role){
        this.password=password;
        this.name=name;
        this.role = role;
    }

public boolean login() {
    try {
        Class.forName("com.mysql.cj.jdbc.Driver");
        try (Connection con = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/ISS1?user=root")) {
            String query = "SELECT * FROM user WHERE name = ?";
            try (PreparedStatement pst = con.prepareStatement(query)) {
                pst.setString(1, this.name);
                ResultSet rs = pst.executeQuery();
                if (rs.next()) {
                    String storedPassword = rs.getString("password");
                    if (storedPassword.equals(this.password)) {
                        System.out.println("Login successful");
                        return true;
                    } else {
                        System.out.println("Invalid name or password");
                        return false;
                    }
                } else {
                    insertNewUser(con);
                    return true;
                }
            }
        }
    } catch (SQLException | ClassNotFoundException e) {
        System.err.println("Database connection error: " + e.getMessage());
        return false;
    }
}

    private void insertNewUser(Connection con) {
        String insertQuery = "INSERT INTO user (name, password, role) VALUES (?, ?, ?)";
        try (PreparedStatement pst = con.prepareStatement(insertQuery)) {
            if(role.equalsIgnoreCase("s")) role = "student";
            if(role.equalsIgnoreCase("d")) role = "doctor";
            pst.setString(1, name);
            pst.setString(2, password);
            pst.setString(3, role);
            pst.executeUpdate();
            System.out.println("New user created");
        } catch (SQLException e) {
            System.err.println("Error inserting new user: " + e.getMessage());
        }
    }
}
