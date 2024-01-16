# Secure Java Server with CA Certificate

This repository contains a simple Java project demonstrating a secure server implementation using Bouncy Castle for cryptographic operations and a Certificate Authority (CA) for secure communication.

## Features

- Server implementation with secure communication.
- CA certificate generation and management.
- Key pair generation and secure storage.

## Prerequisites

- Java Development Kit (JDK) installed (version 20 or higher).
- MySQL Server (xampp)

## Getting Started

1. Clone the repository to your local machine:

    ```bash
    https://github.com/Hayan47/Information-Security.git
    ```
    
2. Run the server

3. Run the CA

4. Run the client


## MySQL Server Configuration

To set up the MySQL server on port 3306 using XAMPP:

1. Make sure XAMPP is installed and MySQL is started.
2. Open a MySQL client, such as phpMyAdmin.
3. Copy and paste the following SQL statements into the SQL query editor.
4. Execute the SQL statements.

### Create "iss1" Database

```sql
CREATE DATABASE IF NOT EXISTS iss1;
USE iss1;
```

### Create user Table

```sql
CREATE TABLE IF NOT EXISTS user (
    name VARCHAR(20),
    password TEXT(50),
    number INT,
    role ENUM('student', 'doctor')
);
```


### Create message Table

```sql
CREATE TABLE IF NOT EXISTS message (
    name VARCHAR(20),
    message TEXT(100)
);
```


### Create marks Table

```sql
CREATE TABLE IF NOT EXISTS marks (
    student_name VARCHAR(20),
    marks TEXT(100),
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Usage

- Update the keystore password in the code to match your security requirements.
- Modify the CA's subject distinguished name and other parameters in `CertificateGenerator` based on your use case.
- Customize the server logic in the `Server` class as needed for your application.


## Acknowledgments

- Bouncy Castle Library: [https://www.bouncycastle.org/](https://www.bouncycastle.org/)



