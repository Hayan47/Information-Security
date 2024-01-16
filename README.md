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

-- Connect to the MySQL Server on port 3306
-- Make sure XAMPP is running and MySQL is started

-- Create the "iss1" database
CREATE DATABASE IF NOT EXISTS iss1;
USE iss1;

-- Create the "user" table
CREATE TABLE IF NOT EXISTS user (
    name VARCHAR(20),
    password TEXT(50),
    number INT,
    role ENUM('student', 'doctor')
);

-- Create the "message" table
CREATE TABLE IF NOT EXISTS message (
    name VARCHAR(20),
    message TEXT(100)
);

-- Create the "marks" table
CREATE TABLE IF NOT EXISTS marks (
    student_name VARCHAR(20),
    marks TEXT(100),
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

1. Clone the repository to your local machine:

    ```bash
    https://github.com/Hayan47/Information-Security.git
    ```
    
2. Run the server

3. Run the CA

4. Run the client


## Usage

- Update the keystore password in the code to match your security requirements.
- Modify the CA's subject distinguished name and other parameters in `CertificateGenerator` based on your use case.
- Customize the server logic in the `Server` class as needed for your application.


## Acknowledgments

- Bouncy Castle Library: [https://www.bouncycastle.org/](https://www.bouncycastle.org/)



