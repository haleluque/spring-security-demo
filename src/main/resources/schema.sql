-- First, enable the citext extension if it's not already enabled
CREATE EXTENSION IF NOT EXISTS citext;

-- Create the users table
CREATE TABLE users (
    username CITEXT NOT NULL PRIMARY KEY,
    password CITEXT NOT NULL,
    enabled BOOLEAN NOT NULL
);

-- Create the authorities table
CREATE TABLE authorities (
    username CITEXT NOT NULL,
    authority CITEXT NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users (username)
);

-- Create a unique index on the authorities table
CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);