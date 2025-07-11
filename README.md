# Rust Simple Password Manager

A simple password manager written in Rust that allows you to securely store 
and manage your passwords. 

This application uses AES-256 encryption to protect your sensitive data 
and stores it in a specified file.

## Features

- **Secure Storage**: Passwords are encrypted using AES-256-GCM before being saved to disk.
- **Configuration File**: Specify the path to the data file using a TOML configuration file.
- **Command-Line Interface**: Easily interact with the application through a command-line interface.
- **Account Management**: Add accounts with usernames and passwords, and display them when needed.

## Requirements
Rust (1.50 or later)

Cargo (comes with Rust)

## Installation
Clone the repository:
```
git clone 
cd rust-vault
````


## Build the project:
```
cargo build
```
Create a configuration file named config.toml in the root directory with the following content:

```
data_file = "passwords.enc"
```

## Usage
Run the application with the following command:

```
./rust-vault-linux-x86_64  -c config.toml
```

## Options
-c or --config: Specify the path to the configuration file (default is config.toml).

## Commands

- **Add an Account**: You will be prompted to enter the account name and password.
- **Display Accounts and Passwords**: Lists all registered accounts along with their passwords.
- **Search**: You will search for an accounts along with their passwords.
- **Delete**: You will delete for an accounts along with their passwords.
- **Quit**: Saves the data and exits the application.

## Security Note
Be cautious when displaying passwords in the terminal. 

This application is intended for personal use and should not be used in production 
environments without further security measures.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an 
issue for any suggestions or improvements.
