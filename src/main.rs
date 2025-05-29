use std::collections::HashMap;
use std::fs::{File, read_to_string};
use std::io::{self, Write, Read};
use std::path::Path;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};
use toml::de::from_str;
use clap::Parser;

#[derive(Serialize, Deserialize)]
struct Config {
    data_file: String,
}

// Structure to store login and password together
#[derive(Serialize, Deserialize, Debug, Clone)]
struct AccountDetails {
    login: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct Passwords {
    accounts: HashMap<String, AccountDetails>, 
}

#[derive(Parser)]
struct Cli {
    // Path to the configuration file
    #[clap(short, long, default_value = "config.toml")]
    config: String,
}

fn load_config(config_path: &str) -> Result<Config, String> {
    let config_str = read_to_string(config_path).map_err(|e| format!("Error reading config file: {}", e))?;
    let config: Config = from_str(&config_str).map_err(|e| format!("Error parsing config file: {}", e))?;
    Ok(config)
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let config = load_config(&cli.config).unwrap_or_else(|err| {
        println!("{}", err);
        std::process::exit(1);
    });

    println!("Welcome to the password manager!");

    // Request master password
    let master_password = prompt("Enter your master password:");

    // Load or initialize data
    let mut passwords = load_passwords(&master_password, &config.data_file).unwrap_or_else(|_| {
        println!("Unable to decrypt data. Master password incorrect or file not found.");
        HashMap::new()
    });

    loop {
        println!("\nOptions:");
        println!("1. Add an account");
        println!("2. Display accounts and passwords");
        println!("3. Search an account");
        println!("4. Delete an account");
        println!("5. Quit");

        match prompt("Choose an option:").as_str() {
            "1" => add_account(&mut passwords),
            "2" => list_accounts(&passwords),
            "3" => search_account(&passwords),
            "4" => delete_account(&mut passwords),
            "5" => {
                save_passwords(&passwords, &master_password, &config.data_file).expect("Error saving data");
                println!("Data saved. Goodbye!");
                break;
            }
            _ => println!("Invalid choice, please try again."),
        }
    }

    Ok(())
}

fn search_account(passwords: &HashMap<String, AccountDetails>) { 
    let app_name = prompt("Enter the application name to search for:");

    match passwords.get(&app_name) {
        Some(details) => println!("Account found! Login: {}, Password: {}", details.login, details.password),
        None => println!("Account not found."),
    }
}

fn delete_account(passwords: &mut HashMap<String, AccountDetails>) { 
    let app_name = prompt("Enter the application name to delete:");

    if passwords.remove(&app_name).is_some() {
        println!("Account '{}' deleted successfully!", app_name);
    } else {
        println!("Account '{}' not found.", app_name);
    }
}

fn prompt(message: &str) -> String {
    println!("{}", message);
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Reading error");
    input.trim().to_string()
}

fn add_account(passwords: &mut HashMap<String, AccountDetails>) { 
    let app_name = prompt("Enter application name:");
    let login = prompt("Enter login:");
    let password = prompt("Enter password:");

    let details = AccountDetails { login, password };
    passwords.insert(app_name, details);
    println!("Account added successfully!");
}

fn list_accounts(passwords: &HashMap<String, AccountDetails>) { 
    if passwords.is_empty() {
        println!("No accounts registered.");
    } else {
        println!("Registered accounts:");
        for (app_name, details) in passwords {
            println!("- Application: {}, Login: {}, Password: {}", app_name, details.login, details.password);
        }
    }
}

fn save_passwords(passwords: &HashMap<String, AccountDetails>, master_password: &str, data_file: &str) -> Result<(), String> { 
    let serialized = serde_json::to_string(&Passwords { accounts: passwords.clone() })
        .map_err(|e| format!("Serialization error: {}", e))?;
    let key = derive_key(master_password);
    let cipher = Aes256Gcm::new(&key);

    let ciphertext = cipher.encrypt(Nonce::from_slice(b"unique_nonce"), serialized.as_bytes())
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let mut file = File::create(data_file).map_err(|e| format!("File creation error: {}", e))?;
    file.write_all(&ciphertext).map_err(|e| format!("File write error: {}", e))?;
    Ok(())
}

fn load_passwords(master_password: &str, data_file: &str) -> Result<HashMap<String, AccountDetails>, String> { 
    if !Path::new(data_file).exists() {
        return Err("Data file not found.".to_string());
    }

    let mut file = File::open(data_file).map_err(|e| format!("File open error: {}", e))?;
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext).map_err(|e| format!("File read error: {}", e))?;

    let key = derive_key(master_password);
    let cipher = Aes256Gcm::new(&key);

    let plaintext = cipher.decrypt(Nonce::from_slice(b"unique_nonce"), ciphertext.as_ref())
        .map_err(|e| format!("Decryption error: {:?}", e))?;
    let passwords: Passwords = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Deserialization error: {}", e))?;

    Ok(passwords.accounts)
}

fn derive_key(master_password: &str) -> aes_gcm::Key<Aes256Gcm> {
    let hash = Sha256::digest(master_password.as_bytes());
    aes_gcm::Key::<Aes256Gcm>::clone_from_slice(&hash[..32])
}
