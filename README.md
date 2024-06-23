# Domain-Information-Tool

Welcome! The Domain Information Tool is a powerful utility that allows you to quickly and easily gather domain information and perform security checks. This guide will walk you through how to use the application step by step.

Downloading and Installing the Application Download the Application: To download the application, run the following command in your terminal:
git clone https://github.com/irfankocak/domain-information-tool.git Navigate to the Directory: Move to the downloaded directory:

cd domain-information-tool Install Dependencies: Install the necessary Go modules:

go mod tidy Run the Application: To start the application, run:

go run main.go 2. Using the Application When you run the application, a menu will appear. Use this menu to perform the desired scanning operations.

Viewing the Menu You will see the following menu options:

[img]https://i.hizliresim.com/wx3vzkt.png[/img]

=== Domain Information Tool ===

Basic Scan
Port Scan
Security Headers
Subdomains
Detect WAF
Blacklist Check
Detect Server Technologies
Full Scan
Exit
Please enter your choice: Options and Descriptions Basic Scan: This option performs a basic scan including WHOIS, SSL, SSL Labs, DNS records, DNS Zone Transfer, and DNSSEC checks.

Port Scan: This option scans and lists open ports for the domain.

Security Headers: This option checks the security headers of the domain.

Subdomains: This option discovers subdomains of the domain.

Detect WAF: This option detects Web Application Firewalls (WAF).

Blacklist Check: This option checks if the domain is listed in any blacklists.

Detect Server Technologies: This option detects the technologies used by the server.

Full Scan: This option performs all the above scanning operations.

Exit: Exits the application.

Selecting an Option To select an option from the menu, enter the corresponding number and press Enter. For example, to start a Basic Scan, type 1 and press Enter.

Entering a Domain After selecting a scanning option, you will be prompted to enter the domain you wish to scan:

Please enter the domain (e.g. example.com): Enter the domain and press Enter. The scanning process will begin, and the results will be displayed on the screen.

Viewing Scan Results Once the scanning is complete, the relevant information will be displayed on the screen in a clear and organized manner. Each scanning operation will have its own section with detailed results.

Exiting the Application To exit the application, select the 0 option from the menu and press Enter.

Additional Information Logs and Errors: If any errors occur during the operation, error messages will be displayed in red. You can review these messages for details and troubleshooting.

Feedback and Support: If you encounter any issues or have suggestions, please contact. We are here to help and appreciate your feedback.

Thank You Thank you for using the Domain Information Tool! We wish you successful and secure scanning operations. 
<a href="https://www.linkedin.com/in/irfan-ko%C3%A7ak-5333bb60/">Linkedin</a>
