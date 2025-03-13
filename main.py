"""
Full Email Validation and Fake Domain Scraper Application
=========================================================
This application consists of two main parts:

1) Email Validation (Main Window - EmailCheckerApp)
   - Loads emails from a CSV file and verifies them using DNS and SMTP checks.
   - Splits the interface into four panels (Domain Validation, Email Validation, Verified Emails, Logs).
   - Manages threads to process multiple emails concurrently.
   - Stores valid emails in 'temizlenmis_eposta_listesi.csv' and invalid emails in 'sahte_eposta_listesi.csv'.
   - Skips already processed emails (both valid and invalid) to avoid redundant checks.

2) Fake Domain Scraper (Second Window - DomainScraperApp)
   - Loads a CSV file that contains "fake emails" (invalid emails).
   - Extracts domains from these emails and checks if they exist (DNS/socket reachability).
   - If the domain exists and hosts a live website, it scrapes the homepage and internal links
     for any discoverable email addresses.
   - Discovered emails are stored in 'kesfedilen_eposta_adresleri.csv'.
   - Once a domain has been checked, it is recorded in 'kontrol_edilmis_sahte_domainler.csv'
     to avoid re-checking the same domain.

Environment Variables (.env):
-----------------------------
- CHECK_TIMEOUT (default 5): Timeout in seconds for DNS, socket, and HTTP requests.
- THREAD_COUNT  (default 10): Number of threads to spawn for concurrent email validation.
- SMTP_SERVER
- SMTP_PORT
- SMTP_USER
- SMTP_PASSWORD

Usage:
------
1. Run this script.
2. In the main "Email Validation Application" window, click "Select CSV and Start" to pick a CSV
   containing emails in a column named "email". This will start the validation process in threads.
3. For the Fake Domain Scraper, click "Fake Domain Scraper" to open a new window. Then select another
   CSV file containing "fake emails" in a column named "email". This will start the domain scraping process.
4. Newly discovered emails from the domain scraper are appended to 'kesfedilen_eposta_adresleri.csv'.

Note: This application uses Python's tkinter for GUI. Make sure you have the required libraries installed:
    pip install python-dotenv dnspython requests beautifulsoup4
"""

import csv
import re
import os
import socket
import smtplib
import dns.resolver
import threading
import queue
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog, ttk
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# Load environment variables
# -----------------------------------------------------------------------------
load_dotenv()

# -----------------------------------------------------------------------------
# Configuration Settings
# -----------------------------------------------------------------------------
CONFIG = {
    "CHECK_TIMEOUT": int(os.getenv("CHECK_TIMEOUT", 5)),  # Default 5
    "THREAD_COUNT": int(os.getenv("THREAD_COUNT", 10)),   # Default 10
    "SMTP_SETTINGS": {
        "SERVER": os.getenv("SMTP_SERVER"),
        "PORT": int(os.getenv("SMTP_PORT", 465)),
        "USER": os.getenv("SMTP_USER"),
        "PASSWORD": os.getenv("SMTP_PASSWORD")
    }
}


def validate_config():
    """
    Validates that all required SMTP environment variables are set.
    Raises EnvironmentError if any are missing.
    """
    required_vars = ["SMTP_SERVER", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing_vars)}\n"
            "Please check your .env file."
        )


# Ensure essential environment variables are present
validate_config()


# -----------------------------------------------------------------------------
# Caches and Data Structures
# -----------------------------------------------------------------------------
checked_domains = {}       # Cache for domains and their MX/A records
checked_emails = set()     # Cache for emails already checked (if needed)
email_queue = queue.Queue() # Thread-safe queue for email processing
processed_emails = set()   # Stores all processed emails (both valid and invalid)


# -----------------------------------------------------------------------------
# Helper Functions for Logging in the Main Window
# -----------------------------------------------------------------------------
def domain_log(msg: str):
    """Writes messages to the domain validation panel in the main app."""
    app.domain_text.insert(tk.END, msg + "\n")
    app.domain_text.see(tk.END)


def email_log(msg: str):
    """Writes messages to the email validation panel in the main app."""
    app.email_text.insert(tk.END, msg + "\n")
    app.email_text.see(tk.END)


def valid_log(msg: str):
    """Writes messages to the verified emails panel in the main app."""
    app.valid_text.insert(tk.END, msg + "\n")
    app.valid_text.see(tk.END)


def main_log(msg: str):
    """Writes messages to the general log panel in the main app."""
    app.log_text.insert(tk.END, msg + "\n")
    app.log_text.see(tk.END)


# -----------------------------------------------------------------------------
# Utility Functions for Loading and Validating Emails
# -----------------------------------------------------------------------------
def load_processed_emails():
    """
    Loads previously stored valid and invalid emails from:
        - temizlenmis_eposta_listesi.csv  (valid)
        - sahte_eposta_listesi.csv        (invalid)
    Adds them to 'processed_emails' set to skip them in future runs.
    """
    if os.path.exists("temizlenmis_eposta_listesi.csv"):
        with open("temizlenmis_eposta_listesi.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 0:
                    processed_emails.add(row[0])

    if os.path.exists("sahte_eposta_listesi.csv"):
        with open("sahte_eposta_listesi.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 0:
                    processed_emails.add(row[0])


def is_valid_email_format(email: str) -> bool:
    """
    Uses a regex pattern to check if an email address has a valid format.
    Returns True if valid, False otherwise.
    """
    pattern = r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$"
    return bool(re.match(pattern, email))


# -----------------------------------------------------------------------------
# DNS and SMTP Checking Functions
# -----------------------------------------------------------------------------
def is_valid_domain(domain):
    # Geliştirilmiş ve alt alan adlarına izin veren domain regex'i
    domain_regex = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
    return bool(re.match(domain_regex, domain))


def get_mx_or_a_record(domain: str) -> str | None:
    """
    Tries to retrieve the MX record for a domain. If none found, tries A record.
    Returns None if both attempts fail.
    """
    if not domain or not is_valid_domain(domain):
        domain_log(f"⚠️ Invalid domain skipped: {domain}")
        return None

    if domain in checked_domains:
        return checked_domains[domain]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver.lifetime = CONFIG["CHECK_TIMEOUT"]

    # Try MX lookup
    try:
        mx_records = resolver.resolve(domain, "MX")
        mx_server = str(mx_records[0].exchange).rstrip(".")
        checked_domains[domain] = mx_server
        domain_log(f"✅ MX: {domain} -> {mx_server}")
        return mx_server
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        domain_log(f"⚠️ No MX record for domain: {domain}")
    except dns.resolver.NoNameservers:
        domain_log(f"❌ DNS did not respond: {domain}")

    # Try A record as fallback
    try:
        a_record = socket.gethostbyname(domain)
        checked_domains[domain] = a_record
        domain_log(f"✅ A record found: {domain} -> {a_record}")
        return a_record
    except (socket.gaierror, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        domain_log(f"❌ No MX/A record found: {domain}")

    checked_domains[domain] = None
    return None



def get_website_title(domain: str) -> str:
    """
    Makes an HTTP request (both http:// and https://) to retrieve a domain's homepage.
    Returns the <title> if found, else 'Title Unavailable'.
    """
    email_log(f"🌐 Fetching title: {domain}")
    for scheme in ["http://", "https://"]:
        try:
            resp = requests.get(f"{scheme}{domain}", timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.title.string.strip() if soup.title else "No Title"
                email_log(f"✅ Title found: {domain} -> {title}")
                return title
        except:
            continue
    email_log(f"❌ No title: {domain}")
    return "Title Unavailable"

def is_valid_email(email):
    # Basit bir e-posta regex doğrulama
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))


def validate_email(email: str) -> bool:
    """
    Validates an email address by checking:
      1) Format correctness with regex
      2) Domain existence (MX or A record)
      3) SMTP handshake on ports 25, 587, 465
    Returns True if any SMTP check is successful, False otherwise.
    """
    if not is_valid_email(email):
        raise ValueError(f"Invalid email format: {email}")

    email_log(f"📧 Checking: {email}")

    # 1) Format
    if not is_valid_email_format(email):
        email_log(f"❌ Invalid format: {email}")
        return False

    # 2) Domain check
    domain = email.split("@")[-1]
    mail_server = get_mx_or_a_record(domain)
    if not mail_server:
        email_log(f"❌ Invalid domain: {email}")
        return False

    # 3) SMTP handshake
    smtp_ports = [25, 587, 465]
    for port in smtp_ports:
        try:
            email_log(f"🔍 Trying: {mail_server}:{port} => {email}")
            if port == 465:
                with smtplib.SMTP_SSL(mail_server, port, timeout=CONFIG["CHECK_TIMEOUT"]) as server:
                    server.login(CONFIG["SMTP_SETTINGS"]["USER"], CONFIG["SMTP_SETTINGS"]["PASSWORD"])
                    server.ehlo()
                    server.mail(CONFIG["SMTP_SETTINGS"]["USER"])
                    code, _ = server.rcpt(email)
                    if code == 250:
                        email_log(f"✅ SMTP verified (SSL): {email}")
                        return True
            else:
                with smtplib.SMTP(mail_server, port, timeout=CONFIG["CHECK_TIMEOUT"]) as server:
                    server.ehlo()
                    if port == 587:
                        server.starttls()
                        server.ehlo()
                    server.mail("verify@example.com")
                    code, _ = server.rcpt(email)
                    if code == 250:
                        email_log(f"✅ SMTP verified (Port {port}): {email}")
                        return True
        except (smtplib.SMTPException, socket.error) as e:
            email_log(f"⚠️ Error: {mail_server}:{port} => {email} | {e}")
            continue

    email_log(f"❌ All attempts failed: {email}")
    return False


# -----------------------------------------------------------------------------
# Main Application for Email Validation
# -----------------------------------------------------------------------------
class EmailCheckerApp(tk.Tk):
    """
    Main application window for Email Validation.
    2x2 grid:
      - Top-left:    Domain Validation Panel
      - Top-right:   Email Validation Panel
      - Bottom-left: Verified Emails Panel
      - Bottom-right: Log Panel
    """
    def __init__(self):
        super().__init__()
        self.title("Email Validation Application")
        self.geometry("1200x700")

        # Configure 2x2 grid
        self.grid_columnconfigure(0, weight=1, uniform="col")
        self.grid_columnconfigure(1, weight=1, uniform="col")
        self.grid_rowconfigure(0, weight=1, uniform="row")
        self.grid_rowconfigure(1, weight=1, uniform="row")

        # 1. Domain Validation Panel
        domain_frame = ttk.Frame(self, padding=5)
        domain_frame.grid(row=0, column=0, sticky="nsew")
        domain_label = ttk.Label(domain_frame, text="Domain Validation Panel", font=("Arial", 12, "bold"))
        domain_label.pack(anchor="center")
        self.domain_text = tk.Text(domain_frame, wrap="word", state="normal")
        self.domain_text.pack(expand=True, fill="both")

        # 2. Email Validation Panel
        email_frame = ttk.Frame(self, padding=5)
        email_frame.grid(row=0, column=1, sticky="nsew")
        email_label = ttk.Label(email_frame, text="Email Validation Panel", font=("Arial", 12, "bold"))
        email_label.pack(anchor="center")
        self.email_text = tk.Text(email_frame, wrap="word")
        self.email_text.pack(expand=True, fill="both")

        # 3. Verified Emails Panel
        valid_frame = ttk.Frame(self, padding=5)
        valid_frame.grid(row=1, column=0, sticky="nsew")
        valid_label = ttk.Label(valid_frame, text="Verified Emails", font=("Arial", 12, "bold"))
        valid_label.pack(anchor="center")
        self.valid_text = tk.Text(valid_frame, wrap="word")
        self.valid_text.pack(expand=True, fill="both")

        # 4. Log Panel
        log_frame = ttk.Frame(self, padding=5)
        log_frame.grid(row=1, column=1, sticky="nsew")
        log_label = ttk.Label(log_frame, text="Log Records", font=("Arial", 12, "bold"))
        log_label.pack(anchor="center")
        self.log_text = tk.Text(log_frame, wrap="word")
        self.log_text.pack(expand=True, fill="both")

        # Bottom Button Section
        bottom_frame = ttk.Frame(self, padding=2)
        bottom_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

        self.start_button = ttk.Button(bottom_frame, text="Select CSV and Start", command=self.select_file)
        self.start_button.pack(anchor="center")

        # Button to open Fake Domain Scraper window
        self.scraper_button = ttk.Button(bottom_frame, text="Fake Domain Scraper", command=self.open_scraper_window)
        self.scraper_button.pack(anchor="center")

    def open_scraper_window(self):
        """Opens the second window for Fake Domain Scraper."""
        DomainScraperApp(self)

    def select_file(self):
        """Prompts the user to select a CSV file for email validation."""
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if file_path:
            self.run_checker_in_thread(file_path)

    def run_checker_in_thread(self, file_path: str):
        """Starts a new thread for processing the given CSV file."""
        t = threading.Thread(target=self.process_csv, args=(file_path,))
        t.start()

    def process_csv(self, file_path: str):
        """
        Main email validation workflow. Reads from CSV, enqueues emails, spawns threads
        for validation, and stores results in separate CSV files.
        """
        # 1) Load previously processed emails (valid/invalid)
        load_processed_emails()

        # 2) Count total lines for logging
        with open(file_path, "r", encoding="utf-8") as f_in:
            lines = f_in.readlines()
        total_rows = len(lines) - 1
        main_log(f"📊 Total Emails: {total_rows}")

        # 3) Clear any old data in the queue, then enqueue new emails
        email_queue.queue.clear()
        with open(file_path, "r", encoding="utf-8") as f_in:
            reader = csv.DictReader(f_in)
            for row in reader:
                email = row["email"].strip()
                if email in processed_emails:
                    main_log(f"⏭ Already Processed: {email}")
                    continue
                email_queue.put(email)

        # 4) Start threads for processing
        threads = []
        for _ in range(CONFIG["THREAD_COUNT"]):
            t = threading.Thread(target=self.process_email_queue)
            t.start()
            threads.append(t)

        # Wait for queue to be empty
        email_queue.join()

        # Cleanup: put None to stop threads
        for _ in threads:
            email_queue.put(None)
        for t in threads:
            t.join()

        main_log("🚀 All operations completed!")

    def process_email_queue(self):
        while True:
            email = email_queue.get()
            if email is None:
                email_queue.task_done()
                break

            try:
                if validate_email(email):
                    domain = email.split("@")[-1]
                    title = get_website_title(domain)
                    with open("temizlenmis_eposta_listesi.csv", "a", newline="", encoding="utf-8") as f_valid:
                        writer = csv.writer(f_valid)
                        writer.writerow([email, domain, title])
                    valid_log(f"✔ {email} => Valid (Domain: {domain}, Title: {title})")
                else:
                    with open("sahte_eposta_listesi.csv", "a", newline="", encoding="utf-8") as f_invalid:
                        writer = csv.writer(f_invalid)
                        writer.writerow([email])
                    main_log(f"❌ {email} => Invalid")

                processed_emails.add(email)

            # Exception Handling
            except Exception as e:
                main_log(f"⚠️ Error processing {email}: {e}")

            finally:
                email_queue.task_done()


# -----------------------------------------------------------------------------
# Second Window: Fake Domain Scraper
# -----------------------------------------------------------------------------
class DomainScraperApp(tk.Toplevel):
    """
    A secondary window to analyze "fake emails" from a CSV file.
    Verifies whether their domains actually exist and, if so, tries to
    scrape the homepage and internal links to find new email addresses.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Fake Domain Scraper")
        self.geometry("800x600")

        # Configure 2x2 grid for display
        self.grid_columnconfigure(0, weight=1, uniform="col")
        self.grid_columnconfigure(1, weight=1, uniform="col")
        self.grid_rowconfigure(0, weight=1, uniform="row")
        self.grid_rowconfigure(1, weight=1, uniform="row")

        # Top-left: Processed Email
        self.email_frame = ttk.Frame(self, padding=5)
        self.email_frame.grid(row=0, column=0, sticky="nsew")
        self.email_label = ttk.Label(self.email_frame, text="Processed Email", font=("Arial", 12, "bold"))
        self.email_label.pack(anchor="center")
        self.email_text = tk.Text(self.email_frame, wrap="word")
        self.email_text.pack(expand=True, fill="both")

        # Top-right: Visited Domain
        self.domain_frame = ttk.Frame(self, padding=5)
        self.domain_frame.grid(row=0, column=1, sticky="nsew")
        self.domain_label = ttk.Label(self.domain_frame, text="Visited Domain", font=("Arial", 12, "bold"))
        self.domain_label.pack(anchor="center")
        self.domain_text = tk.Text(self.domain_frame, wrap="word")
        self.domain_text.pack(expand=True, fill="both")

        # Bottom-left: Visited Page
        self.visited_page_frame = ttk.Frame(self, padding=5)
        self.visited_page_frame.grid(row=1, column=0, sticky="nsew")
        self.visited_page_label = ttk.Label(self.visited_page_frame, text="Visited Page", font=("Arial", 12, "bold"))
        self.visited_page_label.pack(anchor="center")
        self.visited_page_text = tk.Text(self.visited_page_frame, wrap="word")
        self.visited_page_text.pack(expand=True, fill="both")

        # Bottom-right: Discovered Email
        self.discovered_email_frame = ttk.Frame(self, padding=5)
        self.discovered_email_frame.grid(row=1, column=1, sticky="nsew")
        self.discovered_email_label = ttk.Label(self.discovered_email_frame, text="Discovered Email", font=("Arial", 12, "bold"))
        self.discovered_email_label.pack(anchor="center")
        self.discovered_email_text = tk.Text(self.discovered_email_frame, wrap="word")
        self.discovered_email_text.pack(expand=True, fill="both")

        # Bottom Frame for CSV selection
        bottom_frame = ttk.Frame(self, padding=5)
        bottom_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

        self.select_button = ttk.Button(bottom_frame, text="Select CSV File", command=self.select_csv_file)
        self.select_button.pack(side="left", padx=5)

    def select_csv_file(self):
        """Prompts the user to select a CSV file containing fake emails."""
        file_path = filedialog.askopenfilename(
            title="Select Fake Emails CSV",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if file_path:
            self.process_fake_emails(file_path)

    def process_fake_emails(self, file_path):
        """
        Starts a new thread to process the fake emails so that UI remains responsive.
        """
        t = threading.Thread(target=self._process_fake_emails_in_thread, args=(file_path,))
        t.start()

    # ---------------------
    # Core Domain Analysis
    # ---------------------
    def _process_fake_emails_in_thread(self, file_path: str):
        """
        Reads fake emails from a CSV, checks if their domains exist, and if so,
        scrapes them for discoverable email addresses. Results are stored in:
          - kesfedilen_eposta_adresleri.csv
          - kontrol_edilmis_sahte_domainler.csv
        """
        # 1) Load previously checked domains from kontrol_edilmis_sahte_domainler.csv
        checked_fake_domains = set()
        if os.path.exists("kontrol_edilmis_sahte_domainler.csv"):
            with open("kontrol_edilmis_sahte_domainler.csv", "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) > 0:
                        checked_fake_domains.add(row[0])

        # 2) Read fake emails from CSV
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row["email"].strip()
                domain = email.split("@")[-1]

                self._log_to_text(self.email_text, f"Processing => {email}")

                # Skip if domain already checked
                if domain in checked_fake_domains:
                    self._log_to_text(self.domain_text, f"Skipped (Previously checked): {domain}")
                    continue

                # Check domain reachability
                if not self._is_domain_reachable(domain):
                    self._log_to_text(self.domain_text, f"Domain not reachable: {domain}")
                    # Mark domain as checked
                    checked_fake_domains.add(domain)
                    self._append_to_csv("kontrol_edilmis_sahte_domainler.csv", [domain])
                    continue

                # Check if website is alive
                if self._check_website(domain):
                    discovered_emails = self._scrape_website(domain)
                    # Store discovered emails
                    for found in discovered_emails:
                        self._log_to_text(self.discovered_email_text, f"Discovered => {found}")
                        self._append_to_csv("kesfedilen_eposta_adresleri.csv", [found])
                else:
                    self._log_to_text(self.domain_text, f"No response from site: {domain}")

                # Mark domain as checked
                checked_fake_domains.add(domain)
                self._append_to_csv("kontrol_edilmis_sahte_domainler.csv", [domain])

    # --------------------------------------------------
    # Helper Functions for the Domain Scraper
    # --------------------------------------------------
    def _log_to_text(self, widget: tk.Text, msg: str):
        """
        Writes 'msg' to the specified Text widget and scrolls to the bottom.
        """
        widget.insert(tk.END, msg + "\n")
        widget.see(tk.END)

    def _append_to_csv(self, filename: str, row_data: list):
        """
        Appends a row (list) to the specified CSV file.
        """
        with open(filename, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row_data)

    def _is_domain_reachable(self, domain: str) -> bool:
        """
        Uses socket to determine if a domain has a valid A record (i.e., is reachable).
        Returns True if reachable, otherwise False.
        """
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

    def _check_website(self, domain: str) -> bool:
        """
        Attempts HTTP/HTTPS requests to see if the website is alive (2xx/3xx).
        Returns True if the site is considered alive.
        """
        self._log_to_text(self.domain_text, f"Checking site => {domain}")
        for scheme in ["http://", "https://"]:
            try:
                resp = requests.get(f"{scheme}{domain}", timeout=5, allow_redirects=True)
                if 200 <= resp.status_code < 400:
                    self._log_to_text(self.domain_text, f"Site found => {scheme}{domain}")
                    return True
            except:
                continue
        return False

    def _scrape_website(self, domain: str) -> set:
        """
        Scrapes the homepage and internal links for valid email addresses.
        Stops scanning the domain immediately after discovering at least one email.
        """
        visited_urls = set()
        base_urls = [f"http://{domain}", f"https://{domain}"]

        for base_url in base_urls:
            try:
                self._log_to_text(self.visited_page_text, f"Visiting homepage: {base_url}")
                response = requests.get(base_url, timeout=5, allow_redirects=True)

                if 200 <= response.status_code < 400:
                    emails_found = self._find_emails_in_html(response.text)
                    if emails_found:
                        self._log_to_text(self.discovered_email_text, f"Emails found: {emails_found}")
                        return emails_found  # Found email, stop further crawling immediately.

                    # No email found on homepage, continue to internal links
                    soup = BeautifulSoup(response.text, "html.parser")
                    links = soup.find_all("a", href=True)

                    for link in links:
                        href = link["href"].strip()

                        # Skip external links or files
                        if not href.startswith("/"):
                            continue
                        if self._is_unwanted_file(href):
                            continue

                        full_url = base_url + href
                        if full_url in visited_urls:
                            continue

                        visited_urls.add(full_url)

                        # Visit internal link
                        self._log_to_text(self.visited_page_text, f"Visiting internal link: {full_url}")
                        internal_resp = requests.get(full_url, timeout=5, allow_redirects=True)

                        if 200 <= internal_resp.status_code < 400:
                            emails_found = self._find_emails_in_html(internal_resp.text)
                            if emails_found:
                                self._log_to_text(self.discovered_email_text, f"Emails found: {emails_found}")
                                return emails_found  # Found email, stop further crawling immediately.

            except requests.RequestException as e:
                self._log_to_text(self.visited_page_text, f"Request error ({base_url}): {e}")
                continue  # Continue to next base URL (http/https)

        # No emails found after scanning homepage and internal links
        self._log_to_text(self.discovered_email_text, f"No email found: {domain}")
        return set()

    def _is_unwanted_file(self, url: str) -> bool:
        """
        Checks if the URL points to unwanted file types.
        Returns True if unwanted, else False.
        """
        unwanted_extensions = (
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".bmp", ".ico",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".zip", ".rar", ".tar", ".gz", ".7z",
            ".mp3", ".mp4", ".avi", ".mkv", ".mov",
            ".css", ".js", ".json", ".xml"
        )
        return url.lower().endswith(unwanted_extensions)

    def _find_emails_in_html(self, html_content: str) -> set:
        """
        Extracts email addresses from HTML content and ensures their validity.
        """
        email_pattern = r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"
        potential_emails = re.findall(email_pattern, html_content)

        # Only valid email formats pass through
        valid_emails = set(filter(is_valid_email_format, potential_emails))
        return valid_emails

# -----------------------------------------------------------------------------
# Run the Application
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app = EmailCheckerApp()
    app.mainloop()
