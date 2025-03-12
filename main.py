# Import required libraries
import csv                  # For CSV file operations
import re                   # For regular expression operations
import os                   # For operating system dependent functionality
import socket              # For low-level networking interface
import smtplib             # For SMTP protocol client
import dns.resolver        # For DNS operations
import threading           # For multi-threading support
import queue               # For thread-safe queue implementation
import requests            # For HTTP requests
from bs4 import BeautifulSoup  # For HTML parsing
import tkinter as tk       # For GUI creation
from tkinter import filedialog, ttk  # For file dialogs and themed widgets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration settings
CONFIG = {
    "CHECK_TIMEOUT": int(os.getenv("CHECK_TIMEOUT", 5)),    # Default to 5 if not set
    "THREAD_COUNT": int(os.getenv("THREAD_COUNT", 10)),    # Default to 10 if not set
    "SMTP_SETTINGS": {
        "SERVER": os.getenv("SMTP_SERVER"),
        "PORT": int(os.getenv("SMTP_PORT", 465)),
        "USER": os.getenv("SMTP_USER"),
        "PASSWORD": os.getenv("SMTP_PASSWORD")
    }
}

# Validate required environment variables
def validate_config():
    """Validates that all required environment variables are set"""
    required_vars = [
        "SMTP_SERVER",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASSWORD"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing_vars)}\n"
            "Please check your .env file."
        )

# Call validation at startup
validate_config()

# DNS & SMTP Caches
checked_domains = {}       # Cache dictionary to store previously checked domains
checked_emails = set()     # Set to store previously checked email addresses

# Thread-safe Queue
email_queue = queue.Queue()  # Queue for managing email processing across threads

# Processed Emails
processed_emails = set()   # Set to store all processed emails (both valid and invalid)

# ---------------------------------------------------------------------------------
# DESKTOP APPLICATION (Tkinter)
# ---------------------------------------------------------------------------------

class EmailCheckerApp(tk.Tk):
    """
    Main application class for the Email Checker GUI
    Inherits from tkinter.Tk for window management
    """
    def __init__(self):
        """
        Initialize the application window and create the GUI elements
        Sets up a 2x2 grid layout with four main panels
        """
        super().__init__()
        self.title("Email Validation Application")
        self.geometry("1200x700")

        # Design main layout as 2x2 grid
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

        # Bottom button section
        bottom_frame = ttk.Frame(self, padding=2)
        bottom_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.start_button = ttk.Button(bottom_frame, text="Select CSV and Start", command=self.select_file)
        self.start_button.pack(anchor="center")

    def select_file(self):
        """Prompts user to select a CSV file and initiates processing."""
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if file_path:
            # Update input file and start processing threads
            self.run_checker_in_thread(file_path)

    def run_checker_in_thread(self, file_path: str):
        """Starts a new thread for processing the given file."""
        t = threading.Thread(target=self.process_csv, args=(file_path,))
        t.start()

    def process_csv(self, file_path: str):
        """
        Main email validation function (runs in separate thread)
        Processes CSV file and validates each email address
        """
        # 1) Load previously processed emails from clean/fake files into processed_emails
        load_processed_emails()

        # 2) Read the file
        with open(file_path, "r", encoding="utf-8") as f_in:
            lines = f_in.readlines()
        total_rows = len(lines) - 1
        main_log(f"📊 Total Emails: {total_rows}")

        # 3) Add data to queue
        email_queue.queue.clear()  # Clear old data
        with open(file_path, "r", encoding="utf-8") as f_in:
            reader = csv.DictReader(f_in)
            for row in reader:
                email = row["email"]
                # Skip if email was already processed (clean or fake)
                if email in processed_emails:
                    main_log(f"⏭ Already Processed: {email}")
                    continue
                email_queue.put(email)

        # 4) Start threads
        threads = []
        for _ in range(CONFIG["THREAD_COUNT"]):
            t = threading.Thread(target=self.process_email_queue)
            t.start()
            threads.append(t)

        email_queue.join()

        # Queue cleanup
        for _ in range(CONFIG["THREAD_COUNT"]):
            email_queue.put(None)
        for t in threads:
            t.join()

        main_log("🚀 All operations completed!")

    def process_email_queue(self):
        """Kuyruktaki e-postaları çekip doğrulama yapan fonksiyon."""
        while True:
            email = email_queue.get()
            if email is None:
                break

            if validate_email(email):
                domain = email.split("@")[-1]
                title = get_website_title(domain)
                with open("temizlenmis_eposta_listesi.csv", "a", newline="", encoding="utf-8") as f_valid:
                    writer = csv.writer(f_valid)
                    writer.writerow([email, domain, title])
                valid_log(f"✔ {email} => Geçerli (Domain: {domain}, Title: {title})")
                # Bu e-postayı processed_emails'e ekleyelim
                processed_emails.add(email)
            else:
                with open("sahte_eposta_listesi.csv", "a", newline="", encoding="utf-8") as f_invalid:
                    writer = csv.writer(f_invalid)
                    writer.writerow([email])
                main_log(f"❌ {email} => Geçersiz")
                processed_emails.add(email)

            email_queue.task_done()


# ---------------------------------------------------------------------------------
# Global Fonksiyonlar (LOG'lar vb.)
# ---------------------------------------------------------------------------------

def load_processed_emails():
    """
    Daha önce kaydedilmiş temiz (valid) ve sahte (invalid) e-postaları
    'processed_emails' kümesine yükler. Böylece yeniden işlenmezler.
    """
    # Valid e-postalar
    if os.path.exists("temizlenmis_eposta_listesi.csv"):
        with open("temizlenmis_eposta_listesi.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 0:
                    processed_emails.add(row[0])  # CSV'de ilk sütun e-posta

    # Sahte e-postalar
    if os.path.exists("sahte_eposta_listesi.csv"):
        with open("sahte_eposta_listesi.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > 0:
                    processed_emails.add(row[0])


def domain_log(msg: str):
    """Domain loglarını Domain paneline yazar."""
    app.domain_text.insert(tk.END, msg + "\n")
    app.domain_text.see(tk.END)

def email_log(msg: str):
    """E-posta loglarını E-posta paneline yazar."""
    app.email_text.insert(tk.END, msg + "\n")
    app.email_text.see(tk.END)

def valid_log(msg: str):
    """Geçerli e-postaları Valid paneline yazar."""
    app.valid_text.insert(tk.END, msg + "\n")
    app.valid_text.see(tk.END)

def main_log(msg: str):
    """Genel logları (hata, uyarı vb.) Log paneline yazar."""
    app.log_text.insert(tk.END, msg + "\n")
    app.log_text.see(tk.END)


# ---------------------------------------------------------------------------------
# DNS ve SMTP fonksiyonları (validate_email, get_mx_or_a_record, get_website_title)
# ---------------------------------------------------------------------------------

def get_mx_or_a_record(domain: str) -> str | None:
    if domain in checked_domains:
        return checked_domains[domain]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver.lifetime = CONFIG["CHECK_TIMEOUT"]

    try:
        mx_records = resolver.resolve(domain, 'MX')
        mx_server = str(mx_records[0].exchange).rstrip('.')
        checked_domains[domain] = mx_server
        domain_log(f"✅ MX: {domain} -> {mx_server}")
        return mx_server
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        domain_log(f"⚠️ MX Yok: {domain}")
    except dns.resolver.NoNameservers:
        domain_log(f"❌ DNS Yanıt Vermedi: {domain}")
        checked_domains[domain] = None
        return None

    # A kaydı
    try:
        a_record = socket.gethostbyname(domain)
        checked_domains[domain] = a_record
        domain_log(f"✅ A: {domain} -> {a_record}")
        return a_record
    except (socket.gaierror, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        domain_log(f"❌ MX/A Yok: {domain}")
        checked_domains[domain] = None
        return None

def get_website_title(domain: str) -> str:
    email_log(f"🌐 Title Alınıyor: {domain}")
    for scheme in ['http://', 'https://']:
        try:
            resp = requests.get(f"{scheme}{domain}", timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                title = soup.title.string.strip() if soup.title else "No Title"
                email_log(f"✅ Title: {domain} -> {title}")
                return title
        except:
            continue
    email_log(f"❌ Title Yok: {domain}")
    return "Title Unavailable"

def is_valid_email_format(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$"
    return bool(re.match(pattern, email))

def validate_email(email: str) -> bool:
    email_log(f"📧 Kontrol: {email}")

    if not is_valid_email_format(email):
        email_log(f"❌ Format Hatalı: {email}")
        return False

    domain = email.split('@')[-1]
    mail_server = get_mx_or_a_record(domain)
    if not mail_server:
        email_log(f"❌ Domain Hatalı: {email}")
        return False

    smtp_ports = [25, 587, 465]
    for port in smtp_ports:
        try:
            email_log(f"🔍 Deneme: {mail_server}:{port} => {email}")
            if port == 465:
                with smtplib.SMTP_SSL(mail_server, port, timeout=CONFIG["CHECK_TIMEOUT"]) as server:
                    server.login(CONFIG["SMTP_SETTINGS"]["USER"], CONFIG["SMTP_SETTINGS"]["PASSWORD"])
                    server.ehlo()
                    server.mail(CONFIG["SMTP_SETTINGS"]["USER"])
                    code, _ = server.rcpt(email)
                    if code == 250:
                        email_log(f"✅ SMTP Onay (SSL): {email}")
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
                        email_log(f"✅ SMTP Onay (Port {port}): {email}")
                        return True
        except (smtplib.SMTPException, socket.error) as e:
            email_log(f"⚠️ Hata: {mail_server}:{port} => {email} | {e}")
            continue

    email_log(f"❌ Tümü Başarısız: {email}")
    return False


# ---------------------------------------------------------------------------------
# ANA UYGULAMA
# ---------------------------------------------------------------------------------
if __name__ == "__main__":
    app = EmailCheckerApp()
    app.mainloop()
