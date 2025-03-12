# Email Validator

A robust email validation tool with a graphical user interface that performs comprehensive email address verification through multiple methods.

## Features

- 🔍 Multi-level email validation:
  - Format validation using regex
  - Domain validation through DNS lookup (MX and A records)
  - SMTP server verification
  - Website title extraction
- 🚀 Multi-threaded processing for improved performance
- 💾 Caching system for DNS and SMTP checks
- 📊 Four-panel GUI interface:
  - Domain validation panel
  - Email validation panel
  - Verified emails panel
  - Log panel
- 📁 CSV file processing
- 🔄 Duplicate check prevention

## Requirements

- Python 3.8+
- Required packages:
  ```bash
  pip install dnspython requests beautifulsoup4
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/email-validator.git
   cd email-validator
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure SMTP settings in `main.py`:
   ```python
   "SMTP_SETTINGS": {
       "SERVER": "your.smtp.server",
       "PORT": 465,
       "USER": "your.email@domain.com",
       "PASSWORD": "your-password"
   }
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Click "CSV Select and Start" to choose your CSV file
3. The application will process the emails and display results in real-time
4. Results are saved in two files:
   - `temizlenmis_eposta_listesi.csv`: Valid emails
   - `sahte_eposta_listesi.csv`: Invalid emails

## CSV Format

Your input CSV should have an "email" column:
```csv
email
example@domain.com
test@domain.com
```

## Configuration

You can modify the following settings in the CONFIG dictionary:
- `CHECK_TIMEOUT`: DNS & SMTP timeout in seconds
- `THREAD_COUNT`: Number of parallel threads
- `SMTP_SETTINGS`: SMTP server configuration

## Output Files

1. `temizlenmis_eposta_listesi.csv`:
   - Email address
   - Domain
   - Website title

2. `sahte_eposta_listesi.csv`:
   - Invalid email addresses

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Tugrul Yildirim

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request
