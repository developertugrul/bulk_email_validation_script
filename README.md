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
- 🔐 Environment-based configuration

## Requirements

- Python 3.8+
- Required packages are listed in requirements.txt

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/developertugrul/bulk_email_validation_script.git
   cd bulk_email_validation_script
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env file with your settings
   nano .env
   ```

## Environment Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Timeout Settings
CHECK_TIMEOUT=5
THREAD_COUNT=10

# SMTP Settings
SMTP_SERVER=your.smtp.server
SMTP_PORT=465
SMTP_USER=your.email@domain.com
SMTP_PASSWORD=your-password
```

All settings are required. The application will validate these settings on startup.

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

## Configuration Options

The following settings can be configured in your `.env` file:

- `CHECK_TIMEOUT`: DNS & SMTP timeout in seconds (default: 5)
- `THREAD_COUNT`: Number of parallel threads (default: 10)
- `SMTP_SERVER`: SMTP server address for email validation
- `SMTP_PORT`: SMTP server port (default: 465)
- `SMTP_USER`: SMTP authentication username
- `SMTP_PASSWORD`: SMTP authentication password

## Output Files

1. `temizlenmis_eposta_listesi.csv`:
   - Email address
   - Domain
   - Website title

2. `sahte_eposta_listesi.csv`:
   - Invalid email addresses

## Security Notes

- Never commit your `.env` file to version control
- The `.env.example` file is provided as a template
- Sensitive information should only be stored in your local `.env` file

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

## Development Notes

- The `.gitignore` file is configured to exclude sensitive files
- Make sure to update `.env.example` if you add new configuration options
- Run `validate_config()` before accessing any environment variables
