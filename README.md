# Reconnaissance API

A simple REST API for subdomain reconnaissance and validation. Performs automated subdomain enumeration using Amass with fallback methods and validates results via HTTP/HTTPS and DNS.

## Features

- Subdomain enumeration using Amass (with fallback)
- HTTP/HTTPS validation
- DNS resolution validation
- Rate limiting and CORS protection
- JSON and CSV output formats
- Concurrent validation with configurable workers
- Download results via API

## Requirements

- Node.js 14+
- Python 3.6+
- Amass (optional, fallback method available)

## Installation

1. Clone the repository
2. Install Node.js dependencies:
```bash
cd server
npm install
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. (Optional) Install Amass for better subdomain enumeration

## Usage

### Start the server
```bash
cd server
npm start
```

The server runs on `http://localhost:3000` by default.

### API Endpoints

#### POST /api/reconnaissance
Perform subdomain reconnaissance on a domain.

**Request:**
```json
{
  "domain": "example.com",
  "timeout": 300,
  "workers": 20,
  "verbose": false,
  "jsonOnly": false,
  "csvOnly": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Reconnaissance completed successfully",
  "executionTime": 45.2,
  "results": {
    "domain": "example.com",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "total_subdomains": 25,
    "active_subdomains": 12,
    "subdomains": [...],
    "active_hosts": [...],
    "errors": []
  }
}
```

#### GET /api/results/:domain
Get previous reconnaissance results.

**Query Parameters:**
- `format` - `json` or `csv` (default: json)

#### GET /api/results/:domain/download
Download results file directly.

**Query Parameters:**
- `format` - `json` or `csv` (default: json)

## Configuration

Create a `.env` file in the server directory:

```env
PORT=3000
NODE_ENV=development
ALLOWED_ORIGINS=http://localhost:3000
PYTHON_PATH=/path/to/python
```

## Rate Limiting

- 100 requests per 15 minutes per IP
- Configurable via express-rate-limit

## Output

Results are saved in `server/results/{domain}/`:
- `{domain}_reconnaissance_report.json` - Complete results
- `{domain}_subdomains.csv` - Subdomain list in CSV format
- `{domain}_amass_results.text` - Raw Amass output (if available)
