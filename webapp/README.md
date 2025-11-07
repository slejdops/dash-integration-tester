# LTPA Token Tester - Web Application

Interactive web application for testing LTPA cookie authentication with DASH/WebSphere.

## Features

- **Login to DASH**: Acquire LTPA tokens via web-based authentication
- **Manual Token Input**: Test with pre-acquired LTPA tokens
- **Token Inspection**: View token details and metadata
- **Role Fetch Testing**: Simulate TCE integration by calling DASH endpoints
- **Mini Stress Testing**: Run small-scale load tests from the browser
- **Real-time Results**: View request/response details instantly

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Navigate to project root
cd dash-integration-tester

# 2. Create environment file
cp webapp/.env.example .env

# 3. Edit configuration
vi .env
# Set DASH_URL to your DASH server

# 4. Start the web app
docker-compose up -d

# 5. Access the app
open http://localhost:5000
```

### Using Docker (Manual)

```bash
# Build the image
docker build -t ltpa-tester webapp/

# Run the container
docker run -d \
  -p 5000:5000 \
  -e DASH_URL=https://dash.example.com:9443 \
  -e VERIFY_SSL=false \
  --name ltpa-tester \
  ltpa-tester

# Access the app
open http://localhost:5000
```

### Running Locally (Without Docker)

```bash
# 1. Install dependencies
cd webapp
pip install -r requirements.txt

# 2. Set environment variables
export DASH_URL=https://dash.example.com:9443
export VERIFY_SSL=false
export SECRET_KEY=your-secret-key

# 3. Run the app
python app.py

# 4. Access the app
open http://localhost:5000
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DASH_URL` | DASH server base URL | `https://localhost:9443` | Yes |
| `DASH_ROLE_ENDPOINT` | Role-fetching endpoint path | `/dash/api/roles` | No |
| `VERIFY_SSL` | Verify SSL certificates | `false` | No |
| `SECRET_KEY` | Flask session secret | `ltpa-test-secret-key-change-in-production` | Yes |
| `DEBUG` | Enable Flask debug mode | `false` | No |
| `PORT` | Port to run on | `5000` | No |

### Example `.env` File

```bash
DASH_URL=https://dash.example.com:9443
DASH_ROLE_ENDPOINT=/dash/api/roles
VERIFY_SSL=false
SECRET_KEY=my-super-secret-random-key
DEBUG=false
```

## Usage Guide

### 1. Acquiring an LTPA Token

#### Method A: Login via Web App

1. Navigate to http://localhost:5000
2. Click "Login"
3. Enter DASH username and password
4. Click "Login & Acquire Token"
5. Token is automatically stored in session and cookie

#### Method B: Manual Token Input

1. Log into DASH via browser
2. Open DevTools (F12) → Application → Cookies
3. Find `LTPAToken2` cookie
4. Copy the value
5. In web app, click "Manual Token"
6. Paste token and submit

### 2. Testing Role Fetch

1. Go to "Test Role Fetch" page
2. Enter DASH endpoint path (e.g., `/dash/api/roles`)
3. Click "Send Request"
4. View response:
   - Status code (200 = success, 401 = auth failed, 403 = forbidden)
   - Response time
   - Headers
   - JSON response body

### 3. Running Stress Test

1. Go to "Stress Test" page
2. Enter endpoint and number of requests (max 100)
3. Click "Run Stress Test"
4. View results:
   - Success/failure rate
   - Response time statistics (avg, min, max, P95)
   - Detailed failure information

### 4. Viewing Token Information

1. Go to "Token Info" page
2. View:
   - Token length and structure
   - Acquisition time
   - Full token value (for debugging)

## API Endpoints

### Health Check

```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-07T10:30:00",
  "dash_url": "https://dash.example.com:9443",
  "verify_ssl": false
}
```

### Token Status API

```bash
curl http://localhost:5000/api/token-status
```

**Response:**
```json
{
  "has_token": true,
  "username": "admin",
  "acquired_at": "2025-11-07T10:25:00"
}
```

## Docker Management

### View Logs

```bash
# All logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100
```

### Stop Application

```bash
docker-compose down
```

### Rebuild After Changes

```bash
docker-compose down
docker-compose build
docker-compose up -d
```

### Container Shell Access

```bash
docker exec -it ltpa-token-tester /bin/bash
```

## Troubleshooting

### Login Fails - No LTPA Token

**Problem:** Login succeeds but no LTPAToken2 cookie received

**Solutions:**
1. Check DASH_URL is correct and accessible
2. Verify DASH console login endpoint: `/ibm/console/login.do`
3. Check if DASH uses different login URL
4. Enable DEBUG=true and check logs

### SSL Certificate Errors

**Problem:** `SSL: CERTIFICATE_VERIFY_FAILED`

**Solutions:**
1. Set `VERIFY_SSL=false` (testing only!)
2. For production: Import DASH certificate into container trust store
3. Or use valid, CA-signed certificates on DASH

### Connection Refused

**Problem:** Cannot connect to DASH

**Solutions:**
1. Check DASH is running: `curl -k https://dash.example.com:9443`
2. Verify firewall rules allow container → DASH communication
3. If DASH is on localhost: Use host IP, not `localhost`
4. Docker network: Add `--network=host` if needed

### Port Already in Use

**Problem:** `Error starting userland proxy: listen tcp 0.0.0.0:5000: bind: address already in use`

**Solutions:**
```bash
# Use different port
docker-compose up -d -e PORT=5001
# Or edit docker-compose.yml: ports: - "5001:5000"

# Or stop conflicting service
lsof -ti:5000 | xargs kill -9
```

## Security Considerations

### Production Deployment

⚠️ **This tool is for testing/diagnostics only. Do NOT use in production without hardening.**

**Security Checklist:**

- [ ] Change `SECRET_KEY` to a random value
- [ ] Set `DEBUG=false`
- [ ] Enable `VERIFY_SSL=true` with valid certificates
- [ ] Use HTTPS (put behind reverse proxy like nginx)
- [ ] Implement authentication for web app access
- [ ] Restrict network access (firewall rules)
- [ ] Use read-only file system in container
- [ ] Scan container image for vulnerabilities
- [ ] Limit container resources (CPU, memory)
- [ ] Enable logging and monitoring

### Network Security

```yaml
# docker-compose.yml - Restrict to localhost only
ports:
  - "127.0.0.1:5000:5000"  # Only accessible from host
```

### HTTPS Configuration

```bash
# Use nginx as reverse proxy with SSL
# See: https://docs.nginx.com/nginx/admin-guide/security-controls/terminating-ssl-http/
```

## Integration with Main Tool

This web app complements the command-line diagnostics tool:

```bash
# 1. Use web app to acquire LTPA token
#    http://localhost:5000 → Login → Copy token

# 2. Use token in command-line stress tester
python3 modules/stress_tester/ltpa_simulator.py \
  --url https://dash.example.com:9443/dash/api/roles \
  --token "AAECAzQ3ODA..." \
  --mode steady --duration 300 --rate 20

# 3. Use web app to quickly test after configuration changes
#    Make SSO config change → Test via web UI immediately
```

## Development

### Project Structure

```
webapp/
├── app.py                 # Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Container image
├── .env.example          # Configuration template
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Dashboard
│   ├── login.html        # Login page
│   ├── manual_token.html # Manual token input
│   ├── token_info.html   # Token details
│   ├── test_role_fetch.html # Role fetch tester
│   └── stress_test.html  # Stress tester
└── static/               # Static assets (empty for now)
```

### Adding New Features

1. **New Route:**
   ```python
   @app.route('/my-feature')
   def my_feature():
       return render_template('my_feature.html')
   ```

2. **New Template:**
   ```html
   {% extends "base.html" %}
   {% block content %}
   <!-- Your content here -->
   {% endblock %}
   ```

3. **Rebuild:**
   ```bash
   docker-compose down
   docker-compose build
   docker-compose up -d
   ```

## License

Internal IBM tool - Confidential

## Support

For issues:
1. Check logs: `docker-compose logs -f`
2. Verify configuration: `docker exec ltpa-token-tester env`
3. Test connectivity: `docker exec ltpa-token-tester curl -k $DASH_URL`
4. See main project README for additional troubleshooting
