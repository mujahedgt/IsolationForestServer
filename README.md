# IsolationForestServer

Machine Learning-based Anomaly Detection Service for RESTful API Request Analysis

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3.2-orange.svg)](https://scikit-learn.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0+-blue.svg)](https://www.mysql.com/)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [Model Training](#model-training)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

IsolationForestServer is a Python-based machine learning service that uses the Isolation Forest algorithm to detect anomalous API requests in real-time. It analyzes incoming requests and classifies them as either legitimate or suspicious based on multiple features including IP patterns, payload structure, headers, and request frequency.

This service is part of a larger security architecture that intelligently routes traffic between a honeypot (for suspicious requests) and production systems (for legitimate requests).

### Key Use Cases

- **API Security**: Detect and filter malicious API requests
- **Traffic Analysis**: Identify unusual patterns in API traffic
- **Threat Intelligence**: Learn from attack patterns over time
- **Adaptive Defense**: Continuously improve detection through retraining

---

## ✨ Features

### Core Functionality

- 🤖 **ML-Powered Detection**: Isolation Forest algorithm for anomaly detection
- 📊 **Multi-Feature Analysis**: IP reputation, payload complexity, headers, endpoints, frequency
- 🔄 **Continuous Learning**: Manual retraining with corrected labels
- 📈 **Confidence Scoring**: Returns confidence level (0.0-1.0) for each prediction
- 💾 **Persistent Models**: Store and version trained models in MySQL
- 📝 **Request History**: Complete audit trail of analyzed requests

### API Features

- ⚡ **Fast API**: Built on FastAPI for high performance
- 🔍 **Audit Endpoints**: View and filter analyzed requests
- 🏷️ **Label Management**: Correct misclassifications for model improvement
- 📊 **Statistics**: Comprehensive statistics and metrics
- 🔧 **Admin Controls**: Train and retrain models on-demand

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                IsolationForestServer                    │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                   │
│  │   FastAPI    │────│  ML Service  │                   │
│  │  REST API    │    │  (sklearn)   │                   │
│  └──────────────┘    └──────────────┘                   │
│         │                    │                          │
│         ▼                    ▼                          │
│  ┌──────────────────────────────────┐                   │
│  │      Feature Extractor           │                   │
│  │  (IP, Payload, Headers, etc.)    │                   │
│  └──────────────────────────────────┘                   │
│                    │                                    │
│                    ▼                                    │
│         ┌──────────────────┐                            │
│         │  MySQL Database  │                            │
│         │  - Models        │                            │
│         │  - Requests      │                            │
│         └──────────────────┘                            │
└─────────────────────────────────────────────────────────┘
```

### Request Flow

1. **Receive Request** → Gateway sends request features for analysis
2. **Extract Features** → Parse and compute feature scores
3. **ML Prediction** → Isolation Forest classifies request
4. **Store Results** → Save to database for audit and retraining
5. **Return Response** → Send `{isAnomaly, confidence}` back to gateway

---

## 📦 Prerequisites

### Required Software

- **Python**: 3.8 or higher
- **MySQL**: 8.0 or higher
- **pip**: Package installer for Python

### System Requirements

- **RAM**: Minimum 2GB (4GB recommended)
- **Storage**: 500MB for application + database
- **OS**: Linux, macOS, or Windows

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/IsolationForestServer.git
cd IsolationForestServer
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```txt
fastapi==0.104.1
uvicorn[standard]==0.24.0
scikit-learn==1.3.2
mysql-connector-python==8.2.0
pydantic==2.5.0
numpy==1.26.2
pandas==2.1.3
python-multipart==0.0.6
python-dateutil==2.8.2
```

### 4. Setup MySQL Database

```bash
# Login to MySQL
mysql -u root -p

# Create database
CREATE DATABASE isolation_forest_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# Exit MySQL
exit
```

### 5. Create Database Tables

Run the SQL scripts from the documentation to create `models` and `analyzed_requests` tables.

```sql
-- See Part 1 documentation for complete schema
CREATE TABLE models ( ... );
CREATE TABLE analyzed_requests ( ... );
```

### 6. Configure Environment

Create `.env` file in project root:

```env
# MySQL Configuration
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=yourpassword
MYSQL_DATABASE=isolation_forest_db

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=True

# Model Configuration
DEFAULT_CONTAMINATION=0.1
DEFAULT_N_ESTIMATORS=100
MIN_TRAINING_SAMPLES=100
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MYSQL_HOST` | MySQL server hostname | `localhost` |
| `MYSQL_PORT` | MySQL server port | `3306` |
| `MYSQL_USER` | Database username | `root` |
| `MYSQL_PASSWORD` | Database password | - |
| `MYSQL_DATABASE` | Database name | `isolation_forest_db` |
| `API_HOST` | API server host | `0.0.0.0` |
| `API_PORT` | API server port | `8000` |
| `DEFAULT_CONTAMINATION` | Expected anomaly rate | `0.1` (10%) |
| `DEFAULT_N_ESTIMATORS` | Number of trees in forest | `100` |
| `MIN_TRAINING_SAMPLES` | Minimum samples for training | `100` |

### Model Parameters

**Contamination**: Expected proportion of anomalies in data (0.0-0.5)
- `0.05` = 5% of traffic expected to be anomalous (conservative)
- `0.1` = 10% of traffic expected to be anomalous (balanced)
- `0.2` = 20% of traffic expected to be anomalous (aggressive)

**N_Estimators**: Number of isolation trees
- Higher = More accurate but slower
- Recommended: 100-200

---

## 🔌 API Endpoints

### Analysis

#### `POST /analyze`
Analyze a request and return anomaly classification.

**Request:**
```json
{
  "request_id": "req_abc123",
  "ip_address": "192.168.1.100",
  "endpoint": "/api/users/profile",
  "http_method": "POST",
  "headers": {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json"
  },
  "payload": {
    "username": "john_doe"
  },
  "timestamp": "2024-12-02T10:00:00Z"
}
```

**Response:**
```json
{
  "request_id": "req_abc123",
  "isAnomaly": false,
  "confidence": 0.78,
  "model_version": "v1.0",
  "analyzed_at": "2024-12-02T10:00:01Z"
}
```

### Model Management

#### `POST /train`
Train a new model from labeled data.

```json
{
  "model_version": "v1.0",
  "use_corrected_labels": true,
  "training_params": {
    "contamination": 0.1,
    "n_estimators": 100
  }
}
```

#### `POST /retrain`
Retrain model using corrected labels.

```json
{
  "model_version": "v1.1"
}
```

### Audit & Statistics

#### `GET /audit`
View analyzed requests with filtering.

**Query Parameters:**
- `page`: Page number (default: 1)
- `page_size`: Items per page (default: 20)
- `ip_address`: Filter by IP
- `is_anomaly`: Filter by classification
- `min_confidence`, `max_confidence`: Filter by confidence range

#### `GET /statistics`
Get model performance and system statistics.

#### `PUT /label/{request_id}`
Change label for an analyzed request.

```json
{
  "user_label": false,
  "changed_by": "admin_user"
}
```

---

## 💡 Usage Examples

### 1. Start the Server

```bash
# Development mode (with auto-reload)
python -m app.main

# Or using uvicorn directly
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 2. Train Initial Model

**First, populate with training data** (from honeypot logs or manual labels):

```python
import requests

response = requests.post('http://localhost:8000/train', json={
    "model_version": "v1.0",
    "use_corrected_labels": False,
    "training_params": {
        "contamination": 0.1,
        "n_estimators": 100
    }
})

print(response.json())
```

### 3. Analyze a Request

```python
import requests

response = requests.post('http://localhost:8000/analyze', json={
    "request_id": "test_001",
    "ip_address": "203.0.113.50",
    "endpoint": "/api/admin/delete",
    "http_method": "DELETE",
    "headers": {
        "User-Agent": "BadBot/1.0"
    },
    "payload": {
        "table": "users"
    },
    "timestamp": "2024-12-02T10:00:00Z"
})

result = response.json()
print(f"Is Anomaly: {result['isAnomaly']}")
print(f"Confidence: {result['confidence']}")
```

### 4. View Statistics

```bash
curl http://localhost:8000/statistics
```

### 5. Correct a Misclassification

```python
# Change label for request ID 42
response = requests.put('http://localhost:8000/label/42', json={
    "user_label": True,  # Mark as anomaly
    "changed_by": "admin"
})
```

### 6. Retrain with Corrections

```python
response = requests.post('http://localhost:8000/retrain', json={
    "model_version": "v1.1"
})

print(f"Retrained with {response.json()['corrected_labels_used']} corrections")
```

---

## 🎓 Model Training

### Training Workflow

1. **Collect Initial Data**
   - Minimum 100 samples required
   - Mix of normal and anomalous requests
   - Manual labeling or import from honeypot logs

2. **Train First Model**
   ```bash
   POST /train with version "v1.0"
   ```

3. **Monitor Performance**
   - Check statistics endpoint
   - Review false positives/negatives in audit

4. **Correct Labels**
   - Use PUT /label/{id} to fix misclassifications
   - Build dataset of corrections

5. **Retrain Model**
   ```bash
   POST /retrain with version "v1.1"
   ```

6. **Repeat** cycle for continuous improvement

### Best Practices

✅ **Start Conservative**: Use lower contamination (0.05) initially
✅ **Gradual Training**: Accumulate 50-100 corrections before retraining
✅ **Version Semantically**: Use v{major}.{minor} format
✅ **Monitor Metrics**: Track accuracy improvement over versions
✅ **Backup Models**: Keep previous versions for rollback

---

## 🛠️ Development

### Project Structure

```
IsolationForestServer/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI application
│   ├── config.py                  # Configuration
│   ├── database.py                # Database connection
│   ├── models/
│   │   ├── db_models.py           # Database models
│   │   └── request_models.py      # Pydantic models
│   ├── services/
│   │   ├── feature_extractor.py   # Feature engineering
│   │   ├── ml_service.py          # ML model service
│   │   └── training_service.py    # Training logic
│   └── routes/
│       ├── analyze.py             # Analysis endpoint
│       ├── training.py            # Training endpoints
│       ├── audit.py               # Audit endpoints
│       ├── labeling.py            # Label management
│       └── statistics.py          # Statistics endpoint
├── requirements.txt
├── .env
└── README.md
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest

# With coverage
pytest --cov=app tests/
```

### Code Style

```bash
# Install formatters
pip install black flake8

# Format code
black app/

# Check style
flake8 app/
```

---

## 🐛 Troubleshooting

### Common Issues

#### Issue: "No module named 'app'"
**Solution:**
```bash
# Run from project root
python -m app.main
# Or
PYTHONPATH=. uvicorn app.main:app
```

#### Issue: "No active model found"
**Solution:**
Train a model first:
```bash
curl -X POST http://localhost:8000/train \
  -H "Content-Type: application/json" \
  -d '{"model_version":"v1.0","use_corrected_labels":false}'
```

#### Issue: "Insufficient training data"
**Solution:**
Ensure at least 100 records in `analyzed_requests` table with labels.

#### Issue: MySQL connection failed
**Solution:**
```bash
# Check MySQL is running
systemctl status mysql  # Linux
# Or check Services on Windows

# Verify credentials in .env
# Test connection
mysql -u root -p -h localhost
```

#### Issue: "Model prediction errors"
**Solution:**
Check model is compatible with current feature extraction:
- Same features used in training and prediction
- Model not corrupted (check pickle integrity)
- Sufficient memory for model

### Debug Mode

Enable detailed logging:

```python
# In app/main.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Issues

If analysis is slow:
- Reduce `n_estimators` (100 → 50)
- Add database indexes
- Use connection pooling
- Consider model caching

---

## 📊 Monitoring

### Key Metrics to Monitor

- **Request Throughput**: Requests analyzed per second
- **Anomaly Rate**: Percentage classified as anomalies
- **Confidence Distribution**: Average confidence scores
- **False Positive Rate**: Corrections from anomaly → legitimate
- **False Negative Rate**: Corrections from legitimate → anomaly
- **Model Age**: Days since last training
- **Database Size**: Growth of analyzed_requests table

### Health Check

```bash
curl http://localhost:8000/statistics
```

Monitor:
- `total_requests_analyzed`: Should be growing
- `average_confidence`: Should be >0.7 for good model
- `label_corrections.total_corrections`: Track improvement needs

---

## 🔒 Security Considerations

⚠️ **IMPORTANT**: Current implementation has no authentication. In production:

1. Add API key authentication (see conflicts document)
2. Use HTTPS/TLS for all connections
3. Implement rate limiting
4. Secure database credentials
5. Regular security audits
6. Log all administrative actions

---

## 📚 Documentation

Full documentation available in project docs:
- **Part 1**: Architecture & Setup
- **Part 2**: Implementation & Code
- **Part 3**: Testing & Troubleshooting

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🆘 Support

- **Documentation**: See full docs in `/docs` folder
- **Issues**: Open an issue on GitHub
- **Email**: support@yourdomain.com

---

## 🙏 Acknowledgments

- **scikit-learn**: For the Isolation Forest implementation
- **FastAPI**: For the excellent web framework
- **Community**: All contributors and users

---

## 📈 Roadmap

- [ ] Add authentication layer
- [ ] Support for multiple ML algorithms
- [ ] Real-time model retraining
- [ ] Advanced feature engineering
- [ ] Model explainability (SHAP values)
- [ ] Automated hyperparameter tuning
- [ ] Integration with threat intelligence feeds

---

**Version**: 1.0.0  
**Last Updated**: December 2024  
**Status**: Production Ready (with auth fixes)