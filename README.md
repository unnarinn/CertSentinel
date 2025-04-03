# CertSentinel

**CertSentinel** is a real-time monitoring tool that ingests data from Certificate Transparency (CT) logs, parses certificate metadata, and indexes it into an Elasticsearch cluster for security observability and analysis.

---

## 🔍 Features

- Fetches and parses entries from multiple CT logs concurrently
- Extracts rich certificate metadata (domains, issuer, key usage, expiration, etc.)
- Supports X.509 and Precert entries
- Avoids duplicate processing via SHA-256 fingerprint caching
- Stores parsed certificate documents into Elasticsearch using bulk indexing
- Environment-variable-based configuration for easy deployment

---

## ⚙️ Configuration

The following environment variables can be set (with defaults):

```env
ELASTICSEARCH_HOSTS=http://localhost:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
