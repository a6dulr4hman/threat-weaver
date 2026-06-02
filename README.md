# ThreatWeaver

A DevSecOps vulnerability resolution engine that analyzes web application attack surfaces, generates attack graphs, and produces actionable mitigations with AI-generated remediation code.

## Overview

ThreatWeaver automates the process of identifying, analyzing, and remediating security vulnerabilities in web applications. It combines automated reconnaissance with AI-powered analysis to produce comprehensive security assessments.

## Architecture

The system operates in 6 phases:

1. **Workspace Setup** - Register a target URL and verify domain ownership via DNS TXT record
2. **Reconnaissance** - Crawl the target using Cloudflare Browser Rendering to discover the attack surface
3. **Attack Graph Generation** - Use LLM analysis to build a graph of potential vulnerability chains
4. **Mitigation Generation** - Produce remediation code for each identified vulnerability node
5. **PDF Report** - Generate a downloadable PDF report with severity, findings, and full remediation code
6. **Dashboard** - Visualize results with interactive attack graphs and mitigation details

## Setup

1. Copy `.env.example` to `.env` and fill in your credentials:
   ```bash
   cp .env.example .env
   ```

2. Install dependencies:
   ```bash
   uv pip install -r requirements.txt --system
   ```

3. Run the application:
   ```bash
   uvicorn app.main:app --reload
   ```

4. After a scan completes, download the PDF vulnerability report from the job
   page ("Download PDF Report"), or directly via
   `GET /api/jobs/{job_id}/report`. Reports are written to the directory set by
   `REPORT_DIR` (default `/tmp/threatweaver/reports`) and regenerated on demand
   if missing.

## Development

Run tests:
```bash
python3 -m pytest tests/ -v
```

## Tech Stack

- **Framework**: FastAPI (async)
- **Database**: SQLite with SQLAlchemy 2.0 async ORM
- **Templates**: Jinja2 with Tailwind CSS
- **AI**: Cloudflare Workers AI
- **Email**: Resend API
