# AI API Tracker

A simple web app to track all your AI API keys in one place.

## Live Demo

**URL:** https://ai-api-tracker-production.up.railway.app

## Features

### Core Features
- ✅ Add API keys for different providers
- ✅ View all keys at a glance  
- ✅ Test if keys are working
- ✅ Track which providers you have
- ✅ Bot API for automated key management
- ✅ User accounts with subscription tiers
- ✅ Change password functionality

### Providers Supported
- **Anthropic** (Claude) - sk-ant-...
- **Groq** - gsk_...
- **xAI** (Grok) - xai-...
- **OpenAI** - sk-...
- **Qwen** - sk-qwen-...

## Routes

| Route | Description |
|-------|-------------|
| `/` | Landing page |
| `/signup` | Create account |
| `/login` | User login |
| `/dashboard` | View all API keys |
| `/add` | Add new key |
| `/change-password` | Change password |
| `/upgrade` | Subscription plans |
| `/api/token` | Get bot API token (POST) |
| `/api/keys` | List keys via API (GET/POST) |
| `/api/test` | Test a key via API |

## Bot API

Get an API token for your bots:
```bash
curl -X POST https://ai-api-tracker-production.up.railway.app/api/token \
  -H "Content-Type: application/json" \
  -d '{"username": "your-email", "password": "your-pass"}'
```

Then use the token:
```bash
curl https://ai-api-tracker-production.up.railway.app/api/keys \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Tech Stack

- Python (Flask)
- SQLite
- Deploy on Railway

## Subscription Tiers

| Tier | Price | Keys |
|------|-------|------|
| Free | $0 | 3 |
| Premium | $9.99/mo | Unlimited |
| Enterprise | $49/mo | Unlimited + priority support |

---

*Last updated: 2026-04-10*
