# AI API Tracker

A simple web app to track all your AI API keys in one place.

## Features
- Add API keys for different providers
- View all keys at a glance
- Test if keys are working
- Track which providers you have

## Providers Supported
- Anthropic (Claude)
- Groq
- xAI (Grok)
- Qwen
- OpenAI
- And more...

## Tech Stack
- Flask (Python)
- SQLite (simple database)
- Deploy on Railway

## Endpoints
- `/` - Dashboard with all keys
- `/add` - Add new API key
- `/test/<provider>` - Test if key works
- `/delete/<id>` - Remove a key
