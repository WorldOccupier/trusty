# GitHub App

## Overview

The Trusty GitHub App automatically scans PRs for AI-generated code issues
and posts results as PR comments. Unlike the GitHub Action, the App:
- Installs automatically on all repos in an organization
- Doesn't require per-repo configuration
- Posts inline comments on PR diffs
- Tracks findings across PRs

## Setup

1. Go to GitHub Settings → Developer Settings → GitHub Apps
2. Create a new GitHub App with:
   - Name: `trusty-bot`
   - Webhook URL: `https://your-trusty-server.com/webhook`
   - Permissions:
     - Pull requests: Read & Write
     - Contents: Read
     - Checks: Write
   - Subscribe to events: Pull request, Push
3. Install the app on your organization
4. Deploy the Trusty server with `trusty web --port 8080`
5. Set `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY` env vars

## Architecture

```
GitHub PR created → Webhook → Trusty Server → Scan → Comment on PR
```

## Self-Hosted Deployment

```bash
trusty web --port 8080
```

Requires:
- GitHub App ID + Private Key
- `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` env vars
- Publicly accessible webhook endpoint (ngrok for dev)
