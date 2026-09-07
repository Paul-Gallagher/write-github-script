"""Minimal, from-scratch equivalent of what actions/create-github-app-token does.

Written for Appendix F of Github EMU.md - shown in Python because GitHub's own
action is TypeScript, and this exists purely to make the mechanism legible
without wading through a modern JS build. There's no hidden magic: it's
exactly two HTTP calls.

    1. Build a JWT that proves "I am App <app_id>" - signed with the App's own
       private key (RS256; GitHub accepts no other algorithm here).
    2. Exchange that JWT for a short-lived installation access token, scoped
       to whatever repos/permissions the App was installed with. This is the
       token that actually authenticates API calls or a `git push` - it
       behaves exactly like a PAT from that point on, and expires in an hour.

Run against your own practice App (see Appendix F) to see it end-to-end:
    pip install pyjwt cryptography requests
    python github_app_token.py
"""

from __future__ import annotations

import time

import jwt  # PyJWT
import requests

APP_ID = '4815518'  # from the App's settings page, e.g. github.com/settings/apps/<name>
PRIVATE_KEY_PATH = 'app-private-key.pem'  # the .pem downloaded when you generated the key
INSTALLATION_ID = 'REPLACE_ME'  # from the URL after installing the App, or via list_installations() below


def build_signed_jwt(app_id: str, private_key_path: str) -> str:
    """Step 1: prove we ARE the App, not acting on its behalf yet.

    Valid ~10 minutes max (GitHub's own cap) - this JWT is never used directly
    against ordinary GitHub API endpoints, only to fetch an installation token.
    """
    with open(private_key_path, 'rb') as f:
        private_key = f.read()

    now = int(time.time())
    payload = {
        'iat': now - 60,  # issued-at, deliberately backdated 60s - GitHub is strict about clock drift
        'exp': now + (9 * 60),  # 9 minutes; leaves headroom under GitHub's 10-minute cap
        'iss': app_id,  # the App's identity - this is what GitHub actually checks
    }
    return jwt.encode(payload, private_key, algorithm='RS256')


def list_installations(signed_jwt: str) -> list[dict]:
    """Optional: find INSTALLATION_ID if you don't already have it from the install URL."""
    resp = requests.get(
        'https://api.github.com/app/installations',
        headers={
            'Authorization': f'Bearer {signed_jwt}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_installation_token(signed_jwt: str, installation_id: str) -> dict:
    """Step 2: exchange the App-identity JWT for a real, usable, installation-scoped token."""
    resp = requests.post(
        f'https://api.github.com/app/installations/{installation_id}/access_tokens',
        headers={
            'Authorization': f'Bearer {signed_jwt}',  # Bearer + the JWT - not "token", this isn't a PAT
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()  # {'token': 'ghs_...', 'expires_at': '...', 'permissions': {...}, 'repositories': [...]}


if __name__ == '__main__':
    signed = build_signed_jwt(APP_ID, PRIVATE_KEY_PATH)

    if INSTALLATION_ID == 'REPLACE_ME':
        print('No INSTALLATION_ID set - listing installations visible to this App:')
        for installation in list_installations(signed):
            print(f"  id={installation['id']}  account={installation['account']['login']}")
        raise SystemExit('Set INSTALLATION_ID to one of the above and re-run.')

    result = get_installation_token(signed, INSTALLATION_ID)
    print(f"Installation token: {result['token']}")
    print(f"Expires: {result['expires_at']}")
    print(f"Granted permissions: {result['permissions']}")

    # From here it behaves exactly like a PAT, within its granted scope:
    #   git clone https://x-access-token:<token>@github.com/owner/repo.git
    #   curl -H "Authorization: token <token>" https://api.github.com/repos/owner/repo
