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

Needs three env vars set either way, local run or CI (test-app-auth.yaml sets
all three; locally, e.g. in PowerShell: $env:GITHUB_APP_ID="4815518";
$env:GITHUB_APP_INSTALLATION_ID="158725951" - see the App's settings page and
the install URL respectively):
    GITHUB_APP_ID
    GITHUB_APP_INSTALLATION_ID
    GITHUB_APP_PRIVATE_KEY - raw PEM content, not a path. Only needed locally
        if PRIVATE_KEY_PATH below isn't already pointing at a real file - CI
        always sets this directly (currently from a GitHub secret, TODO: AWS
        Secrets Manager instead - see Appendix A9 of Github EMU.md) so the
        key never touches disk there.

Run: uv run src/github_app_token.py

When GITHUB_OUTPUT is set (i.e. running as an Actions step), the resulting
token is also written there as `token=...` so a later step can read it via
`steps.<id>.outputs.token`, the same shape actions/create-github-app-token
itself produces.
"""

from __future__ import annotations

import os
import time
from typing import Any

import jwt  # PyJWT
import requests

PRIVATE_KEY_PATH = "C:\\Users\\u769697\\Olympus\\write-github-script\\jackie-pants.pem"  # local-only fallback - the .pem downloaded when you generated the key


def build_signed_jwt(app_id: str, private_key: bytes | str) -> str:
    """Step 1: prove we ARE the App, not acting on its behalf yet.

    Takes the key material directly rather than a path - the caller decides
    where it comes from (a local file for a dev run, straight from a secret
    for a CI run), so this function never has to touch disk.

    Valid ~10 minutes max (GitHub's own cap) - this JWT is never used directly
    against ordinary GitHub API endpoints, only to fetch an installation token.
    """
    now = int(time.time())
    payload: dict[str, int | str] = {
        "iat": now
        - 60,  # issued-at, deliberately backdated 60s - GitHub is strict about clock drift
        "exp": now
        + (9 * 60),  # 9 minutes; leaves headroom under GitHub's 10-minute cap
        "iss": app_id,  # the App's identity - this is what GitHub actually checks
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def list_installations(signed_jwt: str) -> list[dict[str, Any]]:
    """Optional: find INSTALLATION_ID if you don't already have it from the install URL."""
    resp = requests.get(
        "https://api.github.com/app/installations",
        headers={
            "Authorization": f"Bearer {signed_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_installation_token(signed_jwt: str, installation_id: str) -> dict[str, Any]:
    """Step 2: exchange the App-identity JWT for a real, usable, installation-scoped token."""
    resp = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {signed_jwt}",  # Bearer + the JWT - not "token", this isn't a PAT
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()  # {'token': 'ghs_...', 'expires_at': '...', 'permissions': {...}, 'repositories': [...]}


def _resolve_private_key() -> bytes | str:
    """CI (GITHUB_APP_PRIVATE_KEY, raw PEM content) takes priority over the local PRIVATE_KEY_PATH file."""
    from_env = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    if from_env:
        return from_env
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return f.read()


if __name__ == "__main__":
    app_id = os.environ.get("GITHUB_APP_ID", "")
    if not app_id:  # required - no sensible default, and no fallback behaviour like installation_id has
        raise SystemExit("GITHUB_APP_ID must be set - see the App's settings page.")
    installation_id = os.environ.get("GITHUB_APP_INSTALLATION_ID", "")
    signed = build_signed_jwt(app_id, _resolve_private_key())

    if not installation_id:
        print("No GITHUB_APP_INSTALLATION_ID set - listing installations visible to this App:")
        for installation in list_installations(signed):
            print(
                f"  id={installation['id']}  account={installation['account']['login']}"
            )
        raise SystemExit("Set GITHUB_APP_INSTALLATION_ID to one of the above and re-run.")

    result = get_installation_token(signed, installation_id)
    print(f"Installation token: {result['token']}")
    print(f"Expires: {result['expires_at']}")
    print(f"Granted permissions: {result['permissions']}")

    # If running as a GitHub Actions step, hand the token to later steps the
    # same way actions/create-github-app-token does - steps.<id>.outputs.token
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"token={result['token']}\n")

    # From here it behaves exactly like a PAT, within its granted scope:
    #   git clone https://x-access-token:<token>@github.com/owner/repo.git
    #   curl -H "Authorization: token <token>" https://api.github.com/repos/owner/repo
