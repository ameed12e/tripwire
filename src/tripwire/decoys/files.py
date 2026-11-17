"""Inert decoy files that look valuable. Detection relies on the filesystem collector.

All credentials are random and syntactically plausible but valid nowhere.
"""

from __future__ import annotations

import base64
import secrets
import string
from typing import ClassVar

from tripwire.decoys.base import DecoyTemplate

_WORDS = [
    "orbit",
    "velvet",
    "canyon",
    "ember",
    "lantern",
    "quartz",
    "meadow",
    "harbor",
    "violet",
    "summit",
    "thunder",
    "glacier",
    "copper",
    "falcon",
    "willow",
    "saddle",
    "marble",
    "prism",
    "anchor",
    "cobalt",
]


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


class AwsCredentials(DecoyTemplate):
    name: ClassVar[str] = "aws-credentials"
    description: ClassVar[str] = "Fake ~/.aws/credentials profile"
    default_filename: ClassVar[str] = "credentials"

    def render(self, beacon_url: str | None) -> bytes:
        key_id = "AKIA" + _rand(string.ascii_uppercase + "234567", 16)
        secret = _rand(string.ascii_letters + string.digits + "+/", 40)
        return (
            f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n"
            "region = us-east-1\n\n"
            f"[prod-admin]\naws_access_key_id = AKIA{_rand(string.ascii_uppercase, 16)}\n"
            f"aws_secret_access_key = {_rand(string.ascii_letters + string.digits, 40)}\n"
        ).encode()


class SshKey(DecoyTemplate):
    name: ClassVar[str] = "ssh-key"
    description: ClassVar[str] = "Fake OpenSSH private key (not a valid key)"
    default_filename: ClassVar[str] = "id_ed25519_backup"

    def render(self, beacon_url: str | None) -> bytes:
        body = base64.b64encode(b"openssh-key-v1\x00" + secrets.token_bytes(340)).decode()
        lines = [body[i : i + 70] for i in range(0, len(body), 70)]
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + "\n".join(lines)
            + "\n-----END OPENSSH PRIVATE KEY-----\n"
        ).encode()


class PasswordList(DecoyTemplate):
    name: ClassVar[str] = "passwords"
    description: ClassVar[str] = "Plain-text password list"
    default_filename: ClassVar[str] = "passwords.txt"

    def render(self, beacon_url: str | None) -> bytes:
        sites = ["bank", "email", "router admin", "vpn", "payroll portal", "nas"]
        rows = [
            f"{s:<16} user: {_rand(string.ascii_lowercase, 6)}  pass: "
            f"{secrets.choice(_WORDS).capitalize()}{secrets.randbelow(9000) + 1000}!"
            for s in sites
        ]
        return ("# do not share\n" + "\n".join(rows) + "\n").encode()


class EnvFile(DecoyTemplate):
    name: ClassVar[str] = "env-file"
    description: ClassVar[str] = "Application .env with fake secrets"
    default_filename: ClassVar[str] = ".env.production"

    def render(self, beacon_url: str | None) -> bytes:
        return (
            f"DATABASE_URL=postgres://app:{secrets.token_urlsafe(18)}@db.internal:5432/prod\n"
            f"STRIPE_SECRET_KEY=sk_live_{_rand(string.ascii_letters + string.digits, 24)}\n"
            f"JWT_SECRET={secrets.token_hex(32)}\n"
        ).encode()


class WalletSeed(DecoyTemplate):
    name: ClassVar[str] = "wallet-seed"
    description: ClassVar[str] = "Fake crypto wallet recovery phrase backup"
    default_filename: ClassVar[str] = "wallet-recovery-phrase.txt"

    def render(self, beacon_url: str | None) -> bytes:
        words = " ".join(secrets.choice(_WORDS) for _ in range(24))
        return f"Wallet backup - KEEP OFFLINE\n\nRecovery phrase:\n{words}\n".encode()


TEMPLATES: list[type[DecoyTemplate]] = [AwsCredentials, SshKey, PasswordList, EnvFile, WalletSeed]
