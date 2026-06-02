"""Seed the routing_configs table so alert emails have recipients.

The notifier resolves recipients by these EXACT snake_case role keys (see
app/services/notifier.py SEVERITY_ROUTING): 'ciso', 'head_of_security',
'head_engineer'. Inserting a prettily-named role like 'Head Engineer' will NOT
be matched by the routing matrix, so use the keys below.

Usage (from the project root):

    # Point every role at one inbox (quick demo setup):
    python -m scripts.seed_routing --all you@falak.me

    # Or set individual roles:
    python -m scripts.seed_routing \
        --ciso ciso@falak.me \
        --head-of-security sec@falak.me \
        --head-engineer eng@falak.me

    # Or via env vars (no flags needed):
    TW_CISO=ciso@falak.me TW_HEAD_OF_SECURITY=sec@falak.me \
    TW_HEAD_ENGINEER=eng@falak.me python -m scripts.seed_routing

This upserts (insert-or-update) and is safe to run repeatedly.
"""
import argparse
import asyncio
import os

from sqlalchemy import select

from app.database import async_session, init_db
from app.models import RoutingConfig

# The canonical role keys the notifier looks up.
ROLE_KEYS = ("ciso", "head_of_security", "head_engineer")


async def upsert_role(role: str, email: str) -> None:
    async with async_session() as db:
        existing = await db.execute(
            select(RoutingConfig).where(RoutingConfig.role == role)
        )
        row = existing.scalar_one_or_none()
        if row:
            row.email_address = email
        else:
            db.add(RoutingConfig(role=role, email_address=email))
        await db.commit()


def resolve_emails(args: argparse.Namespace) -> dict[str, str]:
    """Build {role: email} from --all, individual flags, or TW_* env vars."""
    if args.all:
        return {role: args.all for role in ROLE_KEYS}

    mapping = {
        "ciso": args.ciso or os.getenv("TW_CISO"),
        "head_of_security": args.head_of_security or os.getenv("TW_HEAD_OF_SECURITY"),
        "head_engineer": args.head_engineer or os.getenv("TW_HEAD_ENGINEER"),
    }
    return {role: email for role, email in mapping.items() if email}


async def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ThreatWeaver email routing roles.")
    parser.add_argument("--all", help="Use one email for every role (quick demo).")
    parser.add_argument("--ciso", help="Email for the CISO role.")
    parser.add_argument("--head-of-security", dest="head_of_security",
                        help="Email for the Head of Security role.")
    parser.add_argument("--head-engineer", dest="head_engineer",
                        help="Email for the Head Engineer role.")
    args = parser.parse_args()

    emails = resolve_emails(args)
    if not emails:
        parser.error(
            "No emails provided. Use --all EMAIL, the per-role flags, or the "
            "TW_CISO / TW_HEAD_OF_SECURITY / TW_HEAD_ENGINEER env vars."
        )

    await init_db()  # ensure the table exists
    for role, email in emails.items():
        await upsert_role(role, email)
        print(f"  seeded {role} -> {email}")
    print(f"Done. Seeded {len(emails)} routing role(s).")


if __name__ == "__main__":
    asyncio.run(main())
