from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from panel.app import api_server_sync_clients
from panel.database import Base
from panel.models import Server, User


class SyncDbPoolTests(unittest.TestCase):
    def test_sync_releases_db_connection_before_agent_wait(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            engine = create_engine(
                f"sqlite:///{Path(temp) / 'panel.db'}",
                pool_size=1,
                max_overflow=0,
                pool_timeout=0.1,
            )
            Base.metadata.create_all(engine)
            db = Session(engine, expire_on_commit=False)
            user = User(username="admin", password_hash="test")
            server = Server(
                name="pool-test-node",
                agent_url="http://127.0.0.1:8765",
                agent_token="test-token",
                public_host="node.example.com",
                private_key="private",
                public_key="public",
                short_id="abcd1234",
            )
            db.add_all([user, server])
            db.commit()

            class FakeAgent:
                def __init__(self, *_args, **_kwargs):
                    pass

                def get_config(self):
                    # A second DB operation must be able to check out the only
                    # connection while the first sync waits for the agent.
                    with Session(engine) as concurrent:
                        concurrent.scalar(select(func.count()).select_from(Server))
                    return {
                        "inbounds": [
                            {
                                "tag": "vless-reality",
                                "protocol": "vless",
                                "settings": {"clients": []},
                            }
                        ]
                    }

            @contextmanager
            def checking_lock(_agent_url):
                # The lock wait must not hold the first checkout either.
                with Session(engine) as concurrent:
                    concurrent.scalar(select(func.count()).select_from(Server))
                yield

            try:
                with patch("panel.app.AgentClient", FakeAgent), patch(
                    "panel.app.agent_config_lock", checking_lock
                ):
                    result = api_server_sync_clients(
                        server.id, {"client_ids": [999999]}, user=user, db=db
                    )
                self.assertEqual(result["method"], "unchanged")
                self.assertFalse(result["restarted"])
            finally:
                db.close()
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
