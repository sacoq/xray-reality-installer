from __future__ import annotations

import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from panel.app import api_provision_clients_bulk
from panel.database import Base
from panel.models import Client, Server, User
from panel.schemas import ClientProvisionBulkIn


class BulkProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine, expire_on_commit=False)
        self.user = User(username="admin", password_hash="test")
        self.server = Server(
            name="test-node",
            agent_url="http://127.0.0.1:8765",
            agent_token="test-token",
            public_host="node.example.com",
            private_key="private",
            public_key="public",
            short_id="abcd1234",
        )
        self.db.add_all([self.user, self.server])
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()

    def test_bulk_provision_is_fast_db_only_and_idempotent(self) -> None:
        body = ClientProvisionBulkIn(
            items=[
                {
                    "server_id": self.server.id,
                    "email": "sub-123@test-node",
                    "label": "Subscription 123",
                }
            ]
        )

        first = api_provision_clients_bulk(body, user=self.user, db=self.db)
        second = api_provision_clients_bulk(body, user=self.user, db=self.db)

        self.assertEqual(first["created_server_ids"], [self.server.id])
        self.assertEqual(second["created_server_ids"], [])
        self.assertEqual(first["errors"], [])
        self.assertEqual(first["clients"][0]["uuid"], second["clients"][0]["uuid"])
        self.assertEqual(
            self.db.scalar(select(func.count()).select_from(Client)),
            1,
        )


if __name__ == "__main__":
    unittest.main()
