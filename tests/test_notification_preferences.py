from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from panel.database import Base
from panel import audit
from panel.models import AuditLog
from panel.schemas import NotificationPreferences
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from types import SimpleNamespace


def test_defaults_mute_client_noise_but_keep_audit():
    engine=create_engine('sqlite:///:memory:');Base.metadata.create_all(engine)
    with Session(engine) as db, patch.object(audit,'_telegram_notify') as send:
        audit.record(db,user=None,action='client.delete',resource_id=1)
        db.commit()
        assert db.query(AuditLog).count()==1
        send.assert_not_called()
        assert audit.notification_allowed(db,'server.offline')
        prefs=NotificationPreferences(enabled=False)
        audit.setting_set(db,'notifications.preferences',prefs.model_dump_json());db.commit()
        assert not audit.notification_allowed(db,'server.offline')


def test_preferences_persist_and_telegram_markup_is_escaped():
    engine=create_engine('sqlite:///:memory:');Base.metadata.create_all(engine)
    with Session(engine) as db:
        audit.setting_set(db,'telegram.bot_token','test')
        audit.setting_set(db,'telegram.chat_id','1')
        audit.setting_set(db,'notifications.preferences',NotificationPreferences(client_actions=True).model_dump_json())
        db.commit()
    with Session(engine) as db, patch.object(audit.httpx,'post') as post:
        assert audit.notification_allowed(db,'client.delete')
        audit._telegram_notify(db,action='server.offline',resource_type='server',resource_id='1',details='<unsafe>&',actor='test')
        assert '&lt;unsafe&gt;&amp;' in post.call_args.kwargs['json']['text']


def test_preferences_http_roundtrip_and_existing_token_preserved():
    from panel import app as module
    engine=create_engine('sqlite://',poolclass=StaticPool,connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine)
    def session():
        with Session(engine) as db: yield db
    module.app.dependency_overrides[module.get_db]=session
    module.app.dependency_overrides[module.current_user]=lambda:SimpleNamespace(id=None,username='test')
    try:
        with Session(engine) as db:
            audit.setting_set(db,'telegram.bot_token','existing-test-token');db.commit()
        client=TestClient(module.app)
        response=client.get('/api/notifications/preferences')
        assert response.status_code==200 and response.json()['client_actions'] is False
        prefs=response.json();prefs['drop_percent']=65;prefs['node_up']=False
        assert client.put('/api/notifications/preferences',json=prefs).status_code==200
        assert client.get('/api/notifications/preferences').json()['drop_percent']==65
        result=client.post('/api/notifications/telegram',json={'bot_token':None,'chat_id':'123'})
        assert result.status_code==200,result.text
        with Session(engine) as db: assert audit.telegram_config(db)==('existing-test-token','123')
    finally:
        module.app.dependency_overrides.clear()
