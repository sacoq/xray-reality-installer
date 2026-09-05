from uuid import uuid4
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from panel.database import Base
from panel.models import Server, Client
from panel import traffic_lifetime as ledger


def test_totals_survive_client_server_deletion_and_restart():
    engine = create_engine('sqlite:///:memory:')
    @event.listens_for(engine, 'connect')
    def foreign_keys(conn, _): conn.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        server = Server(name='test',agent_url='http://test',agent_token='test',
                        public_host='test',port=443,sni='test',private_key='test',public_key='test',short_id='ab')
        client = Client(uuid=str(uuid4()),email='user',total_up=4*10**12,total_down=86*10**12)
        server.clients.append(client);db.add(server);db.commit()
        ledger.seed(db)
        original=ledger.totals(db)
        ledger.seed(db)
        assert ledger.totals(db)==original
        row=ledger.ensure(db,server)
        before=(client.total_up,client.total_down)
        client.total_down+=1000
        ledger.add(row,client,before);db.commit()
        db.delete(client);db.commit()
        assert ledger.totals(db)==(original[0],original[1]+1000)
        db.delete(server);db.commit()
    with Session(engine) as db:
        ledger.seed(db)
        assert ledger.totals(db)==(original[0],original[1]+1000)


def test_internal_forwarding_is_excluded():
    assert not ledger.visible(Client(email='__balancer__-1',label='other'))
    assert not ledger.visible(Client(email='internal',label='__bypass__'))
    assert ledger.visible(Client(email='normal',label='vpn'))
