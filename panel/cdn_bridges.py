"""Durable Yandex CDN bridges. Credentials are encrypted and never returned."""
import base64,copy,hashlib,json,os,re,secrets,threading,time,uuid
from pathlib import Path
import httpx,paramiko
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import Depends,HTTPException
from pydantic import BaseModel,Field
from sqlalchemy import select
from .auth import current_user,_secret_key
from .database import SessionLocal
from .models import Server,Client
from .agent_client import AgentClient
from .xray_push import push_config

ROOT=Path('/var/lib/xray-panel/private/cdn');LOCK=threading.RLock()
def cipher():return Fernet(base64.urlsafe_b64encode(hashlib.sha256((_secret_key()+':cdn-credentials').encode()).digest()))
def state():
 ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
 p=ROOT/'state.json';return json.loads(p.read_text()) if p.exists() else {'accounts':{},'jobs':{}}
def save(d):
 p=ROOT/'state.json';t=ROOT/'state.tmp';t.write_text(json.dumps(d));t.chmod(0o600);os.replace(t,p)
def seal(d):return cipher().encrypt(json.dumps(d).encode()).decode()
def open_secret(s):return json.loads(cipher().decrypt(s.encode()))
def host(s):
 s=s.strip().lower()
 if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',s) or '.' not in s:raise ValueError('Неверный домен')
 return s
def call(method,url,token,body=None):
 with httpx.Client(timeout=30) as c:
  r=c.request(method,url,headers={'Authorization':'Bearer '+token},json=body)
 if r.status_code>=400:raise RuntimeError('Ошибка API '+str(r.status_code))
 return r.json() if r.content else {}
def iam(key):
 now=int(time.time());b=lambda v:base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip('=')
 h=b({'typ':'JWT','alg':'PS256','kid':key['id']});p=b({'iss':key['service_account_id'],'aud':'https://iam.api.cloud.yandex.net/iam/v1/tokens','iat':now,'exp':now+600})
 pem=key['private_key'];pem=pem[pem.index('-----BEGIN'):]
 k=serialization.load_pem_private_key(pem.encode(),password=None)
 s=base64.urlsafe_b64encode(k.sign((h+'.'+p).encode(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())).decode().rstrip('=')
 with httpx.Client(timeout=20) as c:
  r=c.post('https://iam.api.cloud.yandex.net/iam/v1/tokens',json={'jwt':h+'.'+p+'.'+s});r.raise_for_status();return r.json()['iamToken']
def operation(o,t):
 if not o.get('done'):o=call('GET','https://operation.api.cloud.yandex.net/operations/'+o['id'],t)
 if not o.get('done'):raise Pending('Ожидается операция Yandex')
 if o.get('error'):raise RuntimeError('Операция Yandex завершилась ошибкой')
 return o.get('response',{})
def cf(secret,method,path,body=None):
 d=call(method,'https://api.cloudflare.com/client/v4'+path,secret['cloudflare_token'],body)
 if not d.get('success'):raise RuntimeError('Ошибка Cloudflare')
 return d.get('result')
def dns(secret,name,kind,value):
 path='/zones/'+secret['zone_id']+'/dns_records'
 rows=cf(secret,'GET',path+'?name='+name+'&type='+kind)
 body={'type':kind,'name':name,'content':value,'ttl':120,'proxied':False}
 if rows:
  if rows[0]['content']!=value:raise RuntimeError('DNS-запись уже указывает на другой адрес')
  return
 cf(secret,'POST',path,body)
class Pending(Exception):pass
class AccountIn(BaseModel):
 name:str=Field(min_length=1,max_length=128)
 folder_id:str=Field(pattern=r'^b1[a-z0-9]+$')
 cloud_id:str=Field(pattern=r'^b1[a-z0-9]+$')
 authorized_key:dict
 cloudflare_token:str=Field(default='',max_length=512)
 zone_id:str=Field(default='',max_length=128)
 domain:str=Field(default='',max_length=253)
 email:str=Field(default='',max_length=255)
class AttachIn(BaseModel):
 account_id:str
 source_server_id:int=0
 ssh_host:str=Field(default='',max_length=255)
 name:str=Field(min_length=1,max_length=128)
 ssh_password:str=Field(min_length=1,max_length=512)
 ssh_user:str=Field(default='root',pattern=r'^[a-z_][a-z0-9_-]*$')
 ssh_port:int=Field(default=22,ge=1,le=65535)
def update(jid,**fields):
 with LOCK:
  d=state();d['jobs'][jid].update(fields,updated_at=int(time.time()));save(d)
def remote(j,secret,body):
 c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy());p=None
 try:
  c.connect(j['origin_ip'],port=j['ssh_port'],username=j['ssh_user'],password=secret['ssh_password'],timeout=15,look_for_keys=False,allow_agent=False)
  sf=c.open_sftp();p='/tmp/xnpanel-cdn-'+j['id']+'.json'
  with sf.open(p,'w') as f:f.write(json.dumps(body))
  sf.chmod(p,0o600);sf.put(str(Path(__file__).with_name('cdn_origin_install.py')),'/tmp/xnpanel-cdn-origin-install.py');sf.close()
  _,out,err=c.exec_command('python3 /tmp/xnpanel-cdn-origin-install.py '+p,timeout=300)
  # Drain output before exit status to avoid pipe deadlock. Never expose credentials/output.
  out.read();err.read();code=out.channel.recv_exit_status()
  if code:raise RuntimeError('Настройка origin завершилась ошибкой (код '+str(code)+')')
 finally:
  if p:
   try:c.exec_command('rm -f '+p)
   except Exception:pass
  c.close()
def create_panel_node(j,extras):
 from .app import _provision_all_server_subscriptions_for_server, _reserve_server_id
 with SessionLocal() as db:
  source=db.get(Server,j['source_server_id']);assert source
  existing=db.scalar(select(Server).where(Server.name=='cdn-'+j['id']))
  if existing:
   _provision_all_server_subscriptions_for_server(existing,db);db.refresh(existing);push_config(existing,db);return existing.id
  agent=AgentClient(source.agent_url,source.agent_token,timeout=60);cfg=agent.get_config()
  backup=ROOT/('config-before-'+j['id']+'.json');backup.write_text(json.dumps(cfg));backup.chmod(0o600)
  tag='cdn-'+j['id'];port=j['inbound_port']
  if not any(i.get('tag')==tag for i in cfg['inbounds']):
   if any(i.get('port')==port for i in cfg['inbounds']):raise RuntimeError('Локальный порт занят')
   cfg['inbounds'].append({'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'xhttp','security':'none','xhttpSettings':extras},'sniffing':{'enabled':True,'destOverride':['http','tls','quic']}})
  # The original managed builder would otherwise remove the additional inbound.
  if source.mode=='standalone':
   orig=next((i for i in cfg['inbounds'] if i.get('protocol')=='vless' and i.get('port')==source.port),None)
   if not orig:raise RuntimeError('Не найден исходный VLESS inbound')
   legacy_tag=orig['tag']
  else:
   legacy_tag=(getattr(source,'custom_inbound_tag','') or '').strip()
  agent.put_config(cfg)
  s=Server(id=_reserve_server_id(),name='cdn-'+j['id'],display_name=j['name'],agent_url=source.agent_url,agent_token=source.agent_token,public_host=j['cdn_domain'],port=443,sni=j['cdn_domain'],dest='',private_key='',public_key='',short_id='',protocol='vless-xhttp-tls',mode='custom',custom_inbound_tag=tag,transport='xhttp',transport_path=j['path'],xhttp_extra_json=json.dumps(extras),custom_sync_tags_json='[]',in_pool=True,pool_tier='primary',folder='CDN',subscription_visible=True)
  db.add(s);db.commit();db.refresh(s);_provision_all_server_subscriptions_for_server(s,db);db.refresh(s);push_config(s,db)
  return s.id
def work(jid):
 with LOCK:
  d=state();j=copy.deepcopy(d['jobs'][jid]);a=d['accounts'][j['account_id']];secret=open_secret(a['secret']);jobsecret=open_secret(j['secret']) if j.get('secret') else {}
 if j['status']=='ready':return
 try:
  update(jid,status='running',message='Настройка CDN')
  token=iam(secret['authorized_key']);folder=a['folder_id']
  if not j.get('origin_ready'):
   dns(secret,j['origin_domain'],'A',j['origin_ip'])
   update(jid,message='Сертификат и nginx на исходном сервере')
   remote(j,jobsecret,dict(id=jid,origin=j['origin_domain'],email=secret['email'],cloudflare_token=secret['cloudflare_token'],origin_port=j['origin_port'],inbound_port=j['inbound_port'],path=j['path']))
   update(jid,origin_ready=True);j['origin_ready']=True
  resources=call('GET','https://cdn.api.cloud.yandex.net/cdn/v1/resources?folderId='+folder,token).get('resources',[])
  resource=next((r for r in resources if r.get('cname')==j['cdn_domain']),None)
  if not j.get('origin_group_id'):
   groups=call('GET','https://cdn.api.cloud.yandex.net/cdn/v1/originGroups?folderId='+folder,token).get('originGroups',[])
   group=next((g for g in groups if g.get('name')=='xn-'+jid),None)
   if not group:
    op=call('GET','https://operation.api.cloud.yandex.net/operations/'+j['group_operation_id'],token) if j.get('group_operation_id') else call('POST','https://cdn.api.cloud.yandex.net/cdn/v1/originGroups',token,{'folderId':folder,'name':'xn-'+jid,'useNext':True,'origins':[{'source':j['origin_domain']+':'+str(j['origin_port']),'enabled':True,'backup':False}],'providerType':'ourcdn'})
    update(jid,group_operation_id=op['id']);group=operation(op,token)
   j['origin_group_id']=group['id'];update(jid,origin_group_id=group['id'])
  certs=call('GET','https://certificate-manager.api.cloud.yandex.net/certificate-manager/v1/certificates?folderId='+folder,token).get('certificates',[])
  cert=next((c for c in certs if j['cdn_domain'] in c.get('domains',[])),None)
  if not cert:
   op=call('GET','https://operation.api.cloud.yandex.net/operations/'+j['cert_operation_id'],token) if j.get('cert_operation_id') else call('POST','https://certificate-manager.api.cloud.yandex.net/certificate-manager/v1/certificates/requestNew',token,{'folderId':folder,'name':'xn-'+jid,'domains':[j['cdn_domain']],'challengeType':'DNS'})
   update(jid,cert_operation_id=op['id']);cert=operation(op,token)
  cert=call('GET','https://certificate-manager.api.cloud.yandex.net/certificate-manager/v1/certificates/'+cert['id']+'?view=FULL',token)
  update(jid,certificate_id=cert['id'])
  for challenge in cert.get('challenges',[]):
   ch=challenge.get('dnsChallenge',{});kind=ch.get('type');value=ch.get('value');name=ch.get('name')
   if kind=='CNAME' and value and name:dns(secret,name.rstrip('.'),kind,value.rstrip('.'))
  if cert.get('status')!='ISSUED':raise Pending('Ожидается выпуск сертификата CDN')
  if not resource:
   options={'edgeCacheSettings':{'enabled':True,'defaultValue':'0'},'browserCacheSettings':{'enabled':False},'queryParamsOptions':{'ignoreQueryString':{'enabled':True,'value':True}},'redirectOptions':{'redirectHttpToHttps':{'enabled':False,'value':False}},'hostOptions':{'host':{'enabled':True,'value':j['origin_domain']}},'customServerName':{'enabled':True,'value':j['origin_domain']},'allowedHttpMethods':{'enabled':True,'value':['GET','HEAD']},'ignoreCookie':{'enabled':True,'value':True}}
   op=call('GET','https://operation.api.cloud.yandex.net/operations/'+j['resource_operation_id'],token) if j.get('resource_operation_id') else call('POST','https://cdn.api.cloud.yandex.net/cdn/v1/resources',token,{'folderId':folder,'cname':j['cdn_domain'],'origin':{'originGroupId':j['origin_group_id']},'originProtocol':'HTTPS','active':True,'options':options,'sslCertificate':{'type':'CM','data':{'cm':{'id':cert['id']}}},'providerType':'ourcdn'})
   update(jid,resource_operation_id=op['id']);resource=operation(op,token)
  dns(secret,j['cdn_domain'],'CNAME',resource['providerCname']);update(jid,resource_id=resource['id'])
  try:
   with httpx.Client(timeout=15) as http:r=http.get('https://'+j['cdn_domain']+'/');r.raise_for_status()
  except Exception:raise Pending('Ожидается раскатка CDN и правильный TLS')
  extras=json.loads(Path(__file__).with_name('cdn_xhttp_defaults.json').read_text());extras['path']=j['path'];extras['mode']='packet-up'
  sid=create_panel_node(j,extras)
  update(jid,status='ready',message='CDN подключён; новая нода добавлена в подписки',server_id=sid,secret='')
 except Pending as e:update(jid,status='waiting',message=str(e),retry_at=int(time.time())+60)
 except Exception as e:
  # Provider exceptions may contain credentials: return only controlled messages.
  safe=str(e) if isinstance(e,RuntimeError) and str(e).startswith(('Ошибка API','Ошибка Cloudflare','DNS-запись','Настройка origin','Операция Yandex','Не найден','Локальный')) else 'Не удалось завершить настройку. Доступы и ресурсы сохранены; можно повторить.'
  update(jid,status='waiting',message=safe,retry_at=int(time.time())+60,attempts=int(j.get('attempts',0))+1)
def runner():
 while True:
  try:
   with LOCK:jobs=copy.deepcopy(state()['jobs'])
   for jid,j in jobs.items():
    if j['status'] in {'queued','running','waiting'} and j.get('retry_at',0)<=time.time():
     if time.time()-j['created_at']>10800:update(jid,status='error',message='Ожидание превысило 3 часа. Можно повторить существующую задачу.')
     else:work(jid)
  except Exception:pass
  time.sleep(5)
def public(d):
 accounts=[{k:v for k,v in a.items() if k!='secret'} for a in d['accounts'].values()]
 jobs=[{k:v for k,v in j.items() if k not in {'secret','ssh_user','ssh_port'}} for j in d['jobs'].values()]
 return {'accounts':accounts,'jobs':jobs}
def install_routes(app):
 @app.get('/api/cdn-bridges')
 def get(user=Depends(current_user)):
  with LOCK:return public(state())
 @app.post('/api/cdn-bridges/accounts')
 def account(body:AccountIn,user=Depends(current_user)):
  try:
   t=iam(body.authorized_key)
   folder=call('GET','https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders/'+body.folder_id,t)
   if folder.get('cloudId')!=body.cloud_id:raise ValueError('cloud/folder mismatch')
   domain=host(body.domain) if body.domain else ''
   if body.cloudflare_token and domain:
    s=body.model_dump()
    zones=cf(s,'GET','/zones?name='+domain)
    if len(zones)!=1:raise ValueError('DNS zone not found')
    body.zone_id=zones[0]['id']
  except Exception:raise HTTPException(400,'Не удалось проверить доступ: проверьте файл ключа, ID облака и каталога, домен и права Cloudflare токена.')
  aid=uuid.uuid4().hex[:12]
  with LOCK:
   d=state();d['accounts'][aid]={'id':aid,'name':body.name,'cloud_id':body.cloud_id,'folder_id':body.folder_id,'domain':domain,'dns_ready':bool(body.cloudflare_token and body.zone_id and domain and body.email),'secret':seal(body.model_dump())};save(d)
  return {'id':aid}
 @app.post('/api/cdn-bridges/attach')
 def attach(body:AttachIn,user=Depends(current_user)):
  with LOCK:
   d=state();a=d['accounts'].get(body.account_id)
   if not a or not a['dns_ready']:raise HTTPException(400,'Добавьте токен Cloudflare, домен и email в CDN-аккаунт')
   if any(j['source_server_id']==body.source_server_id and j['status'] in {'queued','waiting','running'} for j in d['jobs'].values()):raise HTTPException(409,'На этой ноде уже выполняется установка CDN')
   with SessionLocal() as db:
    s=db.get(Server,body.source_server_id) if body.source_server_id else None
    if s is None and body.ssh_host:
     from urllib.parse import urlsplit
     s=next((n for n in db.scalars(select(Server)) if urlsplit(n.agent_url).hostname==body.ssh_host.strip()),None)
    if not s or s.protocol not in {'vless-reality','vless-xhttp-tls'} or s.mode not in {'standalone','custom'}:raise HTTPException(400,'Выберите существующую VLESS-ноду с агентом')
    body.source_server_id=s.id
    from urllib.parse import urlsplit
    ip=urlsplit(s.agent_url).hostname
    import ipaddress
    try:ipaddress.ip_address(ip)
    except ValueError:raise HTTPException(400,'Адрес агента должен содержать IP сервера')
    if any(j['source_server_id']==s.id and j['status'] in {'queued','waiting','running'} for j in d['jobs'].values()):raise HTTPException(409,'На этом сервере уже выполняется установка CDN')
    probe=paramiko.SSHClient();probe.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
     probe.connect(ip,port=body.ssh_port,username=body.ssh_user,password=body.ssh_password,timeout=10,look_for_keys=False,allow_agent=False)
     _,out,_=probe.exec_command('id -u',timeout=10)
     if out.read().strip()!=b'0':raise HTTPException(400,'Для установки нужен root. Укажите root и его SSH-пароль.')
    except HTTPException:raise
    except Exception:raise HTTPException(400,'Не удалось подключиться по SSH. Проверьте IP, порт, логин и пароль.')
    finally:probe.close()
   jid=uuid.uuid4().hex[:12];domain=a['domain'];occupied={j.get('origin_port') for j in d['jobs'].values()};port=24443
   while port in occupied:port+=1
   j={'id':jid,'account_id':body.account_id,'source_server_id':body.source_server_id,'name':body.name,'origin_ip':ip,'origin_domain':'origin-'+jid+'.'+domain,'cdn_domain':'cdn-'+jid+'.'+domain,'path':'/content/v1/'+secrets.token_hex(8)+'/','origin_port':port,'inbound_port':port+10000,'ssh_user':body.ssh_user,'ssh_port':body.ssh_port,'secret':seal({'ssh_password':body.ssh_password}),'status':'queued','message':'В очереди','created_at':int(time.time())}
   d['jobs'][jid]=j;save(d)
  return {'id':jid}
 @app.post('/api/cdn-bridges/jobs/{jid}/retry')
 def retry(jid:str,user=Depends(current_user)):
  with LOCK:
   d=state();j=d['jobs'].get(jid)
   if not j:raise HTTPException(404,'Задача не найдена')
   if j['status']=='ready':return {'ok':True}
   if j['status'] not in {'error','waiting'}:raise HTTPException(409,'Задача выполняется')
   j.update(status='queued',retry_at=0,created_at=int(time.time()));save(d)
  return {'ok':True}
 @app.post('/api/cdn-bridges/jobs/{jid}/origin-site')
 def origin_site(jid:str,user=Depends(current_user)):
  with LOCK:
   j=copy.deepcopy(state()['jobs'].get(jid))
  if not j:raise HTTPException(404,'CDN-задача не найдена')
  if j.get('status')!='ready':raise HTTPException(409,'Дождитесь завершения установки CDN')
  with SessionLocal() as db:
   s=db.get(Server,j.get('server_id'))
   if not s:raise HTTPException(404,'CDN-нода не найдена')
   agent=AgentClient(s.agent_url,s.agent_token,timeout=60)
   try:
    with agent._client() as c:
     r=c.post(agent.base_url+'/cdn/origin/site',headers=agent._headers(),json={'job_id':jid})
    if r.status_code==404:raise HTTPException(409,'Агент ещё не поддерживает обновление сайта. Обновите агент в панели и повторите.')
    if r.status_code>=400:raise HTTPException(502,'Агент не смог обновить сайт; проверьте журнал агента. Конфигурация Xray не изменялась.')
    result=r.json()
   except HTTPException:raise
   except Exception:raise HTTPException(502,'Агент недоступен. Сайт не подтверждён как обновлённый.')
  update(jid,site_updated_at=int(time.time()))
  return result
 @app.on_event('startup')
 def start():threading.Thread(target=runner,daemon=True,name='cdn-bridge-worker').start()
