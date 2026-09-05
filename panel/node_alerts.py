"""Debounced, persistent node alert state driven by the existing metrics sampler."""
import json
from statistics import median
from . import audit


def evaluate(state, *, now, online, count, pressure, prefs, failure_kind=''):
    state = dict(state)
    events = []
    last = dict(state.get('last', {}))
    confirmation = prefs['confirmations']
    # Do not join observations separated by a panel outage into one incident.
    if now - state.get('sample_at', now) > 300:
        state.update(history=[], bad=0, good=0, drop_candidate=0, pressure_count=0)
    state['sample_at'] = now
    def emit(action, detail):
        if now-last.get(action, 0) >= prefs['cooldown_minutes']*60:
            events.append((action, detail))
            last[action] = now

    if not online:
        state['bad'] = state.get('bad', 0)+1
        state.update(good=0, drop_candidate=0, history=[], pressure_count=0)
        if state['bad'] >= confirmation and not state.get('down'):
            state['down'] = True
            state['down_since'] = now
            kind = 'server.telemetry_lost' if failure_kind in ('network','agent','unknown') else 'server.offline'
            emit(kind, f'Неуспешных проверок подряд: {state["bad"]}. Причина: {failure_kind or "нет связи"}.')
    else:
        state['bad'] = 0
        state['good'] = state.get('good', 0)+1
        if state.get('down') and state['good'] >= confirmation:
            emit('server.online', f'Связь и сервис восстановлены. Инцидент длился {max(0, int(now-state.get("down_since",now)))//60} мин.')
            state.update(down=False, drop_active=False, drop_baseline=0, drop_candidate=0, history=[])
        # Unknown telemetry never becomes zero online. Recovering agents need
        # fresh baseline samples after the xray statistics counter resets.
        if count is not None and not state.get('down'):
            history = list(state.get('history', []))[-10:]
            baseline = state.get('drop_baseline') or (median(history) if len(history)>=3 else 0)
            low = baseline >= prefs['min_online'] and baseline-count >= prefs['min_lost'] and count <= baseline*(1-prefs['drop_percent']/100)
            if state.get('drop_active'):
                state['recover_count'] = state.get('recover_count',0)+1 if count >= baseline*.8 else 0
                if state['recover_count'] >= confirmation:
                    emit('server.online_recovery', f'Сейчас онлайн: {count}; до падения: {int(baseline)}.')
                    state.update(drop_active=False, drop_baseline=0, drop_candidate=0, recover_count=0)
                    history = [count]
            elif low:
                state['drop_candidate'] = state.get('drop_candidate',0)+1
                state['drop_baseline'] = baseline
                if state['drop_candidate'] >= confirmation:
                    state['drop_active'] = True
                    emit('server.online_drop', f'Онлайн: {int(baseline)} → {count} (−{round((baseline-count)*100/baseline)}%). Падение подтверждено {confirmation} замерами.')
            else:
                state.update(drop_candidate=0, drop_baseline=0)
                history = (history+[count])[-10:]
            state['history'] = history
        elif count is None:
            state.update(drop_candidate=0, history=[])
            if not state.get('drop_active'): state['drop_baseline'] = 0
        hot = pressure >= 95 if not state.get('hot') else pressure > 85
        if hot != bool(state.get('hot')):
            state['pressure_count'] = state.get('pressure_count',0)+1
            if state['pressure_count'] >= confirmation:
                state.update(hot=hot, pressure_count=0)
                emit('server.resource_pressure' if hot else 'server.resource_recovery', f'CPU / память: максимальная загрузка {round(pressure)}%.')
        else:
            state['pressure_count'] = 0
    state['last'] = last
    return state, events


def observe(db, server, *, now, online, count, pressure, failure_kind):
    key = f'notifications.node.{server.id}'
    try: state = json.loads(audit.setting_get(db,key,'{}'))
    except ValueError: state = {}
    state, events = evaluate(state, now=now, online=online, count=count, pressure=pressure,
                             prefs=audit.notification_preferences(db), failure_kind=failure_kind)
    audit.setting_set(db,key,json.dumps(state))
    details = []
    for action, detail in events:
        detail = f'{server.display_name or server.name}\n{server.public_host}:{server.port}\n{detail}'
        audit.record(db,user=None,action=action,resource_type='server',resource_id=server.id,details=detail,notify=False)
        details.append((action, detail))
    return details
