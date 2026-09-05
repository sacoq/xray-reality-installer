"""Traffic Guard lists with isolated, persistent firewall rules.

Never enable/reload UFW, change policies, save unrelated rules, or touch FORWARD.
The upstream `full` command enables inactive UFW, unsafe on existing VPN nodes.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path('/etc/xray-agent/traffic-guard-managed')
CHAIN = 'XNPANEL-GUARD'
SETS = ((4, 'XNPANEL-GUARD-V4', 'inet', 'iptables'), (6, 'XNPANEL-GUARD-V6', 'inet6', 'ip6tables'))
UNIT = Path('/etc/systemd/system/xnpanel-traffic-guard.service')
URL_BASE = 'https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/'


def run(args, *, check=True, data=None, timeout=30):
    return subprocess.run(args, input=data, capture_output=True, text=True,
                          check=check, timeout=timeout, env={**os.environ, 'LC_ALL':'C', 'DEBIAN_FRONTEND':'noninteractive'})


def atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.chmod(0o600)
    tmp.replace(path)


def download(profile):
    names = ['antiscanner'] + (['government_networks'] if profile == 'extended' else [])
    networks = set()
    for name in names:
        with urllib.request.urlopen(URL_BASE + name + '.list', timeout=30) as response:
            raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise ValueError('Blocklist exceeds size limit')
        current = set()
        for line in raw.decode('utf-8-sig').splitlines():
            value = line.split('#', 1)[0].strip()
            if not value:
                continue
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen == 0:
                raise ValueError('Refusing a default-route blocklist entry')
            current.add(net)
        if not current:
            raise ValueError('Empty blocklist: ' + name)
        networks.update(current)
    return sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def ensure_rule(binary, chain, rule, *, first=False):
    if run([binary, '-w', '5', '-C', chain, *rule], check=False).returncode:
        run([binary, '-w', '5', '-I' if first else '-A', chain, *(['1'] if first else []), *rule])


def configure_rules(logging):
    for version, name, family, binary in SETS:
        if run([binary, '-w', '5', '-S', CHAIN], check=False).returncode:
            run([binary, '-w', '5', '-N', CHAIN])
        ensure_rule(binary, CHAIN, ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'RETURN'], first=True)
        log_rule = ['-m', 'set', '--match-set', name, 'src', '-m', 'limit', '--limit', '10/min', '--limit-burst', '5', '-j', 'LOG', '--log-prefix', 'XNPANEL-GUARD: ', '--log-level', '4']
        if logging:
            # Insert before DROP, after established connections.
            if run([binary, '-w', '5', '-C', CHAIN, *log_rule], check=False).returncode:
                run([binary, '-w', '5', '-I', CHAIN, '2', *log_rule])
        elif run([binary, '-w', '5', '-C', CHAIN, *log_rule], check=False).returncode == 0:
            run([binary, '-w', '5', '-D', CHAIN, *log_rule])
        ensure_rule(binary, CHAIN, ['-m', 'set', '--match-set', name, 'src', '-j', 'DROP'])
        ensure_rule(binary, 'INPUT', ['-j', CHAIN], first=True)


def status():
    config = ROOT / 'config.json'
    if not config.exists():
        return None
    state = json.loads(config.read_text())
    counts, valid, logged, packets = {}, [], [], 0
    for version, name, family, binary in SETS:
        saved = run(['ipset', 'save', name], check=False)
        counts[version] = sum(line.startswith('add ' + name + ' ') for line in saved.stdout.splitlines())
        linked = run([binary, '-w', '5', '-C', 'INPUT', '-j', CHAIN], check=False).returncode == 0
        drop = run([binary, '-w', '5', '-C', CHAIN, '-m', 'set', '--match-set', name, 'src', '-j', 'DROP'], check=False).returncode == 0
        valid.append(linked and drop and (counts[version] > 0 or not state.get('ipv' + str(version) + '_entries')))
        rules = run([binary, '-w', '5', '-S', CHAIN], check=False).stdout
        logged.append('-j LOG' in rules)
        counters = run([binary, '-w', '5', '-L', CHAIN, '-n', '-v', '-x'], check=False).stdout
        for line in counters.splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[2] == 'DROP' and parts[0].isdigit():
                packets += int(parts[0])
    persistent = run(['systemctl', 'is-enabled', '--quiet', UNIT.name], check=False).returncode == 0
    active = all(valid) and sum(counts.values()) > 0 and persistent
    return dict(installed=True, active=active, profile=state['profile'], logging=all(logged),
                ipv4_entries=counts[4], ipv6_entries=counts[6], blocked_packets=packets,
                persistent=persistent, backend='managed', log_path='journalctl -k -g XNPANEL-GUARD',
                message='active' if active else 'Firewall rules or persistence need repair')


def install(profile, logging, protected=()):
    if profile not in ('scanner', 'extended'):
        raise ValueError('Unknown profile')
    networks = download(profile)  # Validate everything before changing firewall.
    for address in protected:
        ip = ipaddress.ip_address(address)
        if any(ip in net for net in networks):
            raise ValueError('Management address overlaps blocklist; refusing to lock out the panel')
    if not all(shutil.which(binary) for binary in ('ipset', 'iptables', 'ip6tables')):
        if not shutil.which('apt-get'):
            raise ValueError('Install ipset and iptables with your package manager first')
        run(['apt-get', 'update', '-qq'], timeout=180)
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'ipset', 'iptables'], timeout=180)
    ROOT.mkdir(parents=True, exist_ok=True)
    for version, name, family, binary in SETS:
        temporary = name + '-NEXT'
        run(['ipset', 'create', name, 'hash:net', 'family', family, 'maxelem', '65536', '-exist'])
        run(['ipset', 'create', temporary, 'hash:net', 'family', family, 'maxelem', '65536', '-exist'])
        run(['ipset', 'flush', temporary])
        entries = [net for net in networks if net.version == version]
        run(['ipset', 'restore', '-exist'], data=''.join('add ' + temporary + ' ' + str(net) + '\n' for net in entries))
        run(['ipset', 'swap', temporary, name])
        run(['ipset', 'destroy', temporary])
    configure_rules(logging)
    saved = ''.join(run(['ipset', 'save', name]).stdout for _, name, _, _ in SETS)
    atomic(ROOT / 'ipsets.rules', saved)
    atomic(ROOT / 'config.json', json.dumps(dict(profile=profile, logging=logging,
           ipv4_entries=sum(n.version == 4 for n in networks), ipv6_entries=sum(n.version == 6 for n in networks))))
    # Restore only our own objects, never iptables-save/restore of the host firewall.
    unit = ('[Unit]\nDescription=xnPanel Traffic Guard rules\nAfter=local-fs.target ufw.service\n'
            'Before=xray.service hysteria-server.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            f'ExecStart={sys.executable} {Path(__file__).resolve()} restore\n'
            '[Install]\nWantedBy=multi-user.target\n')
    atomic(UNIT, unit)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', UNIT.name])
    run(['systemctl', 'restart', UNIT.name])
    return status()


def restore():
    state = json.loads((ROOT / 'config.json').read_text())
    run(['ipset', 'restore', '-exist'], data=(ROOT / 'ipsets.rules').read_text())
    configure_rules(state['logging'])


def uninstall():
    if UNIT.exists():
        run(['systemctl', 'disable', '--now', UNIT.name])
    for version, name, family, binary in SETS:
        if not shutil.which(binary):
            continue
        while run([binary, '-w', '5', '-C', 'INPUT', '-j', CHAIN], check=False).returncode == 0:
            run([binary, '-w', '5', '-D', 'INPUT', '-j', CHAIN])
        run([binary, '-w', '5', '-F', CHAIN], check=False)
        run([binary, '-w', '5', '-X', CHAIN], check=False)
        run(['ipset', 'destroy', name], check=False)
    for path in (ROOT / 'config.json', ROOT / 'ipsets.rules', UNIT):
        path.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])


if __name__ == '__main__':
    if sys.argv[1:] == ['restore']:
        restore()
    else:
        raise SystemExit('Usage: traffic_guard.py restore')
