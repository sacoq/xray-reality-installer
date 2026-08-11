#!/usr/bin/env bash

# -----------------------------------------
# Russian ISP Connectivity Checker
# Проверка доступности IP из сетей РФ через RIPE Atlas
# -----------------------------------------

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
BLUE="\033[34m"
DIM="\033[2;90m"
RESET="\033[0m"

# Ваш токен авторизации
AUTH_TOKEN="RVJDWEVXOTAzUkRUU1pTWkFCWDZFRkVOOmQxSEFlZEpzVWRINWFLbUIxaDYxY1BNOQ=="

# Провайдеры РФ
declare -A PROVIDERS=(
  [12389]="Ростелеком"
  [8402]="Билайн"
  [25513]="МГТС"
  [8359]="МТС"
  [3216]="Билайн"
  [20485]="ТТК"
  [25490]="РТК-Юг"
  [43727]="Мегафон"
  [12714]="Мегафон"
  [34757]="Sib Seti"
  [29124]="Iskratelecom"
  [12768]="Дом.ру"
)

# Получаем публичный IP
CURRENT_IP=$(curl -s -4 --connect-timeout 3 https://api.ipify.org 2>/dev/null)
if [[ -z "$CURRENT_IP" ]]; then
  echo -e "${RED}Не удалось определить IP адрес${RESET}"
  exit 1
fi

clear
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e " ${YELLOW}◆${RESET}          ${BLUE}Russian ISP Connectivity Checker${RESET}          ${YELLOW}◆${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "Проверяемый IP: ${CYAN}$CURRENT_IP${RESET}"
echo -e "Целевой порт:   ${CYAN}443 (HTTPS)${RESET}"
echo -e "Метод:          ${CYAN}Ping${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

# Проверяем Python3
if ! command -v python3 >/dev/null; then
  echo -e "${RED}Python3 не установлен${RESET}"
  echo -e "${YELLOW}Установите: apt install python3 или yum install python3${RESET}"
  exit 1
fi

echo -e "${YELLOW}Запуск проверки доступности из сетей РФ...${RESET}"
echo

TMP_ATLAS=$(mktemp)

python3 << EOF
import sys, json, time, urllib.request, urllib.error, base64

auth_token = "$AUTH_TOKEN"
target_ip = "$CURRENT_IP"

def dlog(msg):
    print(f'[DEBUG] {msg}', file=sys.stderr, flush=True)

# Создаем измерение
url = 'https://atlas.ripe.net/api/v2/measurements/'
data = {
    'definitions': [{
        'target': target_ip,
        'description': 'Ping test from Russian ISPs',
        'type': 'ping',
        'af': 4,
        'packets': 3
    }],
    'probes': [
        {'requested': 3, 'type': 'asn', 'value': 12389},  # Ростелеком
        {'requested': 5, 'type': 'asn', 'value': 8402},   # Билайн
        {'requested': 5, 'type': 'asn', 'value': 25513},  # МГТС
        {'requested': 3, 'type': 'asn', 'value': 8359},   # МТС
        {'requested': 3, 'type': 'asn', 'value': 3216},   # Билайн
        {'requested': 2, 'type': 'asn', 'value': 20485},  # ТТК
        {'requested': 1, 'type': 'asn', 'value': 25490},  # РТК-Юг
        {'requested': 1, 'type': 'asn', 'value': 43727},  # Мегафон
        {'requested': 4, 'type': 'asn', 'value': 12714},  # Мегафон
        {'requested': 2, 'type': 'asn', 'value': 34757},  # Sib Seti
        {'requested': 2, 'type': 'asn', 'value': 29124},  # Iskratelecom
        {'requested': 2, 'type': 'asn', 'value': 12768}   # Дом.ру
    ],
    'is_oneoff': True
}

headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Basic {auth_token}'
}

try:
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)
    with urllib.request.urlopen(req) as response:
        resp_data = json.loads(response.read().decode())
        msm_id = resp_data['measurements'][0]
        print(f'MEASUREMENT_ID {msm_id}')
        print(f'MSM_ID {msm_id}')
except Exception as e:
    print(f'ERROR API_FAIL: {str(e)}')
    sys.exit(0)

# Получаем результаты
results_url = f'https://atlas.ripe.net/api/v2/measurements/{msm_id}/results/'
results = []

for attempt in range(30):
    time.sleep(2)
    try:
        req = urllib.request.Request(results_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            results = json.loads(response.read().decode())
            if len(results) >= 33:
                break
    except Exception:
        pass

if not results:
    print('ERROR NO_DATA')
    sys.exit(0)

# Анализируем результаты
total = len(results)
success = 0
failed = 0
failed_asns = {}
failed_names = {}

for probe in results:
    prb_id = probe.get('prb_id')
    asn = probe.get('asn')
    result = probe.get('result', {})
    
    # Проверяем наличие ответов
    if 'result' in result and len(result['result']) > 0:
        success += 1
    else:
        failed += 1
        if asn:
            failed_asns[asn] = failed_asns.get(asn, 0) + 1

print(f'STATS {total} {success} {failed}')

if failed_asns:
    parts = []
    for asn, cnt in failed_asns.items():
        parts.append(f'{asn}:{cnt}')
    print(f'FAILED_ASN {" ".join(parts)}')
EOF

# Анимация ожидания
for i in {1..20}; do
  echo -ne "${CYAN}⏳ Ожидание результатов...${RESET} ${DIM}(${i}/20)${RESET}\r"
  sleep 1
done
echo

# Читаем результаты
ATLAS_OUTPUT=$(cat "$TMP_ATLAS")
rm -f "$TMP_ATLAS"

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BLUE}📊 РЕЗУЛЬТАТЫ ПРОВЕРКИ${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if echo "$ATLAS_OUTPUT" | grep -q "ERROR"; then
  ERROR_MSG=$(echo "$ATLAS_OUTPUT" | grep "ERROR" | head -1)
  echo -e "${RED}❌ Ошибка: ${ERROR_MSG}${RESET}"
  exit 1
fi

# Парсим результаты
STATS_LINE=$(echo "$ATLAS_OUTPUT" | grep "^STATS" | head -1)
FAILED_ASN_LINE=$(echo "$ATLAS_OUTPUT" | grep "^FAILED_ASN" | head -1)

if [[ -z "$STATS_LINE" ]]; then
  echo -e "${RED}❌ Не удалось получить данные${RESET}"
  echo "$ATLAS_OUTPUT"
  exit 1
fi

TOTAL=$(echo "$STATS_LINE" | awk '{print $2}')
SUCCESS=$(echo "$STATS_LINE" | awk '{print $3}')
FAILED=$(echo "$STATS_LINE" | awk '{print $4}')

# Вычисляем проценты
if (( TOTAL > 0 )); then
  SUCCESS_PERCENT=$(( SUCCESS * 100 / TOTAL ))
else
  SUCCESS_PERCENT=0
fi

# Определяем статус
if (( SUCCESS_PERCENT == 100 )); then
  COLOR=$GREEN
  STATUS_TEXT="✅ ПОЛНАЯ ДОСТУПНОСТЬ"
  STATUS_ICON="🟢"
elif (( SUCCESS_PERCENT >= 70 )); then
  COLOR=$YELLOW
  STATUS_TEXT="⚠️ ЧАСТИЧНАЯ ДОСТУПНОСТЬ"
  STATUS_ICON="🟡"
elif (( SUCCESS_PERCENT >= 40 )); then
  COLOR=$YELLOW
  STATUS_TEXT="⚠️ НИЗКАЯ ДОСТУПНОСТЬ"
  STATUS_ICON="🟠"
else
  COLOR=$RED
  STATUS_TEXT="❌ КРИТИЧЕСКИ НЕДОСТУПЕН"
  STATUS_ICON="🔴"
fi

# Выводим статистику
echo
echo -e "  📍 Всего зондов:    ${CYAN}${TOTAL}${RESET}"
echo -e "  ✅ Успешных:        ${GREEN}${SUCCESS}${RESET}"
echo -e "  ❌ Неудачных:       ${RED}${FAILED}${RESET}"
echo -e "  📊 Доступность:     ${COLOR}${SUCCESS_PERCENT}%${RESET}"
echo -e "  🏁 Статус:          ${COLOR}${STATUS_TEXT}${RESET}"

# Выводим провайдеров с проблемами
if [[ -n "$FAILED_ASN_LINE" ]]; then
  FAILED_PARTS=$(echo "$FAILED_ASN_LINE" | sed 's/FAILED_ASN //')
  echo
  echo -e "${RED}🚫 Провайдеры с проблемами:${RESET}"
  echo -e "${DIM}----------------------------------------${RESET}"
  
  for part in $FAILED_PARTS; do
    asn="${part%%:*}"
    cnt="${part##*:}"
    name="${PROVIDERS[$asn]:-AS$asn}"
    echo -e "  ${RED}✗${RESET} ${name}: ${RED}${cnt}${RESET} зондов не ответили (AS${asn})"
  done
fi

echo
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${DIM}📌 Использовано: RIPE Atlas Probes${RESET}"
echo -e "${DIM}🕐 Время: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo -e "${DIM}🌐 IP: ${CURRENT_IP}${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"