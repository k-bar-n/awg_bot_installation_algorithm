import os
import subprocess
import configparser
import json
from datetime import datetime, timedelta
import pytz
import glob
import sys

EXPIRATIONS_FILE = 'files/expirations.json'
UTC = pytz.UTC

def create_config(path='files/setting.ini'):
    wireguard_dir = "/etc/wireguard"
    amnezia_dir = "/etc/amnezia/amneziawg"
    conf_files = []
    
    for dir_path in [wireguard_dir, amnezia_dir]:
        if os.path.exists(dir_path):
            conf_files.extend(glob.glob(os.path.join(dir_path, "*.conf")))
    
    selected_conf = None
    if conf_files:
        print("Выберите конфигурационный файл:")
        for idx, conf in enumerate(conf_files, 1):
            print(f"{idx}) {conf}")
        while True:
            choice = input("Введите номер: ").strip()
            if not choice:
                choice = "1"
            if choice.isdigit() and 1 <= int(choice) <= len(conf_files):
                selected_conf = conf_files[int(choice) -1]
                break
            else:
                print("Неверный выбор. Пожалуйста, введите корректный номер.")
    else:
        dirs_exist = False
        for dir_path in [wireguard_dir, amnezia_dir]:
            if os.path.exists(dir_path):
                dirs_exist = True
                confs = glob.glob(os.path.join(dir_path, "*.conf"))
                if not confs:
                    config_type = "AmneziaWG" if 'amnezia' in dir_path else "WireGuard"
                    print(f"В системе установлен {config_type}, но не обнаружено конфигурационного файла.")
                    print("Перейти к его созданию?")
                    print("1) Да")
                    print("2) Нет")
                    while True:
                        user_choice = input("Введите номер: ").strip()
                        if user_choice == "1":
                            subprocess.run(["./genconf.sh"])
                            conf_files = glob.glob(os.path.join(dir_path, "*.conf"))
                            if conf_files:
                                selected_conf = conf_files[0]
                                break
                            else:
                                print("Не удалось создать конфигурационный файл.")
                                sys.exit(1)
                        elif user_choice == "2":
                            print("Инициализация не завершена.")
                            sys.exit(0)
                        else:
                            print("Неверный выбор. Пожалуйста, введите 1 или 2.")
        if not dirs_exist:
            print("WireGuard или AmneziaWG не установлены в системе.")
            print("Инициализация не завершена.")
            sys.exit(0)
    
    bot_token = input("Введите токен Telegram бота: ").strip()
    admin_id = input("Введите Telegram ID администратора: ").strip()
    endpoint = input("Введите Endpoint (IP-адрес сервера): ").strip()
    
    os.makedirs("files", exist_ok=True)
    with open(path, "w") as f:
        config = configparser.ConfigParser()
        config.add_section("setting")
        config.set("setting", "bot_token", bot_token)
        config.set("setting", "admin_id", admin_id)
        config.set("setting", "wg_config_file", selected_conf)
        config.set("setting", "endpoint", endpoint)
        config.write(f)

def save_client_endpoint(username, endpoint):
    os.makedirs('files/connections', exist_ok=True)
    file_path = os.path.join('files', 'connections', f'{username}_ip.json')
    timestamp = datetime.now().strftime('%d.%m.%Y %H:%M')
    ip_address = endpoint.split(':')[0]

    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    else:
        data = {}

    data[ip_address] = timestamp

    with open(file_path, 'w') as f:
        json.dump(data, f)

def get_config(path='files/setting.ini'):
    if not os.path.exists(path):
        create_config(path)

    config = configparser.ConfigParser()
    config.read(path)
    out = {}
    for key in config['setting']:
        out[key] = config['setting'][key]
    return out

def get_wg_cmd():
    setting = get_config()
    wg_config_file = setting['wg_config_file']
    if 'amnezia' in wg_config_file.lower():
        return 'awg'
    else:
        return 'wg'

def root_add(id_user, ipv6=False):
    setting = get_config()
    endpoint = setting['endpoint']
    wg_config_file = setting['wg_config_file']
    WG_CMD = get_wg_cmd()

    if ipv6:
        cmd = ["./newclient.sh", id_user, endpoint, wg_config_file, WG_CMD, 'ipv6']
    else:
        cmd = ["./newclient.sh", id_user, endpoint, wg_config_file, WG_CMD]

    if subprocess.call(cmd) == 0:
        return True
    return False

def get_client_list():
    setting = get_config()
    wg_config_file = setting['wg_config_file']

    try:
        call = subprocess.check_output(f"awk '/# BEGIN_PEER/ {{print $3}}' {wg_config_file}",
                                       shell=True)
        client_list = call.decode('utf-8').strip().split('\n')

        call = subprocess.check_output(f"awk '/AllowedIPs/ {{sub(/AllowedIPs = /,\"\"); print}}' {wg_config_file}",
                                       shell=True)
        ip_list = call.decode('utf-8').strip().split('\n')

        return [[client, ip_list[n].strip()] for n, client in enumerate(client_list) if client]
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при получении списка клиентов: {e}")
        return []

def get_active_list():
    setting = get_config()
    wg_config_file = setting['wg_config_file']
    WG_CMD = get_wg_cmd()

    try:
        call = subprocess.check_output(f"awk '/^# BEGIN_PEER / {{peer=$3}} /^PublicKey/ {{print peer, $3}}' {wg_config_file}",
                                       shell=True)
        client_data = call.decode('utf-8').strip().split('\n')

        client_key = {}
        for data in client_data:
            if data:
                name, peer = data.split(' ')
                client_key[peer.strip()] = name

        call = subprocess.check_output(f"{WG_CMD} | awk '/peer/ {{peer=$2}} /latest handshake/ {{last=$0}} /endpoint/ {{end=$2}} /transfer:/ {{print $0, \"|\", peer, \"|\", last, \"|\", end}}'",
                                       shell=True)
        client_list = call.decode('utf-8').strip().split('\n')

        keys = {}
        for client in client_list:
            if client:
                parts = client.split('|')
                if len(parts) < 4:
                    continue
                transfer, key, last_time, endpoint = parts[:4]
                keys[key.strip()] = (last_time.strip().split(':', 1)[1], transfer.strip(), endpoint.strip())

        active_clients = []
        for key in keys.keys():
            if key in client_key:
                username = client_key[key]
                last_time, transfer, endpoint = keys[key]
                save_client_endpoint(username, endpoint)
                active_clients.append([username, last_time, transfer, endpoint])

        return active_clients

    except subprocess.CalledProcessError as e:
        print(f"Ошибка при получении активных клиентов: {e}")
        return []

def deactive_user_db(id_user):
    setting = get_config()
    wg_config_file = setting['wg_config_file']
    WG_CMD = get_wg_cmd()

    id_user = str(id_user)
    if subprocess.call(["./removeclient.sh", id_user, wg_config_file, WG_CMD]) == 0:
        return True
    return False

def load_expirations():
    if not os.path.exists(EXPIRATIONS_FILE):
        return {}
    with open(EXPIRATIONS_FILE, 'r') as f:
        try:
            data = json.load(f)
            for user, timestamp in data.items():
                if timestamp:
                    data[user] = datetime.fromisoformat(timestamp).replace(tzinfo=UTC)
                else:
                    data[user] = None
            return data
        except json.JSONDecodeError:
            return {}

def save_expirations(expirations):
    os.makedirs(os.path.dirname(EXPIRATIONS_FILE), exist_ok=True)
    data = {user: (ts.isoformat() if ts else None) for user, ts in expirations.items()}
    with open(EXPIRATIONS_FILE, 'w') as f:
        json.dump(data, f)

def set_user_expiration(username: str, expiration: datetime):
    expirations = load_expirations()
    if expiration:
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)
        expirations[username] = expiration
    else:
        expirations[username] = None
    save_expirations(expirations)

def remove_user_expiration(username: str):
    expirations = load_expirations()
    if username in expirations:
        del expirations[username]
        save_expirations(expirations)

def get_users_with_expiration():
    expirations = load_expirations()
    return [(user, ts.isoformat() if ts else None) for user, ts in expirations.items()]

def get_user_expiration(username: str):
    expirations = load_expirations()
    return expirations.get(username, None)
