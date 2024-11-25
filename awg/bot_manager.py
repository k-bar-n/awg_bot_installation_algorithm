import db
import aiohttp
import logging
import asyncio
import aiofiles
import os
import re
import tempfile
import json
import subprocess
from aiogram import Bot, types
from aiogram.dispatcher import Dispatcher
from aiogram.utils import executor
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from datetime import datetime, timedelta
import pytz
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
import ipaddress
import zipfile

setting = db.get_config()
bot = Bot(setting['bot_token'])
admin = int(setting['admin_id'])
WG_CONFIG_FILE = setting['wg_config_file']

if 'amnezia' in WG_CONFIG_FILE.lower():
    WG_CMD = 'awg'
    WG_QUICK_CMD = 'awg-quick'
else:
    WG_CMD = 'wg'
    WG_QUICK_CMD = 'wg-quick'

dp = Dispatcher(bot)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler(timezone=pytz.UTC)
scheduler.start()

main_menu_markup = InlineKeyboardMarkup(row_width=1).add(
    InlineKeyboardButton("Добавить пользователя", callback_data="add_user"),
    InlineKeyboardButton("Получить конфигурацию пользователя", callback_data="get_config"),
    InlineKeyboardButton("Список клиентов", callback_data="list_users"),
    InlineKeyboardButton("Создать бекап", callback_data="create_backup")
)

user_main_messages = {}
isp_cache = {}
ISP_CACHE_FILE = 'files/isp_cache.json'
CACHE_TTL = timedelta(hours=24)

async def load_isp_cache():
    global isp_cache
    if os.path.exists(ISP_CACHE_FILE):
        async with aiofiles.open(ISP_CACHE_FILE, 'r') as f:
            try:
                isp_cache = json.loads(await f.read())
                for ip in list(isp_cache.keys()):
                    isp_cache[ip]['timestamp'] = datetime.fromisoformat(isp_cache[ip]['timestamp'])
            except:
                isp_cache = {}

async def save_isp_cache():
    async with aiofiles.open(ISP_CACHE_FILE, 'w') as f:
        cache_to_save = {ip: {'isp': data['isp'], 'timestamp': data['timestamp'].isoformat()} for ip, data in isp_cache.items()}
        await f.write(json.dumps(cache_to_save))

async def get_isp_info(ip: str) -> str:
    now = datetime.now(pytz.UTC)
    if ip in isp_cache:
        if now - isp_cache[ip]['timestamp'] < CACHE_TTL:
            return isp_cache[ip]['isp']
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Private Range"
    except:
        return "Invalid IP"
    url = f"http://ip-api.com/json/{ip}?fields=status,message,isp"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('status') == 'success':
                        isp = data.get('isp', 'Unknown ISP')
                        isp_cache[ip] = {'isp': isp, 'timestamp': now}
                        await save_isp_cache()
                        return isp
    except:
        pass
    return "Unknown ISP"

async def cleanup_isp_cache():
    now = datetime.now(pytz.UTC)
    for ip in list(isp_cache.keys()):
        if now - isp_cache[ip]['timestamp'] >= CACHE_TTL:
            del isp_cache[ip]
    await save_isp_cache()

async def cleanup_connection_data(username: str):
    file_path = os.path.join('files', 'connections', f'{username}_ip.json')
    if os.path.exists(file_path):
        async with aiofiles.open(file_path, 'r') as f:
            try:
                data = json.loads(await f.read())
            except:
                data = {}
        sorted_ips = sorted(data.items(), key=lambda x: datetime.strptime(x[1], '%d.%m.%Y %H:%M'), reverse=True)
        limited_ips = dict(sorted_ips[:100])
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(json.dumps(limited_ips))

async def load_isp_cache_task():
    await load_isp_cache()
    scheduler.add_job(cleanup_isp_cache, 'interval', hours=1)

def get_ipv6_subnet():
    try:
        with open(WG_CONFIG_FILE, 'r') as f:
            in_interface = False
            for line in f:
                line = line.strip()
                if line.startswith('[Interface]'):
                    in_interface = True
                    continue
                if in_interface:
                    if line.startswith('Address'):
                        addresses = line.split('=')[1].strip().split(',')
                        for addr in addresses:
                            addr = addr.strip()
                            if ':' in addr:
                                parts = addr.split('/')
                                if len(parts) == 2:
                                    ip, mask = parts
                                    prefix = re.sub(r'::[0-9a-fA-F]+$', '::', ip)
                                    return f"{prefix}/64"
                        return None
                    elif line.startswith('['):
                        break
    except:
        return None

def is_user_blocked(username):
    try:
        with open(WG_CONFIG_FILE, 'r') as f:
            config = f.read()
        pattern = rf'(# BEGIN_PEER {username}\n)(.*?\n)(# END_PEER {username})'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            peer_block = match.group(2)
            lines = peer_block.strip().split('\n')
            if all(line.strip().startswith('#') or line.strip() == '' for line in lines):
                return True
            else:
                return False
        else:
            return False
    except:
        return False

async def block_user(username):
    try:
        async with aiofiles.open(WG_CONFIG_FILE, 'r') as f:
            config = await f.read()
        pattern = rf'(# BEGIN_PEER {username}\n)(.*?)(# END_PEER {username})'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            start = match.group(1)
            peer_block = match.group(2)
            end = match.group(3)
            lines = peer_block.splitlines(keepends=True)
            commented_lines = [f'# {line}' if not line.strip().startswith('#') else line for line in lines]
            commented_block = ''.join(commented_lines)
            new_block = f'{start}{commented_block}{end}'
            config = config.replace(match.group(0), new_block)
        else:
            return False
        async with aiofiles.open(WG_CONFIG_FILE, 'w') as f:
            await f.write(config)
        success = await restart_wireguard()
        if not success:
            return False
        return True
    except:
        return False

async def unblock_user(username):
    try:
        async with aiofiles.open(WG_CONFIG_FILE, 'r') as f:
            config = await f.read()
        pattern = rf'(# BEGIN_PEER {username}\n)(.*?)(# END_PEER {username})'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            start = match.group(1)
            peer_block = match.group(2)
            end = match.group(3)
            lines = peer_block.splitlines(keepends=True)
            uncommented_lines = [line.lstrip('# ').rstrip('\n') + '\n' for line in lines]
            uncommented_block = ''.join(uncommented_lines)
            new_block = f'{start}{uncommented_block}{end}'
            config = config.replace(match.group(0), new_block)
        else:
            return False
        async with aiofiles.open(WG_CONFIG_FILE, 'w') as f:
            await f.write(config)
        success = await restart_wireguard()
        if not success:
            return False
        return True
    except:
        return False

async def restart_wireguard():
    try:
        interface_name = os.path.basename(WG_CONFIG_FILE).split('.')[0]
        process_strip = await asyncio.create_subprocess_shell(
            f'{WG_QUICK_CMD} strip {interface_name}',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_strip, stderr_strip = await process_strip.communicate()
        if process_strip.returncode != 0:
            logger.error(f"Strip WireGuard конфигурации не удался: {stderr_strip.decode()}")
            return False
        with tempfile.NamedTemporaryFile(delete=False) as temp_config:
            temp_config.write(stdout_strip)
            temp_config_path = temp_config.name
        process_syncconf = await asyncio.create_subprocess_shell(
            f'{WG_CMD} syncconf {interface_name} {temp_config_path}',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_syncconf, stderr_syncconf = await process_syncconf.communicate()
        if process_syncconf.returncode != 0:
            os.unlink(temp_config_path)
            logger.error(f"Syncconf WireGuard не удался: {stderr_syncconf.decode()}")
            return False
        os.unlink(temp_config_path)
        return True
    except Exception as e:
        logger.error(f"Ошибка при перезапуске WireGuard: {e}")
        return False

def create_zip(backup_filepath):
    with zipfile.ZipFile(backup_filepath, 'w') as zipf:
        for main_file in ['awg-decode.py', 'newclient.sh', 'removeclient.sh']:
            if os.path.exists(main_file):
                zipf.write(main_file, main_file)
        for root, dirs, files in os.walk('files'):
            for file in files:
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, os.getcwd())
                zipf.write(filepath, arcname)
        for root, dirs, files in os.walk('users'):
            for file in files:
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, os.getcwd())
                zipf.write(filepath, arcname)

async def delete_message_after_delay(chat_id: int, message_id: int, delay: int):
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, message_id)
    except:
        pass

@dp.message_handler(commands=['start', 'help'])
async def help_command_handler(message: types.Message):
    if message.chat.id == admin:
        sent_message = await message.answer("Выберите действие:", reply_markup=main_menu_markup)
        user_main_messages[admin] = (sent_message.chat.id, sent_message.message_id)
        try:
            await bot.pin_chat_message(chat_id=message.chat.id, message_id=sent_message.message_id, disable_notification=True)
        except:
            pass
    else:
        await message.answer("У вас нет доступа к этому боту.")

@dp.message_handler()
async def handle_messages(message: types.Message):
    if message.chat.id != admin:
        await message.answer("У вас нет доступа к этому боту.")
        return
    if user_main_messages.get('waiting_for_user_name'):
        user_name = message.text.strip()
        if not all(c.isalnum() or c in "-_" for c in user_name):
            await message.reply("Имя пользователя может содержать только буквы, цифры, дефисы и подчёркивания.")
            asyncio.create_task(delete_message_after_delay(message.chat.id, message.message_id, delay=5))
            return
        user_main_messages['client_name'] = user_name
        user_main_messages['waiting_for_user_name'] = False
        ipv6_subnet = get_ipv6_subnet()
        if ipv6_subnet:
            connect_buttons = [
                InlineKeyboardButton("С IPv6", callback_data=f'connect_{user_name}_ipv6'),
                InlineKeyboardButton("Без IPv6", callback_data=f'connect_{user_name}_noipv6'),
                InlineKeyboardButton("Домой", callback_data="home")
            ]
            connect_markup = InlineKeyboardMarkup(row_width=1).add(*connect_buttons)
            main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
            if main_chat_id and main_message_id:
                await bot.edit_message_text(
                    chat_id=main_chat_id,
                    message_id=main_message_id,
                    text=f"Выберите тип подключения для пользователя **{user_name}**:",
                    parse_mode="Markdown",
                    reply_markup=connect_markup
                )
            else:
                await message.answer("Ошибка: главное сообщение не найдено.")
        else:
            user_main_messages['ipv6'] = 'noipv6'
            duration_buttons = [
                InlineKeyboardButton("1 час", callback_data=f"duration_1h_{user_name}_noipv6"),
                InlineKeyboardButton("1 день", callback_data=f"duration_1d_{user_name}_noipv6"),
                InlineKeyboardButton("1 неделя", callback_data=f"duration_1w_{user_name}_noipv6"),
                InlineKeyboardButton("1 месяц", callback_data=f"duration_1m_{user_name}_noipv6"),
                InlineKeyboardButton("Без ограничений", callback_data=f"duration_unlimited_{user_name}_noipv6"),
                InlineKeyboardButton("Домой", callback_data="home")
            ]
            duration_markup = InlineKeyboardMarkup(row_width=1).add(*duration_buttons)
            main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
            if main_chat_id and main_message_id:
                await bot.edit_message_text(
                    chat_id=main_chat_id,
                    message_id=main_message_id,
                    text=f"Выберите время действия конфигурации для пользователя **{user_name}**:",
                    parse_mode="Markdown",
                    reply_markup=duration_markup
                )
            else:
                await message.answer("Ошибка: главное сообщение не найдено.")
    else:
        await message.reply("Неизвестная команда или действие.")

@dp.callback_query_handler(lambda c: c.data == "add_user")
async def prompt_for_user_name(callback_query: types.CallbackQuery):
    if callback_query.from_user.id != admin:
        await callback_query.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        await bot.edit_message_text(
            chat_id=main_chat_id,
            message_id=main_message_id,
            text="Введите имя пользователя для добавления:",
            reply_markup=InlineKeyboardMarkup().add(
                InlineKeyboardButton("Домой", callback_data="home")
            )
        )
        user_main_messages['waiting_for_user_name'] = True
    else:
        await callback_query.answer("Ошибка: главное сообщение не найдено.", show_alert=True)
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('connect_'))
async def connect_user(callback: types.CallbackQuery):
    if callback.from_user.id != admin:
        await callback.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    try:
        _, client_name, ipv6_flag = callback.data.split('_', 2)
    except ValueError:
        await callback.answer("Неверный формат команды.", show_alert=True)
        return
    user_main_messages['client_name'] = client_name
    user_main_messages['ipv6'] = ipv6_flag
    duration_buttons = [
        InlineKeyboardButton("1 час", callback_data=f"duration_1h_{client_name}_{ipv6_flag}"),
        InlineKeyboardButton("1 день", callback_data=f"duration_1d_{client_name}_{ipv6_flag}"),
        InlineKeyboardButton("1 неделя", callback_data=f"duration_1w_{client_name}_{ipv6_flag}"),
        InlineKeyboardButton("1 месяц", callback_data=f"duration_1m_{client_name}_{ipv6_flag}"),
        InlineKeyboardButton("Без ограничений", callback_data=f"duration_unlimited_{client_name}_{ipv6_flag}"),
        InlineKeyboardButton("Домой", callback_data="home")
    ]
    duration_markup = InlineKeyboardMarkup(row_width=1).add(*duration_buttons)
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        await bot.edit_message_text(
            chat_id=main_chat_id,
            message_id=main_message_id,
            text="Выберите время действия конфигурации:",
            parse_mode="Markdown",
            reply_markup=duration_markup
        )
    else:
        await callback.answer("Ошибка: главное сообщение не найдено.", show_alert=True)
    await callback.answer()

def parse_relative_time(time_str):
    now = datetime.now(pytz.UTC)
    delta = timedelta()
    parts = time_str.strip().split(',')
    for part in parts:
        part = part.strip()
        match = re.match(r'(\d+)\s+(day|hour|minute|second)s?', part)
        if match:
            value = int(match.group(1))
            unit = match.group(2)
            if unit == 'day':
                delta += timedelta(days=value)
            elif unit == 'hour':
                delta += timedelta(hours=value)
            elif unit == 'minute':
                delta += timedelta(minutes=value)
            elif unit == 'second':
                delta += timedelta(seconds=value)
    last_handshake_time = now - delta
    return last_handshake_time

@dp.callback_query_handler(lambda c: c.data.startswith('duration_'))
async def set_config_duration(callback: types.CallbackQuery):
    if callback.from_user.id != admin:
        await callback.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    parts = callback.data.split('_')
    duration_choice = parts[1]
    client_name = parts[2]
    ipv6_flag = parts[3] if len(parts) > 3 else 'noipv6'
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if not main_chat_id or not main_message_id:
        await callback.answer("Ошибка: главное сообщение не найдено.", show_alert=True)
        return
    if duration_choice == '1h':
        duration = timedelta(hours=1)
    elif duration_choice == '1d':
        duration = timedelta(days=1)
    elif duration_choice == '1w':
        duration = timedelta(weeks=1)
    elif duration_choice == '1m':
        duration = timedelta(days=30)
    elif duration_choice == 'unlimited':
        duration = None
    else:
        await bot.send_message(admin, "Неверный выбор времени.", reply_markup=main_menu_markup, disable_notification=True)
        asyncio.create_task(delete_message_after_delay(admin, main_message_id, delay=2))
        return
    if ipv6_flag == 'ipv6':
        success = db.root_add(client_name, ipv6=True)
    else:
        success = db.root_add(client_name, ipv6=False)
    if success:
        try:
            conf_path = os.path.join('users', client_name, f'{client_name}.conf')
            png_path = os.path.join('users', client_name, f'{client_name}.png')
            
            if os.path.exists(png_path):
                with open(png_path, 'rb') as photo:
                    sent_photo = await bot.send_photo(admin, photo, disable_notification=True)
                    asyncio.create_task(delete_message_after_delay(admin, sent_photo.message_id, delay=15))
            
            vpn_key = ""
            if os.path.exists(conf_path):
                vpn_key = await generate_vpn_key(conf_path)
            
            if vpn_key:
                instruction_text = (
                    "\nWireGuard [Google play](https://play.google.com/store/apps/details?id=com.wireguard.android)\n"
                    "AmneziaWG [Google play](https://play.google.com/store/apps/details?id=org.amnezia.awg&hl=ru), "
                    "[GitHub](https://github.com/amnezia-vpn/amneziawg-android)\n"
                    "AmneziaVPN [Google play](https://play.google.com/store/apps/details?id=org.amnezia.vpn&hl=ru), "
                    "[GitHub](https://github.com/amnezia-vpn/amnezia-client)\n"
                )
                caption = f"\n{instruction_text}\n```{vpn_key}```"
            else:
                caption = "VPN ключ не был сгенерирован."
    
            if os.path.exists(conf_path):
                with open(conf_path, 'rb') as config:
                    sent_doc = await bot.send_document(
                        admin,
                        config,
                        caption=caption,
                        parse_mode="Markdown",
                        disable_notification=True
                    )
                    asyncio.create_task(delete_message_after_delay(admin, sent_doc.message_id, delay=15))
        
        except FileNotFoundError:
            confirmation_text = "Не удалось найти файлы конфигурации для указанного пользователя."
            sent_message = await bot.send_message(admin, confirmation_text, parse_mode="Markdown", disable_notification=True)
            asyncio.create_task(delete_message_after_delay(admin, sent_message.message_id, delay=15))
            await callback_query.answer()
            return
        except Exception as e:
            confirmation_text = "Произошла ошибка."
            sent_message = await bot.send_message(admin, confirmation_text, parse_mode="Markdown", disable_notification=True)
            asyncio.create_task(delete_message_after_delay(admin, sent_message.message_id, delay=15))
            await callback_query.answer()
            return
        if duration:
            expiration_time = datetime.now(pytz.UTC) + duration
            scheduler.add_job(
                deactivate_user,
                trigger=DateTrigger(run_date=expiration_time),
                args=[client_name],
                id=client_name
            )
            db.set_user_expiration(client_name, expiration_time)
            confirmation_text = f"Пользователь **{client_name}** добавлен. Конфигурация истечет через **{duration_choice}**."
        else:
            db.set_user_expiration(client_name, None)
            confirmation_text = f"Пользователь **{client_name}** добавлен с неограниченным временем действия."
        sent_confirmation = await bot.send_message(
            chat_id=admin,
            text=confirmation_text,
            parse_mode="Markdown",
            disable_notification=True
        )
        asyncio.create_task(delete_message_after_delay(admin, sent_confirmation.message_id, delay=15))
    else:
        confirmation_text = "Не удалось добавить пользователя."
        sent_confirmation = await bot.send_message(
            chat_id=admin,
            text=confirmation_text,
            parse_mode="Markdown",
            disable_notification=True
        )
        asyncio.create_task(delete_message_after_delay(admin, sent_confirmation.message_id, delay=15))
    await bot.edit_message_text(
        chat_id=main_chat_id,
        message_id=main_message_id,
        text="Выберите действие:",
        reply_markup=main_menu_markup
    )
    await callback.answer()

async def generate_vpn_key(conf_path: str) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            'python3.11',
            'awg-decode.py',
            '--encode',
            conf_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(f"awg-decode.py ошибка: {stderr.decode().strip()}")
            return ""
        vpn_key = stdout.decode().strip()
        if vpn_key.startswith('vpn://'):
            return vpn_key
        else:
            logger.error(f"awg-decode.py вернул некорректный формат: {vpn_key}")
            return ""
    except Exception as e:
        logger.error(f"Ошибка при вызове awg-decode.py: {e}")
        return ""

@dp.callback_query_handler(lambda c: c.data.startswith('list_users'))
async def list_users_callback(callback_query: types.CallbackQuery):
    if callback_query.from_user.id != admin:
        await callback_query.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    clients = db.get_client_list()
    if not clients:
        await callback_query.answer("Список пользователей пуст.", show_alert=True)
        return
    active_clients = db.get_active_list()
    active_clients_dict = {}
    for client in active_clients:
        username = client[0]
        last_handshake = client[1]
        active_clients_dict[username] = last_handshake
    keyboard = InlineKeyboardMarkup(row_width=2)
    now = datetime.now(pytz.UTC)
    for client in clients:
        username = client[0]
        last_handshake_str = active_clients_dict.get(username)
        if last_handshake_str:
            last_handshake = parse_relative_time(last_handshake_str)
        else:
            last_handshake = None
        if last_handshake:
            delta = now - last_handshake
            if delta <= timedelta(days=5):
                status_symbol = '✅'
            else:
                status_symbol = '❌'
        else:
            status_symbol = '❌'
        button_text = f"{status_symbol} {username}"
        keyboard.insert(InlineKeyboardButton(button_text, callback_data=f"client_{username}"))
    keyboard.add(InlineKeyboardButton("Домой", callback_data="home"))
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        await bot.edit_message_text(
            chat_id=main_chat_id,
            message_id=main_message_id,
            text="Выберите пользователя:",
            reply_markup=keyboard
        )
    else:
        sent_message = await callback_query.message.reply("Выберите пользователя:", reply_markup=keyboard)
        user_main_messages[admin] = (sent_message.chat.id, sent_message.message_id)
        try:
            await bot.pin_chat_message(chat_id=sent_message.chat.id, message_id=sent_message.message_id, disable_notification=True)
        except:
            pass
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('client_'))
async def client_selected_callback(callback_query: types.CallbackQuery):
    _, username = callback_query.data.split('client_', 1)
    username = username.strip()
    clients = db.get_client_list()
    client_info = next((c for c in clients if c[0] == username), None)
    if not client_info:
        await callback_query.answer("Ошибка: пользователь не найден.", show_alert=True)
        return
    is_blocked = is_user_blocked(username)
    expiration_time = db.get_user_expiration(username)
    text = f"*Информация о пользователе {username}:*\n"
    if client_info[1]:
        ip_addresses = client_info[1].split(',')
        for ip in ip_addresses:
            ip = ip.strip()
            if not ip:
                continue
            if '/' in ip:
                ip_adr, mask = ip.split('/', 1)
                ip_with_mask = f"{ip_adr}/{mask}"
            else:
                ip_adr = ip
                mask = ''
                ip_with_mask = ip_adr
            if ':' in ip_adr:
                text += f'  IPv6: {ip_with_mask}\n'
            elif '.' in ip_adr:
                text += f'  IPv4: {ip_with_mask}\n'
            else:
                text += f'  IP: {ip_with_mask}\n'
    else:
        text += '  Нет IP-адресов.\n'
    active_clients = db.get_active_list()
    active_info = next((ac for ac in active_clients if ac[0] == username), None)
    if active_info:
        name, last_time, transfer, endpoint = active_info
        text += f'  Последнее подключение: {last_time}\n'
        text += f'  Передача данных: {transfer}\n'
        text += f'  Endpoint: {endpoint}\n'
    else:
        text += '  Нет активных подключений.\n'
    if expiration_time:
        now = datetime.now(pytz.UTC)
        expiration_dt = expiration_time
        if expiration_dt.tzinfo is None:
            expiration_dt = expiration_dt.replace(tzinfo=pytz.UTC)
        remaining = expiration_dt - now
        if remaining.total_seconds() > 0:
            days, seconds = remaining.days, remaining.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            text += f'  Оставшееся время: {days}д {hours}ч {minutes}м\n'
    if is_blocked:
        text += '\n*Статус:* 🔴 Заблокирован'
    else:
        text += '\n*Статус:* 🟢 Активен'
    keyboard = InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        InlineKeyboardButton("IP info", callback_data=f"ip_info_{username}"),
        InlineKeyboardButton("Подключения", callback_data=f"connections_{username}")
    )
    keyboard.add(
        InlineKeyboardButton("Удалить", callback_data=f"delete_user_{username}"),
        InlineKeyboardButton("Разблокировать" if is_blocked else "Заблокировать", callback_data=f"{'unblock' if is_blocked else 'block'}_user_{username}"),
    )
    keyboard.add(
        InlineKeyboardButton("Назад", callback_data="list_users"),
        InlineKeyboardButton("Домой", callback_data="home")
    )
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        try:
            await bot.edit_message_text(
                chat_id=main_chat_id,
                message_id=main_message_id,
                text=text,
                parse_mode="Markdown",
                reply_markup=keyboard
            )
        except:
            pass
    else:
        await callback_query.answer("Ошибка: главное сообщение не найдено.", show_alert=True)
        return
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('connections_'))
async def client_connections_callback(callback_query: types.CallbackQuery):
    _, username = callback_query.data.split('connections_', 1)
    username = username.strip()
    file_path = os.path.join('files', 'connections', f'{username}_ip.json')
    if not os.path.exists(file_path):
        await callback_query.answer("Нет данных о подключениях пользователя.", show_alert=True)
        return
    try:
        async with aiofiles.open(file_path, 'r') as f:
            data = json.loads(await f.read())
        sorted_ips = sorted(data.items(), key=lambda x: datetime.strptime(x[1], '%d.%m.%Y %H:%M'), reverse=True)
        last_connections = sorted_ips[:5]
        isp_tasks = [get_isp_info(ip) for ip, _ in last_connections]
        isp_results = await asyncio.gather(*isp_tasks)
        connections_text = f"*Последние подключения пользователя {username}:*\n"
        for (ip, timestamp), isp in zip(last_connections, isp_results):
            connections_text += f"{ip} ({isp}) - {timestamp}\n"
        keyboard = InlineKeyboardMarkup(row_width=2)
        keyboard.add(
            InlineKeyboardButton("Назад", callback_data=f"client_{username}"),
            InlineKeyboardButton("Домой", callback_data="home")
        )
        await bot.edit_message_text(
            chat_id=callback_query.message.chat.id,
            message_id=callback_query.message.message_id,
            text=connections_text,
            parse_mode="Markdown",
            reply_markup=keyboard
        )
    except:
        await callback_query.answer("Ошибка при получении данных о подключениях.", show_alert=True)
        return
    await cleanup_connection_data(username)
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('ip_info_'))
async def ip_info_callback(callback_query: types.CallbackQuery):
    _, username = callback_query.data.split('ip_info_', 1)
    username = username.strip()

    active_clients = db.get_active_list()
    active_info = next((ac for ac in active_clients if ac[0] == username), None)
    if active_info:
        endpoint = active_info[3]
        ip_address = endpoint.split(':')[0]
    else:
        await callback_query.answer("Нет информации о подключении пользователя.", show_alert=True)
        return

    url = f"http://ip-api.com/json/{ip_address}?fields=message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if 'message' in data:
                        await callback_query.answer(f"Ошибка при получении данных: {data['message']}", show_alert=True)
                        return
                else:
                    await callback_query.answer(f"Ошибка при запросе к API: {resp.status}", show_alert=True)
                    return
    except Exception as e:
        logger.error(f"Ошибка при запросе к API: {e}")
        await callback_query.answer("Ошибка при запросе к API.", show_alert=True)
        return

    info_text = f"*IP информация для {username}:*\n"
    for key, value in data.items():
        info_text += f"{key.capitalize()}: {value}\n"

    keyboard = InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        InlineKeyboardButton("Назад", callback_data=f"client_{username}"),
        InlineKeyboardButton("Домой", callback_data="home")
    )

    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        try:
            await bot.edit_message_text(
                chat_id=main_chat_id,
                message_id=main_message_id,
                text=info_text,
                parse_mode="Markdown",
                reply_markup=keyboard
            )
        except Exception as e:
            logger.error(f"Ошибка при изменении сообщения: {e}")
            await callback_query.answer("Ошибка при обновлении сообщения.", show_alert=True)
            return
    else:
        await callback_query.answer("Ошибка: главное сообщение не найдено.", show_alert=True)
        return

    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('delete_user_'))
async def client_delete_callback(callback_query: types.CallbackQuery):
    username = callback_query.data.split('delete_user_')[1]
    success = db.deactive_user_db(username)
    if success:
        db.remove_user_expiration(username)
        try:
            scheduler.remove_job(job_id=username)
        except:
            pass
        conf_path = os.path.join('users', username, f'{username}.conf')
        png_path = os.path.join('users', username, f'{username}.png')
        try:
            if os.path.exists(conf_path):
                os.remove(conf_path)
            if os.path.exists(png_path):
                os.remove(png_path)
        except Exception as e:
            logger.error(f"Ошибка при удалении файлов для пользователя {username}: {e}")
        confirmation_text = f"Пользователь **{username}** успешно удален."
    else:
        confirmation_text = f"Не удалось удалить пользователя **{username}**."
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        await bot.edit_message_text(
            chat_id=main_chat_id,
            message_id=main_message_id,
            text=confirmation_text,
            parse_mode="Markdown",
            reply_markup=main_menu_markup
        )
    else:
        await callback_query.answer("Ошибка: главное сообщение не найдено.", show_alert=True)
        return
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('block_user_') or c.data.startswith('unblock_user_'))
async def client_block_callback(callback_query: types.CallbackQuery):
    data = callback_query.data
    if data.startswith('block_user_'):
        action = 'block'
        username = data.split('block_user_')[1]
    elif data.startswith('unblock_user_'):
        action = 'unblock'
        username = data.split('unblock_user_')[1]
    else:
        await callback_query.answer("Неверная команда.", show_alert=True)
        return

    if action == 'block':
        success = await block_user(username)
        if not success:
            confirmation_text = f"Не удалось заблокировать пользователя **{username}**."
        else:
            confirmation_text = None
    else:
        success = await unblock_user(username)
        if not success:
            confirmation_text = f"Не удалось разблокировать пользователя **{username}**."
        else:
            confirmation_text = None

    callback_query.data = f'client_{username}'
    await client_selected_callback(callback_query)

    if confirmation_text:
        sent_confirmation = await bot.send_message(
            chat_id=admin,
            text=confirmation_text,
            parse_mode="Markdown",
            disable_notification=True
        )
        asyncio.create_task(delete_message_after_delay(admin, sent_confirmation.message_id, delay=15))

    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "home")
async def return_home(callback_query: types.CallbackQuery):
    if callback_query.from_user.id != admin:
        await callback_query.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        user_main_messages.pop('waiting_for_user_name', None)
        user_main_messages.pop('client_name', None)
        user_main_messages.pop('ipv6', None)
        try:
            await bot.edit_message_text(
                chat_id=main_chat_id,
                message_id=main_message_id,
                text="Выберите действие:",
                reply_markup=main_menu_markup
            )
        except:
            sent_message = await callback_query.message.reply("Выберите действие:", reply_markup=main_menu_markup)
            user_main_messages[admin] = (sent_message.chat.id, sent_message.message_id)
            try:
                await bot.pin_chat_message(chat_id=sent_message.chat.id, message_id=sent_message.message_id, disable_notification=True)
            except:
                pass
    else:
        sent_message = await callback_query.message.reply("Выберите действие:", reply_markup=main_menu_markup)
        user_main_messages[admin] = (sent_message.chat.id, sent_message.message_id)
        try:
            await bot.pin_chat_message(chat_id=sent_message.chat.id, message_id=sent_message.message_id, disable_notification=True)
        except:
            pass
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "get_config")
async def list_users_for_config(callback_query: types.CallbackQuery):
    if callback_query.from_user.id != admin:
        await callback_query.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    clients = db.get_client_list()
    if not clients:
        await callback_query.answer("Список пользователей пуст.", show_alert=True)
        return
    keyboard = InlineKeyboardMarkup(row_width=2)
    for client in clients:
        username = client[0]
        keyboard.insert(InlineKeyboardButton(username, callback_data=f"send_config_{username}"))
    keyboard.add(InlineKeyboardButton("Домой", callback_data="home"))
    main_chat_id, main_message_id = user_main_messages.get(admin, (None, None))
    if main_chat_id and main_message_id:
        await bot.edit_message_text(
            chat_id=main_chat_id,
            message_id=main_message_id,
            text="Выберите пользователя для получения конфигурации:",
            reply_markup=keyboard
        )
    else:
        sent_message = await callback_query.message.reply("Выберите пользователя для получения конфигурации:", reply_markup=keyboard)
        user_main_messages[admin] = (sent_message.chat.id, sent_message.message_id)
        try:
            await bot.pin_chat_message(chat_id=sent_message.chat.id, message_id=sent_message.message_id, disable_notification=True)
        except:
            pass
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data.startswith('send_config_'))
async def send_user_config(callback_query: types.CallbackQuery):
    if callback_query.from_user.id != admin:
        await callback_query.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    _, username = callback_query.data.split('send_config_', 1)
    username = username.strip()
    sent_messages = []
    try:
        png_path = os.path.join('users', username, f'{username}.png')
        if os.path.exists(png_path):
            with open(png_path, 'rb') as photo:
                sent_photo = await bot.send_photo(admin, photo, disable_notification=True)
                sent_messages.append(sent_photo.message_id)

        conf_path = os.path.join('users', username, f'{username}.conf')
        if os.path.exists(conf_path):
            vpn_key = await generate_vpn_key(conf_path)
            if vpn_key:
                instruction_text = (
                    "\nWireGuard [Google play](https://play.google.com/store/apps/details?id=com.wireguard.android)\n"
                    "AmneziaWG [Google play](https://play.google.com/store/apps/details?id=org.amnezia.awg&hl=ru), "
                    "[GitHub](https://github.com/amnezia-vpn/amneziawg-android)\n"
                    "AmneziaVPN [Google play](https://play.google.com/store/apps/details?id=org.amnezia.vpn&hl=ru), "
                    "[GitHub](https://github.com/amnezia-vpn/amnezia-client)\n"
                )
                caption = f"\n{instruction_text}\n```{vpn_key}```"
            else:
                caption = "VPN ключ не был сгенерирован."

            with open(conf_path, 'rb') as config:
                sent_doc = await bot.send_document(
                    admin,
                    config,
                    caption=caption,
                    parse_mode="Markdown",
                    disable_notification=True
                )
                sent_messages.append(sent_doc.message_id)
        
    except Exception as e:
        confirmation_text = f"Произошла ошибка."
        sent_message = await bot.send_message(admin, confirmation_text, parse_mode="Markdown", disable_notification=True)
        asyncio.create_task(delete_message_after_delay(admin, sent_message.message_id, delay=15))
        await callback_query.answer()
        return

    if not sent_messages:
        confirmation_text = f"Не удалось найти файлы конфигурации для пользователя **{username}**."
        sent_message = await bot.send_message(admin, confirmation_text, parse_mode="Markdown", disable_notification=True)
        asyncio.create_task(delete_message_after_delay(admin, sent_message.message_id, delay=15))
        await callback_query.answer()
        return
    else:
        confirmation_text = f"Конфигурация для **{username}** отправлена."
        sent_confirmation = await bot.send_message(
            chat_id=admin,
            text=confirmation_text,
            parse_mode="Markdown",
            disable_notification=True
        )
        asyncio.create_task(delete_message_after_delay(admin, sent_confirmation.message_id, delay=15))
    
    for message_id in sent_messages:
        asyncio.create_task(delete_message_after_delay(admin, message_id, delay=15))
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "create_backup")
async def create_backup_callback(callback_query: types.CallbackQuery):
    if callback_query.from_user.id != admin:
        await callback_query.answer("У вас нет прав для выполнения этого действия.", show_alert=True)
        return
    date_str = datetime.now().strftime('%Y-%m-%d')
    backup_filename = f"backup_{date_str}.zip"
    backup_filepath = os.path.join(os.getcwd(), backup_filename)
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, create_zip, backup_filepath)
        if os.path.exists(backup_filepath):
            with open(backup_filepath, 'rb') as f:
                await bot.send_document(admin, f, caption=backup_filename, disable_notification=True)
        else:
            logger.error(f"Бекап файл не создан: {backup_filepath}")
            await bot.send_message(admin, "Не удалось создать бекап.", disable_notification=True)
    except Exception as e:
        logger.error(f"Ошибка при создании бекапа: {e}")
        await bot.send_message(admin, "Не удалось создать бекап.", disable_notification=True)
    await callback_query.answer()

@dp.callback_query_handler(lambda c: True)
async def process_unknown_callback(callback_query: types.CallbackQuery):
    await callback_query.answer("Неизвестная команда.", show_alert=True)

async def deactivate_user(client_name: str):
    success = db.deactive_user_db(client_name)
    if success:
        conf_path = os.path.join('users', client_name, f'{client_name}.conf')
        png_path = os.path.join('users', client_name, f'{client_name}.png')
        try:
            if os.path.exists(conf_path):
                os.remove(conf_path)
            if os.path.exists(png_path):
                os.remove(png_path)
        except Exception as e:
            logger.error(f"Ошибка при удалении файлов для пользователя {client_name}: {e}")
        sent_message = await bot.send_message(admin, f"Конфигурация пользователя **{client_name}** истекла и была деактивирована.", parse_mode="Markdown", disable_notification=True)
        asyncio.create_task(delete_message_after_delay(admin, sent_message.message_id, delay=15))
        db.remove_user_expiration(client_name)
    else:
        sent_message = await bot.send_message(admin, f"Не удалось деактивировать пользователя **{client_name}** по истечении времени.", parse_mode="Markdown", disable_notification=True)
        asyncio.create_task(delete_message_after_delay(admin, sent_message.message_id, delay=15))

async def on_startup(dp):
    os.makedirs('files/connections', exist_ok=True)
    os.makedirs('users', exist_ok=True)
    await load_isp_cache_task()
    users = db.get_users_with_expiration()
    for user in users:
        client_name, expiration_time = user
        if expiration_time:
            try:
                expiration_datetime = datetime.fromisoformat(expiration_time)
            except ValueError:
                continue
            if expiration_datetime.tzinfo is None:
                expiration_datetime = expiration_datetime.replace(tzinfo=pytz.UTC)
            if expiration_datetime > datetime.now(pytz.UTC):
                scheduler.add_job(
                    deactivate_user,
                    trigger=DateTrigger(run_date=expiration_datetime),
                    args=[client_name],
                    id=client_name
                )
            else:
                await deactivate_user(client_name)

executor.start_polling(dp, on_startup=on_startup)
