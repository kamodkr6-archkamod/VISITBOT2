import logging
import asyncio
import json
import binascii
import os
import sys
import urllib3
import threading
import time
import requests
import base64
import random
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ChatMember
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, CallbackQueryHandler, Application
from telegram.request import HTTPXRequest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
BOT_TOKEN = "8019676929:AAF4ikptwlqbQYuOprsvEZ4dJyRirbYVNwI"   

ADMIN_ID = 8138834246  
CHANNEL_LINK = "@KAMOD_CODEX"
GROUP_LINK = "@KAMOD_LIKE_GROUP"
MUST_JOIN_CHANNELS = ["@KAMOD_CODEX", "@KAMOD_CODEX_BACKUP"]

# Files
INPUT_VISIT = "account_visit.json"   # 🆕 Input File (ID:PASS)
OUTPUT_VISIT = "token_ind_visit.json" # Output File (Tokens)
LIMIT_FILE = "visit_limits.json"

# Refresh Config
TARGET_REGION = "IND"
REFRESH_INTERVAL = 10800 # 3 Hours

# Setup Logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)

# ==============================================================================
#             PART 1: AUTO JWT GENERATOR (NEW ADDITION)
# ==============================================================================
class AutoJWTGenerator:
    def __init__(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        
    def decode_jwt_token(self, jwt_token):
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                payload_part = parts[1]
                padding = 4 - len(payload_part) % 4
                if padding != 4: payload_part += '=' * padding
                decoded = base64.urlsafe_b64decode(payload_part)
                data = json.loads(decoded)
                account_id = data.get('account_id') or data.get('external_id')
                if account_id: return str(account_id)
        except Exception: pass
        return "N/A"
    
    def get_region_lang(self, region):
        region_lang = {"ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th", "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", "BR": "pt"}
        return region_lang.get(region.upper(), "en")

    def extract_jwt_from_majorlogin(self, uid, password, region):
        try:
            def encrypt_api(plain_text):
                plain_text = bytes.fromhex(plain_text)
                key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
                iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
                return cipher_text.hex()
            
            lang = self.get_region_lang(region)
            payload_parts = [
                b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
                lang.encode("ascii"),
                b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
            ]
            payload = b''.join(payload_parts)
            url = "https://loginbp.common.ggbluefox.com/MajorLogin" if region.upper() in ["ME", "TH"] else "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {
                "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
                "Host": "loginbp.common.ggbluefox.com" if region.upper() in ["ME", "TH"] else "loginbp.ggblueshark.com",
                "ReleaseVersion": "OB52", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
            }
            access_token, open_id = self.get_access_token_and_openid(uid, password)
            if not access_token or not open_id: return None
            
            data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            encrypted_data = encrypt_api(data.hex())
            final_payload = bytes.fromhex(encrypted_data)

            response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
            if response.status_code == 200 and len(response.text) > 10:
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    jwt_token = response.text[jwt_start:]
                    second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                    if second_dot != -1: return jwt_token[:second_dot + 44]
            return None
        except Exception: return None
    
    def get_access_token_and_openid(self, uid, password):
        try:
            import hmac
            import hashlib
            key = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()
            url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {"Accept-Encoding": "gzip", "Connection": "Keep-Alive", "Content-Type": "application/x-www-form-urlencoded", "Host": "100067.connect.garena.com", "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)"}
            body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": key, "client_id": "100067"}
            response = requests.post(url, headers=headers, data=body, timeout=20, verify=False)
            json_data = response.json()
            if 'open_id' in json_data and 'access_token' in json_data: return json_data['access_token'], json_data['open_id']
            return None, None
        except: return None, None

    def process_file_batch(self, input_file, output_file, thread_count=1):
        full_input_path = os.path.join(self.current_dir, input_file)
        full_output_path = os.path.join(self.current_dir, output_file)
        if not os.path.exists(full_input_path):
            print(f"{Fore.RED}⚠️ File not found: {input_file}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}🚀 Starting Batch: {input_file} | Threads: {thread_count}{Style.RESET_ALL}")
        try:
            with open(full_input_path, 'r', encoding='utf-8') as f: accounts = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}❌ JSON Error in {input_file}: {e}{Style.RESET_ALL}")
            return

        valid_tokens_list = []
        lock = threading.Lock()

        def worker(acc):
            uid = acc.get('uid')
            pwd = acc.get('password')
            if uid and pwd:
                token = None
                for attempt in range(1, 3):
                    token = self.extract_jwt_from_majorlogin(uid, pwd, TARGET_REGION)
                    if token: break
                    else: time.sleep(2)
                
                if token:
                    with lock: valid_tokens_list.append({"token": token})
                    print(f"{Fore.GREEN}✅ Generated: {uid}{Style.RESET_ALL}")
                else: print(f"{Fore.RED}❌ Failed: {uid}{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(worker, acc) for acc in accounts]
            for future in as_completed(futures): future.result()

        try:
            with open(full_output_path, 'w', encoding='utf-8') as f: json.dump(valid_tokens_list, f, indent=4)
            print(f"{Fore.CYAN}💾 Saved {len(valid_tokens_list)} tokens to {output_file}{Style.RESET_ALL}")
        except Exception as e: print(f"{Fore.RED}❌ Error saving file: {e}{Style.RESET_ALL}")

def run_auto_refresher():
    generator = AutoJWTGenerator()
    print(f"{Fore.CYAN}{Style.BRIGHT}=== AUTO TOKEN REFRESHER THREAD STARTED ==={Style.RESET_ALL}")
    while True:
        print(f"\n{Fore.MAGENTA}⏰ Starting Token Generation Cycle...{Style.RESET_ALL}")
        # Generate Visit Tokens (Fast 10 Threads)
        generator.process_file_batch(INPUT_VISIT, OUTPUT_VISIT, thread_count=10)
        
        print(f"\n{Fore.CYAN}😴 Cycle Complete. Sleeping for 3 Hours...{Style.RESET_ALL}")
        time.sleep(REFRESH_INTERVAL)

# ==============================================================================
#             PART 2: MEMORY & LIMITS
# ==============================================================================
MEM_TOKENS = [] 
USER_LIMITS = {}
LIMIT_LOCK = threading.Lock()
DAILY_LIMIT = 20  # 🔥 Limit set to 20 as per your poster

def refresh_tokens_ram():
    global MEM_TOKENS
    while True:
        try:
            if os.path.exists(OUTPUT_VISIT):
                with open(OUTPUT_VISIT, 'r') as f:
                    MEM_TOKENS = json.load(f)
        except Exception as e:
            print(f"Token Load Error: {e}")
        time.sleep(300) 

# --- LIMIT SYSTEM ---
def load_limits():
    global USER_LIMITS
    if os.path.exists(LIMIT_FILE):
        try:
            with open(LIMIT_FILE, "r") as f: USER_LIMITS = json.load(f)
        except: USER_LIMITS = {}

def save_limits():
    with LIMIT_LOCK:
        try:
            with open(LIMIT_FILE, "w") as f: json.dump(USER_LIMITS, f, indent=4)
        except: pass

def check_and_update_limit(user_id):
    """Checks usage. Returns (Allowed, Current_Count)."""
    if user_id == ADMIN_ID: return True, "∞"
    
    uid = str(user_id)
    now = time.time()
    
    with LIMIT_LOCK:
        history = USER_LIMITS.get(uid, [])
        # Keep timestamps from last 24h
        valid_history = [t for t in history if now - t < 86400]
        
        current_usage = len(valid_history)
        
        if current_usage >= DAILY_LIMIT:
            USER_LIMITS[uid] = valid_history
            save_limits()
            return False, current_usage
        
        # Add new usage
        valid_history.append(now)
        USER_LIMITS[uid] = valid_history
        save_limits()
        return True, current_usage + 1

# ==============================================================================
#             PART 3: FF ENCRYPTION & API
# ==============================================================================
import uid_generator_pb2
import like_count_pb2

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode('utf-8')

def create_profile_check_proto(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()

async def send_request(session, encrypted_data, token, url):
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive", 'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB52"
    }
    try:
        async with session.post(url, data=bytes.fromhex(encrypted_data), headers=headers, ssl=False) as response:
            return response.status
    except: return 999

# 🔥 Updated to fetch Name AND Likes
async def get_profile_data(uid, tokens):
    url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    proto = create_profile_check_proto(uid)
    enc_data = encrypt_message(proto)
    valid_tokens = [t for t in tokens if t.get('token')]
    
    if not valid_tokens: return "Unknown User", "0"
    
    sample = random.sample(valid_tokens, min(len(valid_tokens), 25))
    
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
        for t in sample:
            headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Authorization': f"Bearer {t['token']}",
                'Content-Type': "application/x-www-form-urlencoded",
                'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB52"
            }
            try:
                async with session.post(url, data=bytes.fromhex(enc_data), headers=headers, ssl=False) as r:
                    if r.status == 200:
                        content = await r.read()
                        items = like_count_pb2.Info()
                        items.ParseFromString(content)
                        return items.AccountInfo.PlayerNickname, str(items.AccountInfo.Likes)
            except: pass
    return "Unknown User", "0"

# ==============================================================================
#             PART 4: VISIT PROCESSOR
# ==============================================================================

async def process_visit_task(chat_id, uid, region, tokens, context, msg_id, usage_count):
    start_time = time.time()
    
    url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    enc_data = encrypt_message(create_profile_check_proto(uid))
    
    # Start fetching Name + Likes
    info_task = asyncio.create_task(get_profile_data(uid, tokens))
    
    sem = asyncio.Semaphore(60) 
    
    async def run_visits():
        async def bound_req(session, token):
            async with sem: 
                await asyncio.sleep(0.01)
                return await send_request(session, enc_data, token, url)
        
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
            tasks = [bound_req(session, t.get("token")) for t in tokens if t.get("token")]
            results = await asyncio.gather(*tasks)
            return results.count(200)

    visit_task = asyncio.create_task(run_visits())

    steps = [("█░░░░░░░░░", "10%"), ("███░░░░░░░", "30%"), ("██████░░░░", "60%"), ("████████░░", "80%"), ("██████████", "100%")]
    for bar, pct in steps:
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=msg_id,
                text=f"👁️ <b>VISIT SERVER RUNNING</b>\n━━━━━━━━━━━━━━━━━━━━━━━\n\n👤 𝗨𝗜𝗗: <code>{uid}</code>\n🚀 <b>Speed:</b> Safe High\n\n<code>{bar} {pct}</code>\n\n⏳ <b>Sending Visits...</b>",
                parse_mode='HTML'
            )
            if pct != "100%": await asyncio.sleep(1.0)
        except: pass

    success = await visit_task
    name, likes = await info_task
    end_time = time.time()
    duration = end_time - start_time
    
    # 🔥 NEW POSTER (As Requested)
    final_msg = (
        "✅ 𝗩𝗜𝗦𝗜𝗧 𝗦𝗘𝗡𝗧 𝗦𝗨𝗖𝗖𝗘𝗦𝗦𝗙𝗨𝗟𝗟𝗬!\n\n\n"
        "✦ 👤 𝗣𝗟𝗔𝗬𝗘𝗥 𝗗𝗘𝗧𝗔𝗜𝗟𝗦 ✦\n"
        f"┌ 👤 𝗡𝗶𝗰𝗸𝗻𝗮𝗺𝗲 : {name}\n"
        f"├ 🆔 𝗨𝗜𝗗 : <code>{uid}</code>\n"
        f"├ 🌍 𝗥𝗲𝗴𝗶𝗼𝗻 : {region}\n"
        f"└ 📈 𝗧𝗼𝘁𝗮𝗹 𝗟𝗶𝗸𝗲𝘀 : {likes}\n\n"
        "✦ 🚀 𝗩𝗜𝗦𝗜𝗧 𝗥𝗘𝗦𝗨𝗟𝗧 ✦\n"
        f"┌ ➕ 𝗩𝗶𝘀𝗶𝘁𝘀 𝗔𝗱𝗱𝗲𝗱 : +{success}\n"
        f"└ ⏱️ 𝗧𝗶𝗺𝗲 𝗧𝗮𝗸𝗲𝗻 : {duration:.2f}s\n\n"
        f"📊 𝗧𝗼𝗱𝗮𝘆 𝗨𝘀𝗮𝗴𝗲 : {usage_count} / {DAILY_LIMIT}\n\n"
        "╭───────────────╮\n"
        "🗿 𝗝𝗢𝗜𝗡 𝗖𝗛𝗔𝗡𝗡𝗘𝗟\n"
        f"👉 {CHANNEL_LINK}\n"
        "╰───────────────╯"
    )
    
    try: await context.bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=final_msg, parse_mode='HTML')
    except: pass

# ==============================================================================
#             PART 5: COMMANDS
# ==============================================================================

async def check_subscription(user_id, context):
    if user_id == ADMIN_ID: return True
    not_joined = []
    for channel in MUST_JOIN_CHANNELS:
        try:
            member = await context.bot.get_chat_member(chat_id=channel, user_id=user_id)
            if member.status in [ChatMember.LEFT, ChatMember.BANNED, ChatMember.RESTRICTED]:
                not_joined.append(channel)
        except: pass 
    return len(not_joined) == 0

async def force_join_alert(update, context):
    user = update.effective_user
    safe_name = html.escape(user.first_name)
    
    keyboard = [
        [InlineKeyboardButton("🔔 Channel 1", url=f"https://t.me/{MUST_JOIN_CHANNELS[0].replace('@','')}")],
        [InlineKeyboardButton("🔔 Channel 2", url=f"https://t.me/{MUST_JOIN_CHANNELS[1].replace('@','')}")],
    ]
    
    msg = (
        f"🚫 <b>ACCESS DENIED!</b>\n\n"
        f"👋 Hello {safe_name},\n"
        "You must join our channels to use this bot.\n\n"
        "👇 <b>Join Below:</b>"
    )
    await update.message.reply_text(msg, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='HTML')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👁️ <b>KAMOD VISIT BOT</b> 👁️\n\n"
        "This bot is dedicated for <b>Auto Visits</b>.\n"
        "Use command below:\n\n"
        "👉 <code>/visit IND &lt;UID&gt;</code>\n\n"
        "<i>Example:</i> <code>/visit IND 12345678</code>"
    )
    await update.message.reply_text(msg, parse_mode='HTML')

async def visit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if update.effective_chat.type == "private" and user_id != ADMIN_ID:
        return await update.message.reply_text(f"❌ <b>COMMAND NOT AVAILABLE!</b>\n\nAllowed Only In:\n👉 {GROUP_LINK}", parse_mode='HTML')

    if not await check_subscription(user_id, context): return await force_join_alert(update, context)

    # 🔥 LIMIT CHECK (20/24h)
    allowed, count = check_and_update_limit(user_id)
    if not allowed:
        return await update.message.reply_text(
            f"⛔ <b>DAILY LIMIT REACHED!</b>\n\n"
            f"You have used {count}/{DAILY_LIMIT} visits today.\n"
            "Try again after 24 hours.",
            parse_mode='HTML'
        )

    if len(context.args) != 2:
        return await update.message.reply_text("❌ <b>Format:</b> <code>/visit IND 12345678</code>", parse_mode='HTML')

    region, uid = context.args[0].upper(), context.args[1]
    
    if not MEM_TOKENS:
        return await update.message.reply_text("⚠️ <b>System Busy or No Tokens!</b>", parse_mode='HTML')

    msg = await update.message.reply_text("⏳ <b>Processing Visit Request...</b>", parse_mode='HTML')
    # 🔥 Pass the 'count' to the processor for display
    asyncio.create_task(process_visit_task(update.effective_chat.id, uid, region, MEM_TOKENS, context, msg.message_id, count))

async def check_visit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if len(context.args) != 2: return await update.message.reply_text("❌ Usage: /checkvisit IND UID")
    
    uid = context.args[1]
    msg = await update.message.reply_text(f"🔄 Checking {len(MEM_TOKENS)} Tokens...")
    
    url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    enc_data = encrypt_message(create_profile_check_proto(uid))
    sem = asyncio.Semaphore(50)
    
    async def check_one(session, token):
        async with sem: return await send_request(session, enc_data, token, url)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
        tasks = [check_one(session, t.get("token")) for t in MEM_TOKENS if t.get("token")]
        results = await asyncio.gather(*tasks)
    
    await context.bot.edit_message_text(
        chat_id=update.effective_chat.id, message_id=msg.message_id, 
        text=f"✅ Working: {results.count(200)}\n❌ Dead: {len(MEM_TOKENS) - results.count(200)}"
    )

if __name__ == '__main__':
    load_limits()
    
    # 🔥 Start Auto Token Generator (Thread 1)
    threading.Thread(target=run_auto_refresher, daemon=True).start()
    
    # 🔥 Start RAM Reloader (Thread 2)
    threading.Thread(target=refresh_tokens_ram, daemon=True).start()

    request = HTTPXRequest(connect_timeout=40, read_timeout=40, write_timeout=40, pool_timeout=40)
    app = ApplicationBuilder().token(BOT_TOKEN).request(request).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("visit", visit_command))
    app.add_handler(CommandHandler("checkvisit", check_visit_command))

    print("🚀 KAMOD BOT B (20 LIMIT + AUTO REFRESH) STARTED")
    app.run_polling()
