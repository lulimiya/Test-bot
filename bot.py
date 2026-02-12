import os
import sys
import logging
import asyncio
import re
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
from threading import Lock
from typing import Optional, Dict, Any

import yt_dlp
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from instagrapi import Client
from instagrapi.exceptions import (
    LoginRequired,
    ChallengeRequired,
    TwoFactorRequired,
    BadPassword,
    PleaseWaitFewMinutes,
)
from cryptography.fernet import Fernet
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

# ============================================
#       LOAD CONFIG
# ============================================
try:
    from config import (
        BOT_TOKEN,
        MONGO_URI,
        FIRST_ADMIN_ID,
        ENCRYPTION_KEY,
        RATE_LIMIT_SECONDS,
        MAX_SCHEDULE_DAYS,
        BULK_UPLOAD_DELAY,
        MAX_FILE_SIZE_MB,
        DOWNLOAD_TIMEOUT,
        IG_UPLOAD_COOLDOWN,
        MAX_CAPTION_LENGTH,
        SCHEDULED_CHECK_INTERVAL,
        MAX_RETRIES,
        MAX_BULK_LINKS,
        SUPPORTED_URL_PATTERNS,
        HASHTAG_SETS,
        CAPTION_TEMPLATES,
    )
except ImportError:
    print("=" * 50)
    print("❌ ERROR: config.py not found!")
    print("Create config.py with your settings first.")
    print("=" * 50)
    sys.exit(1)

# ============================================
#       VALIDATE CONFIG
# ============================================
if not BOT_TOKEN:
    print("❌ BOT_TOKEN is empty in config.py!")
    sys.exit(1)

if not MONGO_URI:
    print("❌ MONGO_URI is empty in config.py!")
    sys.exit(1)

if not FIRST_ADMIN_ID or FIRST_ADMIN_ID == 0:
    print("❌ FIRST_ADMIN_ID is not set in config.py!")
    sys.exit(1)

# Handle Encryption Key
ACTIVE_ENCRYPTION_KEY = ENCRYPTION_KEY
if not ACTIVE_ENCRYPTION_KEY:
    ACTIVE_ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("")
    print("=" * 60)
    print("⚠️  ENCRYPTION KEY NOT FOUND IN config.py")
    print("=" * 60)
    print("")
    print("A new key has been generated for you:")
    print("")
    print(f'ENCRYPTION_KEY = "{ACTIVE_ENCRYPTION_KEY}"')
    print("")
    print("STEPS:")
    print("1. Copy the line above")
    print("2. Open config.py")
    print("3. Paste it as the ENCRYPTION_KEY value")
    print("4. Save config.py")
    print("5. Restart the bot")
    print("")
    print("⚠️  Bot will run with this key for now.")
    print("⚠️  But you MUST save it or passwords will be lost!")
    print("=" * 60)
    print("")

# ============================================
#       CONVERSATION STATES
# ============================================
(
    GET_LINK,
    CAPTION_MENU,
    GET_NEW_CAPTION,
    CHOOSE_TEMPLATE,
    CHOOSE_HASHTAGS,
    CUSTOM_HASHTAGS,
    CHOOSE_ACCOUNT,
    CONFIRM_PREVIEW,
    CHOOSE_TIMING,
    GET_SCHEDULE_TIME,
    GET_SPECIFIC_TIME,
    BULK_COLLECT,
    ADMIN_MENU,
    ADD_USER_ID,
    REMOVE_USER_ID,
    ADD_ACCOUNT_USER,
    ADD_ACCOUNT_PASS,
    REMOVE_ACCOUNT,
    SETTINGS_MENU,
    SETUP_FIRST_ACCOUNT_USER,
    SETUP_FIRST_ACCOUNT_PASS,
    ADD_ADMIN_ID,
    REMOVE_ADMIN_ID,
) = range(23)

# ============================================
#       LOGGING SETUP
# ============================================
os.makedirs("logs", exist_ok=True)
os.makedirs("downloads", exist_ok=True)
os.makedirs("sessions", exist_ok=True)

file_handler = RotatingFileHandler(
    "logs/bot.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
)
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ============================================
#       ENCRYPTION
# ============================================
cipher = Fernet(
    ACTIVE_ENCRYPTION_KEY.encode()
    if isinstance(ACTIVE_ENCRYPTION_KEY, str)
    else ACTIVE_ENCRYPTION_KEY
)


def encrypt_password(password: str) -> str:
    return cipher.encrypt(password.encode()).decode()


def decrypt_password(encrypted: str) -> str:
    return cipher.decrypt(encrypted.encode()).decode()


# ============================================
#       MONGODB SETUP
# ============================================
try:
    mongo_client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=10000,
        maxPoolSize=50,
        retryWrites=True,
    )
    mongo_client.admin.command("ping")
    logger.info("✅ MongoDB connected!")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.error(f"❌ MongoDB connection failed: {e}")
    print(f"❌ Cannot connect to MongoDB: {e}")
    print("Check your MONGO_URI in config.py")
    sys.exit(1)
except Exception as e:
    logger.error(f"❌ MongoDB error: {e}")
    print(f"❌ MongoDB error: {e}")
    sys.exit(1)

db = mongo_client["instagram_bot"]

users_col = db["users"]
uploads_col = db["uploads"]
scheduled_col = db["scheduled_posts"]
settings_col = db["user_settings"]
accounts_col = db["instagram_accounts"]
auth_col = db["authorized_users"]
admins_col = db["admin_users"]

# Create indexes
try:
    users_col.create_index([("user_id", ASCENDING)], unique=True)
    uploads_col.create_index([("user_id", ASCENDING), ("uploaded_at", ASCENDING)])
    uploads_col.create_index([("uploaded_at", ASCENDING)])
    scheduled_col.create_index([("status", ASCENDING), ("scheduled_for", ASCENDING)])
    settings_col.create_index([("user_id", ASCENDING)], unique=True)
    accounts_col.create_index([("username", ASCENDING)], unique=True)
    auth_col.create_index([("user_id", ASCENDING)], unique=True)
    admins_col.create_index([("user_id", ASCENDING)], unique=True)
    logger.info("✅ MongoDB indexes created!")
except Exception as e:
    logger.warning(f"Index creation warning: {e}")

# ============================================
#       THREAD-SAFE GLOBALS
# ============================================
instagram_clients: Dict[str, Client] = {}
ig_clients_lock = Lock()

user_last_action: Dict[int, datetime] = {}
rate_limit_lock = Lock()

ig_last_upload: Dict[str, datetime] = {}
ig_upload_lock = Lock()


# ============================================
#       ADMIN & AUTH FUNCTIONS
# ============================================
def init_first_admin():
    """Initialize first admin if none exist"""
    try:
        if admins_col.count_documents({}) == 0:
            admins_col.update_one(
                {"user_id": FIRST_ADMIN_ID},
                {
                    "$set": {
                        "user_id": FIRST_ADMIN_ID,
                        "added_by": "system",
                        "added_at": datetime.now(),
                    }
                },
                upsert=True,
            )
            logger.info(f"✅ First admin {FIRST_ADMIN_ID} initialized.")
    except Exception as e:
        logger.error(f"Init admin error: {e}")


def is_admin(user_id: int) -> bool:
    """Check if user is admin"""
    try:
        return admins_col.find_one({"user_id": user_id}) is not None
    except Exception as e:
        logger.error(f"Admin check error: {e}")
        return False


def get_all_admins() -> list:
    """Get all admin IDs"""
    try:
        return [a["user_id"] for a in admins_col.find({})]
    except Exception:
        return []


def add_admin(user_id: int, added_by: int):
    """Add new admin"""
    try:
        admins_col.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "added_by": added_by,
                    "added_at": datetime.now(),
                }
            },
            upsert=True,
        )
        logger.info(f"Admin added: {user_id} by {added_by}")
    except Exception as e:
        logger.error(f"Add admin error: {e}")


def remove_admin(user_id: int) -> bool:
    """Remove admin (cannot remove first admin)"""
    if user_id == FIRST_ADMIN_ID:
        return False
    try:
        result = admins_col.delete_one({"user_id": user_id})
        if result.deleted_count > 0:
            logger.info(f"Admin removed: {user_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"Remove admin error: {e}")
        return False


def is_authorized(user_id: int) -> bool:
    """Check if user is authorized"""
    if is_admin(user_id):
        return True
    try:
        return auth_col.find_one({"user_id": user_id}) is not None
    except Exception as e:
        logger.error(f"Auth check error: {e}")
        return False


def get_all_authorized() -> list:
    """Get all authorized user IDs"""
    try:
        return [u["user_id"] for u in auth_col.find({})]
    except Exception:
        return []


def add_authorized_user(user_id: int, added_by: int):
    """Add authorized user"""
    try:
        auth_col.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "added_by": added_by,
                    "added_at": datetime.now(),
                }
            },
            upsert=True,
        )
        logger.info(f"User authorized: {user_id} by {added_by}")
    except Exception as e:
        logger.error(f"Add user error: {e}")


def remove_authorized_user(user_id: int) -> bool:
    """Remove authorized user"""
    try:
        result = auth_col.delete_one({"user_id": user_id})
        if result.deleted_count > 0:
            logger.info(f"User removed: {user_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"Remove user error: {e}")
        return False


# ============================================
#       INSTAGRAM ACCOUNT FUNCTIONS
# ============================================
def login_ig_account(username: str, password: str) -> tuple:
    """Login to Instagram account"""
    cl = Client()
    cl.delay_range = [1, 3]
    session_file = os.path.join("sessions", f"{username}.json")

    try:
        if os.path.exists(session_file):
            try:
                cl.load_settings(session_file)
                cl.login(username, password)
                cl.get_timeline_feed()
            except (LoginRequired, Exception):
                logger.info(f"Session expired for @{username}, fresh login...")
                if os.path.exists(session_file):
                    os.remove(session_file)
                cl = Client()
                cl.delay_range = [1, 3]
                cl.login(username, password)
        else:
            cl.login(username, password)

        cl.dump_settings(session_file)
        with ig_clients_lock:
            instagram_clients[username] = cl
        logger.info(f"✅ Instagram @{username} logged in!")
        return True, "Success"

    except BadPassword:
        return False, "Wrong password"
    except TwoFactorRequired:
        return False, "2FA required - not supported yet"
    except ChallengeRequired:
        return False, "Challenge required - login on phone first"
    except PleaseWaitFewMinutes:
        return False, "Rate limited - wait a few minutes"
    except Exception as e:
        logger.error(f"❌ Login failed @{username}: {e}")
        return False, str(e)[:200]


def save_ig_account(username: str, password: str, added_by: int):
    """Save Instagram account with encrypted password"""
    try:
        encrypted_pass = encrypt_password(password)
        accounts_col.update_one(
            {"username": username},
            {
                "$set": {
                    "username": username,
                    "password": encrypted_pass,
                    "added_by": added_by,
                    "added_at": datetime.now(),
                    "status": "active",
                }
            },
            upsert=True,
        )
        logger.info(f"IG account saved: @{username}")
    except Exception as e:
        logger.error(f"Save IG account error: {e}")


def remove_ig_account(username: str) -> bool:
    """Remove Instagram account"""
    try:
        result = accounts_col.delete_one({"username": username})
        with ig_clients_lock:
            if username in instagram_clients:
                del instagram_clients[username]
        session_file = f"sessions/{username}.json"
        if os.path.exists(session_file):
            os.remove(session_file)
        if result.deleted_count > 0:
            logger.info(f"IG account removed: @{username}")
            return True
        return False
    except Exception as e:
        logger.error(f"Remove IG account error: {e}")
        return False


def get_all_ig_accounts() -> list:
    """Get all saved Instagram accounts"""
    try:
        return list(accounts_col.find({}))
    except Exception:
        return []


def load_all_ig_accounts():
    """Load all saved accounts on startup"""
    accounts = get_all_ig_accounts()
    for acc in accounts:
        try:
            decrypted_pass = decrypt_password(acc["password"])
            success, msg = login_ig_account(acc["username"], decrypted_pass)
            if not success:
                logger.warning(f"Failed to load @{acc['username']}: {msg}")
        except Exception as e:
            logger.error(f"Failed to load @{acc['username']}: {e}")


def has_ig_accounts() -> bool:
    """Check if any accounts are connected"""
    with ig_clients_lock:
        return len(instagram_clients) > 0


def get_ig_client(username: str) -> Optional[Client]:
    """Get Instagram client by username"""
    with ig_clients_lock:
        return instagram_clients.get(username)


def check_ig_rate_limit(username: str) -> tuple:
    """Check if account can upload (cooldown)"""
    with ig_upload_lock:
        now = datetime.now()
        if username in ig_last_upload:
            diff = (now - ig_last_upload[username]).total_seconds()
            if diff < IG_UPLOAD_COOLDOWN:
                remaining = int(IG_UPLOAD_COOLDOWN - diff)
                return False, remaining
        return True, 0


def update_ig_last_upload(username: str):
    """Update last upload time"""
    with ig_upload_lock:
        ig_last_upload[username] = datetime.now()


# ============================================
#       USER & UPLOAD FUNCTIONS
# ============================================
def save_user(user_id: int, username: str, first_name: str):
    """Save or update user"""
    try:
        users_col.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "username": username or "N/A",
                    "first_name": first_name or "N/A",
                    "last_active": datetime.now(),
                },
                "$setOnInsert": {"joined_at": datetime.now()},
            },
            upsert=True,
        )
    except Exception as e:
        logger.error(f"Save user error: {e}")


def log_upload(
    user_id: int, source_url: str, caption: str, status: str, account: str
):
    """Log an upload attempt"""
    try:
        uploads_col.insert_one(
            {
                "user_id": user_id,
                "source_url": source_url[:500] if source_url else "",
                "caption": caption[:500] if caption else "",
                "status": status,
                "instagram_account": account,
                "uploaded_at": datetime.now(),
            }
        )
    except Exception as e:
        logger.error(f"Log upload error: {e}")


def save_scheduled_post(
    user_id: int, file_path: str, caption: str, minutes: int, account: str, source_url: str = ""
):
    """Save a scheduled post"""
    try:
        return scheduled_col.insert_one(
            {
                "user_id": user_id,
                "file_path": file_path,
                "caption": caption[:MAX_CAPTION_LENGTH] if caption else "",
                "delay_minutes": minutes,
                "instagram_account": account,
                "source_url": source_url[:500] if source_url else "",
                "status": "pending",
                "created_at": datetime.now(),
                "scheduled_for": datetime.now() + timedelta(minutes=minutes),
            }
        )
    except Exception as e:
        logger.error(f"Save scheduled error: {e}")
        return None


def get_user_stats(user_id: int) -> dict:
    """Get user upload statistics"""
    try:
        total = uploads_col.count_documents({"user_id": user_id})
        success = uploads_col.count_documents(
            {"user_id": user_id, "status": "success"}
        )
        failed = uploads_col.count_documents(
            {"user_id": user_id, "status": "failed"}
        )
        today_start = datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        today = uploads_col.count_documents(
            {"user_id": user_id, "uploaded_at": {"$gte": today_start}}
        )
        week_start = datetime.now() - timedelta(days=7)
        this_week = uploads_col.count_documents(
            {"user_id": user_id, "uploaded_at": {"$gte": week_start}}
        )
        pending = scheduled_col.count_documents(
            {"user_id": user_id, "status": "pending"}
        )
        return {
            "total": total,
            "success": success,
            "failed": failed,
            "today": today,
            "this_week": this_week,
            "pending": pending,
            "success_rate": round((success / total * 100), 1) if total > 0 else 0,
        }
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return {
            "total": 0,
            "success": 0,
            "failed": 0,
            "today": 0,
            "this_week": 0,
            "pending": 0,
            "success_rate": 0,
        }


def get_upload_history(user_id: int, limit: int = 10) -> list:
    """Get recent upload history"""
    try:
        return list(
            uploads_col.find({"user_id": user_id})
            .sort("uploaded_at", -1)
            .limit(limit)
        )
    except Exception:
        return []


def get_all_stats() -> dict:
    """Get global statistics"""
    try:
        today_start = datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return {
            "total_users": users_col.count_documents({}),
            "total_uploads": uploads_col.count_documents({}),
            "total_success": uploads_col.count_documents({"status": "success"}),
            "total_failed": uploads_col.count_documents({"status": "failed"}),
            "total_pending": scheduled_col.count_documents({"status": "pending"}),
            "total_accounts": len(instagram_clients),
            "today_uploads": uploads_col.count_documents(
                {"uploaded_at": {"$gte": today_start}}
            ),
            "total_admins": admins_col.count_documents({}),
            "total_auth_users": auth_col.count_documents({}),
        }
    except Exception as e:
        logger.error(f"Global stats error: {e}")
        return {}


def save_user_settings(user_id: int, key: str, value: Any):
    """Save a user setting"""
    try:
        settings_col.update_one(
            {"user_id": user_id},
            {"$set": {key: value}},
            upsert=True,
        )
    except Exception as e:
        logger.error(f"Save settings error: {e}")


def get_user_settings(user_id: int) -> dict:
    """Get user settings"""
    try:
        return settings_col.find_one({"user_id": user_id}) or {}
    except Exception:
        return {}


# ============================================
#       URL VALIDATION & SANITIZATION
# ============================================
def is_valid_url(url: str) -> bool:
    """Check if URL is from supported platform"""
    if not url or len(url) > 2000:
        return False
    for pattern in SUPPORTED_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False


def sanitize_caption(caption: str) -> str:
    """Clean and limit caption"""
    if not caption:
        return ""
    caption = caption.strip()
    caption = re.sub(r"[<>]", "", caption)
    return caption[:MAX_CAPTION_LENGTH]


def validate_message_length(text: str, max_length: int = 4000) -> str:
    """Ensure message doesn't exceed Telegram's limit"""
    if len(text) > max_length:
        return text[:max_length] + "\n... (truncated)"
    return text


# ============================================
#       FILE MANAGEMENT
# ============================================
def cleanup_file(file_path: str):
    """Delete a file safely"""
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Cleaned: {file_path}")
    except Exception as e:
        logger.error(f"Cleanup error: {e}")


def cleanup_old_downloads():
    """Delete downloads older than 1 hour"""
    download_dir = "downloads"
    if not os.path.exists(download_dir):
        return
    now = datetime.now()
    for f in os.listdir(download_dir):
        fp = os.path.join(download_dir, f)
        try:
            if os.path.isfile(fp):
                age = now - datetime.fromtimestamp(os.path.getmtime(fp))
                if age.total_seconds() > 3600:
                    os.remove(fp)
                    logger.info(f"Cleaned old: {fp}")
        except Exception as e:
            logger.error(f"Cleanup error {fp}: {e}")


# ============================================
#       DECORATORS
# ============================================
def rate_limit(func):
    """Rate limit decorator"""

    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if is_admin(user_id):
            return await func(update, context)

        now = datetime.now()
        with rate_limit_lock:
            if user_id in user_last_action:
                diff = (now - user_last_action[user_id]).total_seconds()
                if diff < RATE_LIMIT_SECONDS:
                    remaining = int(RATE_LIMIT_SECONDS - diff)
                    if update.message:
                        await update.message.reply_text(
                            f"⏳ Rate limited! Wait {remaining}s."
                        )
                    return ConversationHandler.END
            user_last_action[user_id] = now
        return await func(update, context)

    return wrapper


# ============================================
#       DOWNLOAD FUNCTION
# ============================================
def download_media(url: str) -> dict:
    """Download video from URL"""
    ydl_opts = {
        "format": "bestvideo[ext=mp4][filesize<100M]+bestaudio[ext=m4a]/best[ext=mp4][filesize<100M]/best[filesize<100M]",
        "outtmpl": "downloads/%(id)s.%(ext)s",
        "quiet": True,
        "no_warnings": True,
        "merge_output_format": "mp4",
        "socket_timeout": DOWNLOAD_TIMEOUT,
        "retries": 3,
        "max_filesize": MAX_FILE_SIZE_MB * 1024 * 1024,
    }

    file_path = None
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            file_path = ydl.prepare_filename(info)

            # Check for mp4 extension
            if not os.path.exists(file_path):
                mp4_path = os.path.splitext(file_path)[0] + ".mp4"
                if os.path.exists(mp4_path):
                    file_path = mp4_path
                else:
                    raise FileNotFoundError("Downloaded file not found")

            file_size = os.path.getsize(file_path)

            if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                os.remove(file_path)
                raise ValueError(
                    f"File too large: {file_size / 1024 / 1024:.1f}MB"
                )

            if file_size == 0:
                os.remove(file_path)
                raise ValueError("Downloaded file is empty")

            return {
                "file_path": file_path,
                "caption": sanitize_caption(
                    info.get("description") or info.get("title") or ""
                ),
                "title": info.get("title", "N/A")[:50],
                "duration": info.get("duration", 0),
                "file_size": file_size,
            }

    except yt_dlp.utils.DownloadError as e:
        # Cleanup any partial download
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        raise ValueError(f"Download failed: {str(e)[:200]}")
    except FileNotFoundError:
        # Cleanup any partial download
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        raise ValueError("File not found after download")
    except ValueError:
        # Already cleaned up in size checks
        raise
    except Exception as e:
        # Cleanup any partial download
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        raise ValueError(f"Error: {str(e)[:200]}")


# ============================================
#       INSTAGRAM UPLOAD
# ============================================
async def upload_to_instagram(context: ContextTypes.DEFAULT_TYPE):
    """Upload video to Instagram as Reel"""
    job = context.job
    data = job.data
    file_path = data["file_path"]
    caption = data["caption"]
    chat_id = data["chat_id"]
    user_id = data["user_id"]
    source_url = data.get("source_url", "")
    account = data.get("account", "")

    # Check client exists
    client = get_ig_client(account)
    if not client:
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"❌ @{account} is not connected. Re-add the account.",
        )
        log_upload(user_id, source_url, caption, "failed", account)
        cleanup_file(file_path)
        return

    # Check IG rate limit
    can_upload, wait_time = check_ig_rate_limit(account)
    if not can_upload:
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"⏳ Waiting {wait_time}s for @{account} cooldown...",
        )
        await asyncio.sleep(wait_time)

    # Check file exists
    if not os.path.exists(file_path):
        await context.bot.send_message(
            chat_id=chat_id,
            text="❌ Video file not found. May have been cleaned up.",
        )
        log_upload(user_id, source_url, caption, "failed", account)
        return

    # Send progress
    progress_msg = await context.bot.send_message(
        chat_id=chat_id,
        text=(
            "╔══════════════════════════╗\n"
            "║   ⏳ UPLOADING...        ║\n"
            "╠══════════════════════════╣\n"
            "║  ▓▓▓░░░░░░░░░░  25%     ║\n"
            "╚══════════════════════════╝\n"
            f"📱 Account: @{account}"
        ),
    )

    bars = [
        "▓▓▓▓▓▓░░░░░░  50%",
        "▓▓▓▓▓▓▓▓▓░░░  75%",
        "▓▓▓▓▓▓▓▓▓▓▓▓ 100%",
    ]

    for attempt in range(MAX_RETRIES):
        try:
            # Update progress
            try:
                await progress_msg.edit_text(
                    "╔══════════════════════════╗\n"
                    "║   ⏳ UPLOADING...        ║\n"
                    "╠══════════════════════════╣\n"
                    f"║  {bars[attempt]}     ║\n"
                    "╚══════════════════════════╝\n"
                    f"📱 @{account} | Try {attempt + 1}/{MAX_RETRIES}"
                )
            except Exception:
                pass

            # Upload in executor to not block
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: client.clip_upload(file_path, caption),
            )

            # Success
            update_ig_last_upload(account)
            log_upload(user_id, source_url, caption, "success", account)

            scheduled_col.update_many(
                {"file_path": file_path, "status": "pending"},
                {"$set": {"status": "completed", "completed_at": datetime.now()}},
            )

            try:
                await progress_msg.edit_text(
                    "╔══════════════════════════╗\n"
                    "║   ✅ UPLOAD COMPLETE!    ║\n"
                    "╠══════════════════════════╣\n"
                    "║  ▓▓▓▓▓▓▓▓▓▓▓▓ 100%     ║\n"
                    "╚══════════════════════════╝\n\n"
                    f"📱 Account: @{account}\n"
                    f"📝 Caption: {caption[:80]}...\n"
                    f"🕐 {datetime.now().strftime('%I:%M %p')}\n\n"
                    "🎉 Reel posted successfully!"
                )
            except Exception:
                pass

            break  # Exit retry loop on success

        except LoginRequired:
            logger.warning(f"Login required for @{account}")
            acc_data = accounts_col.find_one({"username": account})
            if acc_data:
                try:
                    dec_pass = decrypt_password(acc_data["password"])
                    success, msg = login_ig_account(account, dec_pass)
                    if success:
                        client = get_ig_client(account)
                        if client:
                            # Retry the upload immediately with new client
                            continue
                except Exception as e:
                    logger.error(f"Re-login error: {e}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(5 * (attempt + 1))

        except PleaseWaitFewMinutes:
            logger.warning(f"IG rate limit for @{account}")
            if attempt < MAX_RETRIES - 1:
                wait = 60 * (attempt + 1)
                try:
                    await progress_msg.edit_text(
                        f"⏳ Instagram rate limit. Waiting {wait}s..."
                    )
                except Exception:
                    pass
                await asyncio.sleep(wait)

        except Exception as e:
            logger.error(f"Upload attempt {attempt + 1} failed: {e}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(5 * (attempt + 1))
            else:
                # All retries failed
                log_upload(user_id, source_url, caption, "failed", account)

                scheduled_col.update_many(
                    {"file_path": file_path, "status": "pending"},
                    {"$set": {"status": "failed", "error": str(e)[:200]}},
                )

                try:
                    error_msg = str(e)[:24].ljust(24)  # Pad to maintain box alignment
                    await progress_msg.edit_text(
                        "╔══════════════════════════╗\n"
                        "║   ❌ UPLOAD FAILED!      ║\n"
                        "╠══════════════════════════╣\n"
                        f"║  {error_msg}  ║\n"
                        "╚══════════════════════════╝\n\n"
                        f"All {MAX_RETRIES} attempts failed.\n"
                        "Try again with /start"
                    )
                except Exception:
                    pass

    # Cleanup downloaded file
    cleanup_file(file_path)


# ============================================
#       SCHEDULED JOBS
# ============================================
async def check_scheduled_posts(context: ContextTypes.DEFAULT_TYPE):
    """Check and execute due scheduled posts"""
    try:
        now = datetime.now()
        pending = scheduled_col.find(
            {"status": "pending", "scheduled_for": {"$lte": now}}
        )

        for post in pending:
            try:
                # Atomically update status to prevent race conditions
                result = scheduled_col.find_one_and_update(
                    {"_id": post["_id"], "status": "pending"},
                    {"$set": {"status": "processing"}},
                )
                
                # Skip if already being processed
                if not result:
                    continue

                context.job_queue.run_once(
                    upload_to_instagram,
                    when=0,
                    data={
                        "file_path": post["file_path"],
                        "caption": post["caption"],
                        "chat_id": post["user_id"],
                        "user_id": post["user_id"],
                        "source_url": post.get("source_url", ""),
                        "account": post["instagram_account"],
                    },
                    name=f"sched_{post['_id']}",
                )
                logger.info(f"Scheduled post triggered: {post['_id']}")

            except Exception as e:
                logger.error(f"Scheduled post error: {e}")
                scheduled_col.update_one(
                    {"_id": post["_id"]},
                    {"$set": {"status": "failed", "error": str(e)[:200]}},
                )

    except Exception as e:
        logger.error(f"Schedule checker error: {e}")


async def cleanup_job(context: ContextTypes.DEFAULT_TYPE):
    """Periodic cleanup of old downloads"""
    cleanup_old_downloads()


# ============================================
#       UI KEYBOARDS
# ============================================
def main_menu_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Main menu buttons"""
    keyboard = [
        [
            InlineKeyboardButton("📤 Upload Reel", callback_data="menu_upload"),
            InlineKeyboardButton("📋 Bulk Upload", callback_data="menu_bulk"),
        ],
        [
            InlineKeyboardButton("📊 My Stats", callback_data="menu_stats"),
            InlineKeyboardButton("📜 History", callback_data="menu_history"),
        ],
        [
            InlineKeyboardButton("📱 IG Accounts", callback_data="menu_accounts"),
            InlineKeyboardButton("⚙️ Settings", callback_data="menu_settings"),
        ],
    ]

    if is_admin(user_id):
        keyboard.append(
            [InlineKeyboardButton("🔐 Admin Panel", callback_data="menu_admin")]
        )

    keyboard.append(
        [InlineKeyboardButton("❓ Help", callback_data="menu_help")]
    )

    return InlineKeyboardMarkup(keyboard)


def admin_menu_keyboard() -> InlineKeyboardMarkup:
    """Admin panel buttons"""
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "━━━ 👥 USER MANAGEMENT ━━━", callback_data="ignore"
                )
            ],
            [
                InlineKeyboardButton("➕ Add User", callback_data="admin_add_user"),
                InlineKeyboardButton(
                    "➖ Remove User", callback_data="admin_remove_user"
                ),
            ],
            [
                InlineKeyboardButton(
                    "📋 List Users", callback_data="admin_list_users"
                )
            ],
            [
                InlineKeyboardButton(
                    "━━━ 👑 ADMIN MANAGEMENT ━━━", callback_data="ignore"
                )
            ],
            [
                InlineKeyboardButton("➕ Add Admin", callback_data="admin_add_admin"),
                InlineKeyboardButton(
                    "➖ Remove Admin", callback_data="admin_remove_admin"
                ),
            ],
            [
                InlineKeyboardButton(
                    "📋 List Admins", callback_data="admin_list_admins"
                )
            ],
            [
                InlineKeyboardButton(
                    "━━━ 📱 INSTAGRAM ━━━", callback_data="ignore"
                )
            ],
            [
                InlineKeyboardButton(
                    "➕ Add Account", callback_data="admin_add_ig"
                ),
                InlineKeyboardButton(
                    "➖ Remove Account", callback_data="admin_remove_ig"
                ),
            ],
            [
                InlineKeyboardButton(
                    "📋 List Accounts", callback_data="admin_list_ig"
                )
            ],
            [
                InlineKeyboardButton(
                    "━━━━━━━━━━━━━━━━━━━━", callback_data="ignore"
                )
            ],
            [
                InlineKeyboardButton(
                    "📊 Global Stats", callback_data="admin_global_stats"
                )
            ],
            [
                InlineKeyboardButton(
                    "🔙 Back to Menu", callback_data="back_main"
                )
            ],
        ]
    )


def caption_menu_keyboard() -> InlineKeyboardMarkup:
    """Caption editing options"""
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("✏️ Edit Caption", callback_data="caption_edit")],
            [
                InlineKeyboardButton(
                    "📝 Use Template", callback_data="caption_template"
                )
            ],
            [
                InlineKeyboardButton(
                    "#️⃣ Add Hashtags", callback_data="caption_hashtags"
                )
            ],
            [
                InlineKeyboardButton(
                    "✅ Keep Current", callback_data="caption_keep"
                )
            ],
            [InlineKeyboardButton("🔙 Cancel", callback_data="back_main")],
        ]
    )


def template_keyboard() -> InlineKeyboardMarkup:
    """Caption template selection"""
    buttons = []
    for name in CAPTION_TEMPLATES:
        buttons.append(
            [
                InlineKeyboardButton(
                    f"📝 {name.title()}", callback_data=f"template_{name}"
                )
            ]
        )
    buttons.append(
        [InlineKeyboardButton("🔙 Back", callback_data="back_caption")]
    )
    return InlineKeyboardMarkup(buttons)


def hashtag_keyboard() -> InlineKeyboardMarkup:
    """Hashtag preset selection"""
    buttons = []
    row = []
    for name in HASHTAG_SETS:
        row.append(
            InlineKeyboardButton(f"#{name}", callback_data=f"hashtag_{name}")
        )
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    buttons.append(
        [
            InlineKeyboardButton(
                "✍️ Custom Hashtags", callback_data="hashtag_custom"
            )
        ]
    )
    buttons.append(
        [InlineKeyboardButton("🔙 Back", callback_data="back_caption")]
    )
    return InlineKeyboardMarkup(buttons)


def account_keyboard() -> InlineKeyboardMarkup:
    """Instagram account selection"""
    buttons = []
    with ig_clients_lock:
        for username in instagram_clients:
            buttons.append(
                [
                    InlineKeyboardButton(
                        f"📱 @{username}", callback_data=f"account_{username}"
                    )
                ]
            )
    if not buttons:
        buttons.append(
            [
                InlineKeyboardButton(
                    "❌ No accounts available", callback_data="ignore"
                )
            ]
        )
    buttons.append(
        [InlineKeyboardButton("🔙 Cancel", callback_data="back_main")]
    )
    return InlineKeyboardMarkup(buttons)


def timing_keyboard() -> InlineKeyboardMarkup:
    """Upload timing selection"""
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⚡ Upload Now", callback_data="timing_now")],
            [
                InlineKeyboardButton("⏰ 5 min", callback_data="timing_5"),
                InlineKeyboardButton("⏰ 15 min", callback_data="timing_15"),
            ],
            [
                InlineKeyboardButton("⏰ 30 min", callback_data="timing_30"),
                InlineKeyboardButton("⏰ 1 hour", callback_data="timing_60"),
            ],
            [
                InlineKeyboardButton("⏰ 3 hours", callback_data="timing_180"),
                InlineKeyboardButton("⏰ 6 hours", callback_data="timing_360"),
            ],
            [
                InlineKeyboardButton(
                    "📅 Custom Time", callback_data="timing_custom"
                )
            ],
            [InlineKeyboardButton("🔙 Cancel", callback_data="back_main")],
        ]
    )


def settings_keyboard() -> InlineKeyboardMarkup:
    """User settings options"""
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "📝 Default Template", callback_data="setting_template"
                )
            ],
            [
                InlineKeyboardButton(
                    "#️⃣ Default Hashtags", callback_data="setting_hashtags"
                )
            ],
            [
                InlineKeyboardButton(
                    "📱 Default Account", callback_data="setting_account"
                )
            ],
            [
                InlineKeyboardButton(
                    "🔙 Back to Menu", callback_data="back_main"
                )
            ],
        ]
    )


def back_button() -> InlineKeyboardMarkup:
    """Back to main menu button"""
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔙 Back to Menu", callback_data="back_main")]]
    )


def back_admin_button() -> InlineKeyboardMarkup:
    """Back to admin panel button"""
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔙 Back to Admin", callback_data="back_admin")]]
    )


# ============================================
#       /start COMMAND
# ============================================
@rate_limit
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    user = update.effective_user
    save_user(user.id, user.username, user.first_name)

    # Check authorization
    if not is_authorized(user.id):
        await update.message.reply_text(
            "╔══════════════════════════════╗\n"
            "║       ⛔ ACCESS DENIED       ║\n"
            "╠══════════════════════════════╣\n"
            "║  You are not authorized to   ║\n"
            "║  use this bot.               ║\n"
            "║                              ║\n"
            "║  Contact admin for access.   ║\n"
            f"║  Your ID: {user.id:<18} ║\n"
            "╚══════════════════════════════╝"
        )
        return ConversationHandler.END

    # First time setup for admin
    if is_admin(user.id) and not has_ig_accounts():
        await update.message.reply_text(
            "╔══════════════════════════════╗\n"
            "║    🔧 FIRST TIME SETUP       ║\n"
            "╠══════════════════════════════╣\n"
            "║  No Instagram accounts found ║\n"
            "║                              ║\n"
            "║  Let's add your first one.   ║\n"
            "║  Send Instagram USERNAME:    ║\n"
            "╚══════════════════════════════╝"
        )
        return SETUP_FIRST_ACCOUNT_USER

    # Normal welcome
    await update.message.reply_text(
        f"╔══════════════════════════════╗\n"
        f"║  🎬 INSTAGRAM REEL UPLOADER  ║\n"
        f"╠══════════════════════════════╣\n"
        f"║  Welcome, {user.first_name[:16]:<16}  ║\n"
        f"║                              ║\n"
        f"║  Upload reels from any       ║\n"
        f"║  platform to Instagram!      ║\n"
        f"╚══════════════════════════════╝",
        reply_markup=main_menu_keyboard(user.id),
    )
    return ConversationHandler.END


# ============================================
#       FIRST TIME SETUP HANDLERS
# ============================================
async def setup_first_account_user(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive Instagram username for first setup"""
    username = update.message.text.strip().replace("@", "")

    if not username or len(username) < 2:
        await update.message.reply_text("❌ Invalid username. Try again:")
        return SETUP_FIRST_ACCOUNT_USER

    context.user_data["setup_ig_user"] = username

    await update.message.reply_text(
        f"📱 Username: @{username}\n\n"
        "Now send the Instagram PASSWORD:\n"
        "⚠️ It will be encrypted and stored securely.\n"
        "⚠️ Your message will be deleted for safety."
    )
    return SETUP_FIRST_ACCOUNT_PASS


async def setup_first_account_pass(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive Instagram password for first setup"""
    password = update.message.text.strip()
    username = context.user_data.get("setup_ig_user", "")

    # Delete password message
    try:
        await update.message.delete()
    except Exception:
        pass

    if not password or len(password) < 6:
        await update.effective_chat.send_message(
            "❌ Password too short (min 6 chars). Try again:"
        )
        return SETUP_FIRST_ACCOUNT_PASS

    status_msg = await update.effective_chat.send_message(
        f"⏳ Logging into @{username}..."
    )

    success, msg = login_ig_account(username, password)

    if success:
        save_ig_account(username, password, update.effective_user.id)
        await status_msg.edit_text(
            f"✅ @{username} connected successfully!\n\n"
            "🎉 Setup complete! You can now use the bot."
        )
        await update.effective_chat.send_message(
            "Choose an option:",
            reply_markup=main_menu_keyboard(update.effective_user.id),
        )
        return ConversationHandler.END
    else:
        await status_msg.edit_text(
            f"❌ Login failed: {msg}\n\n"
            "Send Instagram USERNAME again to retry:"
        )
        return SETUP_FIRST_ACCOUNT_USER


# ============================================
#       MAIN MENU CALLBACK
# ============================================
async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all main menu button presses"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    data = query.data

    # Ignore divider buttons
    if data == "ignore":
        return

    # Check auth
    if not is_authorized(user_id):
        await query.edit_message_text("⛔ Access denied.")
        return ConversationHandler.END

    # === BACK BUTTONS ===

    if data == "back_main":
        await query.edit_message_text(
            "╔══════════════════════════════╗\n"
            "║  🎬 INSTAGRAM REEL UPLOADER  ║\n"
            "╠══════════════════════════════╣\n"
            "║  Choose an option below:     ║\n"
            "╚══════════════════════════════╝",
            reply_markup=main_menu_keyboard(user_id),
        )
        return ConversationHandler.END

    if data == "back_admin":
        if not is_admin(user_id):
            await query.edit_message_text("⛔ Admin access required!")
            return ConversationHandler.END
        await query.edit_message_text(
            "🔐 Admin Panel",
            reply_markup=admin_menu_keyboard(),
        )
        return ADMIN_MENU

    if data == "back_caption":
        caption = context.user_data.get("caption", "No caption")
        await query.edit_message_text(
            f"📝 Current Caption:\n\n{caption[:500]}\n\n"
            "Choose an option:",
            reply_markup=caption_menu_keyboard(),
        )
        return CAPTION_MENU

    # === UPLOAD ===

    if data == "menu_upload":
        if not has_ig_accounts():
            await query.edit_message_text(
                "❌ No Instagram accounts configured!\n"
                "Ask an admin to add one.",
                reply_markup=back_button(),
            )
            return ConversationHandler.END

        await query.edit_message_text(
            "╔══════════════════════════════╗\n"
            "║       📤 UPLOAD REEL         ║\n"
            "╠══════════════════════════════╣\n"
            "║  Send the video URL from:    ║\n"
            "║                              ║\n"
            "║  • YouTube / Shorts          ║\n"
            "║  • TikTok                    ║\n"
            "║  • Instagram                 ║\n"
            "║  • Twitter / X               ║\n"
            "║  • Facebook                  ║\n"
            "║  • Reddit                    ║\n"
            "║  • Vimeo & more...           ║\n"
            "╚══════════════════════════════╝\n\n"
            "📎 Send the URL now or /cancel:"
        )
        return GET_LINK

    # === BULK ===

    if data == "menu_bulk":
        if not has_ig_accounts():
            await query.edit_message_text(
                "❌ No Instagram accounts configured!",
                reply_markup=back_button(),
            )
            return ConversationHandler.END

        context.user_data["bulk_links"] = []
        await query.edit_message_text(
            "╔══════════════════════════════╗\n"
            "║       📋 BULK UPLOAD         ║\n"
            "╠══════════════════════════════╣\n"
            "║  Send video URLs one by one  ║\n"
            "║                              ║\n"
            "║  • Send /done when finished  ║\n"
            "║  • Send /cancel to exit      ║\n"
            f"║  • Max {MAX_BULK_LINKS} links per batch    ║\n"
            "╚══════════════════════════════╝\n\n"
            "📊 Links collected: 0"
        )
        return BULK_COLLECT

    # === STATS ===

    if data == "menu_stats":
        stats = get_user_stats(user_id)
        text = (
            "╔══════════════════════════════╗\n"
            "║       📊 YOUR STATS          ║\n"
            "╠══════════════════════════════╣\n"
            f"║  📤 Total Uploads: {stats['total']:<9} ║\n"
            f"║  ✅ Successful:    {stats['success']:<9} ║\n"
            f"║  ❌ Failed:        {stats['failed']:<9} ║\n"
            f"║  📈 Success Rate:  {stats['success_rate']:<6}%  ║\n"
            f"║  📅 Today:         {stats['today']:<9} ║\n"
            f"║  📆 This Week:     {stats['this_week']:<9} ║\n"
            f"║  ⏳ Pending:       {stats['pending']:<9} ║\n"
            "╚══════════════════════════════╝"
        )
        await query.edit_message_text(
            validate_message_length(text),
            reply_markup=back_button(),
        )
        return ConversationHandler.END

    # === HISTORY ===

    if data == "menu_history":
        history = get_upload_history(user_id)

        if not history:
            await query.edit_message_text(
                "📜 No upload history yet!\n"
                "Upload your first reel to see history.",
                reply_markup=back_button(),
            )
            return ConversationHandler.END

        text = "╔═══════════════════════════╗\n"
        text += "║     📜 UPLOAD HISTORY     ║\n"
        text += "╠═══════════════════════════╣\n"

        for i, h in enumerate(history, 1):
            status_icon = "✅" if h.get("status") == "success" else "❌"
            time_str = h.get("uploaded_at", datetime.now()).strftime(
                "%m/%d %I:%M%p"
            )
            acc = h.get("instagram_account", "?")[:10]
            text += f"║ {i}. {status_icon} @{acc} {time_str}\n"

        text += "╚═══════════════════════════╝"

        await query.edit_message_text(
            validate_message_length(text), 
            reply_markup=back_button()
        )
        return ConversationHandler.END

    # === ACCOUNTS ===

    if data == "menu_accounts":
        accounts = get_all_ig_accounts()

        if not accounts:
            await query.edit_message_text(
                "📱 No Instagram accounts configured.",
                reply_markup=back_button(),
            )
            return ConversationHandler.END

        text = "╔═══════════════════════════╗\n"
        text += "║   📱 INSTAGRAM ACCOUNTS   ║\n"
        text += "╠═══════════════════════════╣\n"

        for acc in accounts:
            with ig_clients_lock:
                connected = acc["username"] in instagram_clients
            status = "🟢 Connected" if connected else "🔴 Offline"
            text += f"║  @{acc['username']} - {status}\n"

        text += "╚═══════════════════════════╝"

        await query.edit_message_text(text, reply_markup=back_button())
        return ConversationHandler.END

    # === SETTINGS ===

    if data == "menu_settings":
        await query.edit_message_text(
            "⚙️ User Settings\n\n"
            "Configure your default preferences:",
            reply_markup=settings_keyboard(),
        )
        return SETTINGS_MENU

    # === ADMIN ===

    if data == "menu_admin":
        if not is_admin(user_id):
            await query.edit_message_text("⛔ Admin access required!")
            return ConversationHandler.END

        await query.edit_message_text(
            "🔐 Admin Panel",
            reply_markup=admin_menu_keyboard(),
        )
        return ADMIN_MENU

    # === HELP ===

    if data == "menu_help":
        await query.edit_message_text(
            "╔══════════════════════════════╗\n"
            "║         ❓ HELP              ║\n"
            "╠══════════════════════════════╣\n"
            "║                              ║\n"
            "║  📤 Upload Reel:             ║\n"
            "║  Send a video URL to         ║\n"
            "║  download & upload as reel   ║\n"
            "║                              ║\n"
            "║  📋 Bulk Upload:             ║\n"
            "║  Send multiple URLs and      ║\n"
            "║  upload them all at once     ║\n"
            "║                              ║\n"
            "║  ⏰ Schedule:                ║\n"
            "║  Schedule posts for later    ║\n"
            "║                              ║\n"
            "║  📊 Stats & History:         ║\n"
            "║  Track your uploads          ║\n"
            "║                              ║\n"
            "║  Commands:                   ║\n"
            "║  /start  - Main menu         ║\n"
            "║  /cancel - Cancel action     ║\n"
            "║  /stats  - Quick stats       ║\n"
            "║  /help   - This message      ║\n"
            "╚══════════════════════════════╝",
            reply_markup=back_button(),
        )
        return ConversationHandler.END


# ============================================
#       UPLOAD FLOW - GET LINK
# ============================================
async def get_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive video URL from user"""
    url = update.message.text.strip()

    if not is_valid_url(url):
        await update.message.reply_text(
            "❌ Invalid or unsupported URL!\n\n"
            "Supported platforms:\n"
            "YouTube, TikTok, Instagram, Twitter/X,\n"
            "Facebook, Reddit, Vimeo, Dailymotion\n\n"
            "Send a valid URL or /cancel:"
        )
        return GET_LINK

    status_msg = await update.message.reply_text(
        "⏳ Downloading video... Please wait."
    )

    try:
        media = download_media(url)

        context.user_data["file_path"] = media["file_path"]
        context.user_data["caption"] = media["caption"]
        context.user_data["source_url"] = url
        context.user_data["title"] = media["title"]
        context.user_data["duration"] = media["duration"]
        context.user_data["hashtags"] = ""

        file_size_mb = media["file_size"] / (1024 * 1024)

        await status_msg.edit_text(
            "╔══════════════════════════════╗\n"
            "║     ✅ DOWNLOAD COMPLETE     ║\n"
            "╠══════════════════════════════╣\n"
            f"║  📹 {media['title'][:24]}\n"
            f"║  ⏱️  Duration: {media['duration']}s\n"
            f"║  📦 Size: {file_size_mb:.1f}MB\n"
            "╚══════════════════════════════╝\n\n"
            f"📝 Caption:\n{media['caption'][:300]}\n\n"
            "Choose caption option:",
            reply_markup=caption_menu_keyboard(),
        )
        return CAPTION_MENU

    except ValueError as e:
        await status_msg.edit_text(
            f"❌ {e}\n\n"
            "Send another URL or /cancel:"
        )
        return GET_LINK

    except Exception as e:
        logger.error(f"Download error: {e}")
        await status_msg.edit_text(
            f"❌ Download error: {str(e)[:150]}\n\n"
            "Send another URL or /cancel:"
        )
        return GET_LINK


# ============================================
#       UPLOAD FLOW - CAPTION
# ============================================
async def caption_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle caption menu buttons"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "caption_edit":
        await query.edit_message_text(
            "✏️ Send your new caption:\n\n"
            "Or /cancel to go back."
        )
        return GET_NEW_CAPTION

    if data == "caption_template":
        await query.edit_message_text(
            "📝 Choose a caption template:",
            reply_markup=template_keyboard(),
        )
        return CHOOSE_TEMPLATE

    if data == "caption_hashtags":
        await query.edit_message_text(
            "#️⃣ Choose a hashtag preset:",
            reply_markup=hashtag_keyboard(),
        )
        return CHOOSE_HASHTAGS

    if data == "caption_keep":
        await query.edit_message_text(
            "📱 Choose Instagram account to post to:",
            reply_markup=account_keyboard(),
        )
        return CHOOSE_ACCOUNT

    return CAPTION_MENU


async def get_new_caption(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive new caption text"""
    new_caption = sanitize_caption(update.message.text)

    if not new_caption:
        await update.message.reply_text(
            "❌ Caption cannot be empty. Try again:"
        )
        return GET_NEW_CAPTION

    context.user_data["caption"] = new_caption

    await update.message.reply_text(
        f"✅ Caption updated!\n\n"
        f"📝 New Caption:\n{new_caption[:300]}\n\n"
        "Choose next option:",
        reply_markup=caption_menu_keyboard(),
    )
    return CAPTION_MENU


# ============================================
#       UPLOAD FLOW - TEMPLATE
# ============================================
async def choose_template(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle template selection"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "back_caption":
        caption = context.user_data.get("caption", "No caption")
        await query.edit_message_text(
            f"📝 Caption:\n{caption[:300]}\n\nChoose option:",
            reply_markup=caption_menu_keyboard(),
        )
        return CAPTION_MENU

    template_name = data.replace("template_", "")

    if template_name in CAPTION_TEMPLATES:
        template = CAPTION_TEMPLATES[template_name]
        caption = context.user_data.get("caption", "")
        hashtags = context.user_data.get("hashtags", "")

        try:
            # Safe replacement to avoid format string issues with curly braces in user content
            formatted = template.replace("{caption}", caption).replace("{hashtags}", hashtags)
        except Exception:
            formatted = caption

        context.user_data["caption"] = formatted

        await query.edit_message_text(
            f"✅ Template '{template_name}' applied!\n\n"
            f"📝 Caption:\n{formatted[:500]}\n\n"
            "Choose next option:",
            reply_markup=caption_menu_keyboard(),
        )

    return CAPTION_MENU


# ============================================
#       UPLOAD FLOW - HASHTAGS
# ============================================
async def choose_hashtags(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle hashtag selection"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "back_caption":
        caption = context.user_data.get("caption", "No caption")
        await query.edit_message_text(
            f"📝 Caption:\n{caption[:300]}\n\nChoose option:",
            reply_markup=caption_menu_keyboard(),
        )
        return CAPTION_MENU

    if data == "hashtag_custom":
        await query.edit_message_text(
            "✍️ Send your custom hashtags:\n\n"
            "Example: #funny #viral #trending"
        )
        return CUSTOM_HASHTAGS

    hashtag_name = data.replace("hashtag_", "")

    if hashtag_name in HASHTAG_SETS:
        hashtags = HASHTAG_SETS[hashtag_name]
        context.user_data["hashtags"] = hashtags

        caption = context.user_data.get("caption", "")
        if hashtags not in caption:
            context.user_data["caption"] = f"{caption}\n\n{hashtags}"

        await query.edit_message_text(
            f"✅ '{hashtag_name}' hashtags added!\n\n"
            f"📝 Caption:\n{context.user_data['caption'][:500]}\n\n"
            "Choose next option:",
            reply_markup=caption_menu_keyboard(),
        )

    return CAPTION_MENU


async def custom_hashtags(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive custom hashtags"""
    hashtags = update.message.text.strip()

    if not hashtags:
        await update.message.reply_text("❌ Send valid hashtags:")
        return CUSTOM_HASHTAGS

    context.user_data["hashtags"] = hashtags
    caption = context.user_data.get("caption", "")
    context.user_data["caption"] = f"{caption}\n\n{hashtags}"

    await update.message.reply_text(
        f"✅ Custom hashtags added!\n\n"
        f"📝 Caption:\n{context.user_data['caption'][:500]}\n\n"
        "Choose next option:",
        reply_markup=caption_menu_keyboard(),
    )
    return CAPTION_MENU


# ============================================
#       UPLOAD FLOW - ACCOUNT SELECTION
# ============================================
async def choose_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle account selection"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "back_main":
        # Don't cleanup file here - let upload job handle it to prevent race conditions
        context.user_data.clear()
        await query.edit_message_text(
            "❌ Cancelled.",
            reply_markup=main_menu_keyboard(query.from_user.id),
        )
        return ConversationHandler.END

    if data == "ignore":
        return CHOOSE_ACCOUNT

    account = data.replace("account_", "")

    with ig_clients_lock:
        if account not in instagram_clients:
            await query.edit_message_text(
                f"❌ @{account} not connected!\nChoose another:",
                reply_markup=account_keyboard(),
            )
            return CHOOSE_ACCOUNT

    context.user_data["account"] = account

    # Check if bulk mode
    if context.user_data.get("bulk_mode"):
        return await process_bulk_upload(query, context, account)

    caption = context.user_data.get("caption", "No caption")
    title = context.user_data.get("title", "N/A")

    await query.edit_message_text(
        "╔══════════════════════════════╗\n"
        "║      📋 UPLOAD PREVIEW       ║\n"
        "╠══════════════════════════════╣\n"
        f"║  📹 {title[:24]}\n"
        f"║  📱 @{account}\n"
        "╠══════════════════════════════╣\n"
        f"║  📝 {caption[:80]}\n"
        "╚══════════════════════════════╝\n\n"
        "⏰ Choose upload timing:",
        reply_markup=timing_keyboard(),
    )
    return CHOOSE_TIMING


# ============================================
#       UPLOAD FLOW - TIMING
# ============================================
async def choose_timing(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle timing selection"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "back_main":
        # Don't cleanup file here - let upload job handle it to prevent race conditions
        context.user_data.clear()
        await query.edit_message_text(
            "❌ Cancelled.",
            reply_markup=main_menu_keyboard(query.from_user.id),
        )
        return ConversationHandler.END

    if data == "timing_custom":
        max_mins = MAX_SCHEDULE_DAYS * 24 * 60
        await query.edit_message_text(
            f"📅 Send delay in minutes (1 - {max_mins}):\n\n"
            "Examples:\n"
            "• 30 = 30 minutes\n"
            "• 120 = 2 hours\n"
            "• 1440 = 1 day"
        )
        return GET_SCHEDULE_TIME

    if data == "timing_now":
        delay = 0
    else:
        try:
            delay = int(data.replace("timing_", ""))
        except ValueError:
            delay = 0

    return await execute_upload(query, context, delay)


async def get_schedule_time(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive custom schedule time in minutes"""
    try:
        minutes = int(update.message.text.strip())
        max_mins = MAX_SCHEDULE_DAYS * 24 * 60

        if minutes < 1 or minutes > max_mins:
            await update.message.reply_text(
                f"❌ Must be between 1 and {max_mins} minutes.\n"
                "Try again:"
            )
            return GET_SCHEDULE_TIME

    except ValueError:
        await update.message.reply_text(
            "❌ Send a valid number. Try again:"
        )
        return GET_SCHEDULE_TIME

    file_path = context.user_data.get("file_path", "")
    caption = context.user_data.get("caption", "")
    account = context.user_data.get("account", "")
    source_url = context.user_data.get("source_url", "")
    user_id = update.effective_user.id

    save_scheduled_post(user_id, file_path, caption, minutes, account, source_url)

    scheduled_time = datetime.now() + timedelta(minutes=minutes)

    await update.message.reply_text(
        "╔══════════════════════════════╗\n"
        "║     ✅ POST SCHEDULED!       ║\n"
        "╠══════════════════════════════╣\n"
        f"║  📱 Account: @{account}\n"
        f"║  ⏰ At: {scheduled_time.strftime('%I:%M %p, %b %d')}\n"
        f"║  ⏳ In: {minutes} minutes\n"
        "╚══════════════════════════════╝",
        reply_markup=main_menu_keyboard(user_id),
    )
    return ConversationHandler.END


async def execute_upload(
    query, context: ContextTypes.DEFAULT_TYPE, delay_minutes: int
):
    """Execute or schedule the upload"""
    file_path = context.user_data.get("file_path", "")
    caption = context.user_data.get("caption", "")
    account = context.user_data.get("account", "")
    source_url = context.user_data.get("source_url", "")
    user_id = query.from_user.id
    chat_id = query.message.chat_id

    if delay_minutes == 0:
        # Upload now
        context.job_queue.run_once(
            upload_to_instagram,
            when=0,
            data={
                "file_path": file_path,
                "caption": caption,
                "chat_id": chat_id,
                "user_id": user_id,
                "source_url": source_url,
                "account": account,
            },
            name=f"upload_{user_id}_{datetime.now().timestamp()}",
        )

        await query.edit_message_text(
            "✅ Upload started!\n"
            "You'll be notified when it's done.",
            reply_markup=main_menu_keyboard(user_id),
        )

    else:
        # Schedule
        save_scheduled_post(user_id, file_path, caption, delay_minutes, account, source_url)
        scheduled_time = datetime.now() + timedelta(minutes=delay_minutes)

        await query.edit_message_text(
            "╔══════════════════════════════╗\n"
            "║     ✅ POST SCHEDULED!       ║\n"
            "╠══════════════════════════════╣\n"
            f"║  📱 Account: @{account}\n"
            f"║  ⏰ At: {scheduled_time.strftime('%I:%M %p, %b %d')}\n"
            f"║  ⏳ In: {delay_minutes} minutes\n"
            "╚══════════════════════════════╝",
            reply_markup=main_menu_keyboard(user_id),
        )

    return ConversationHandler.END


# ============================================
#       BULK UPLOAD HANDLERS
# ============================================
async def bulk_collect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Collect URLs for bulk upload"""
    text = update.message.text.strip()

    # Check for /done command
    if text == "/done":
        links = context.user_data.get("bulk_links", [])

        if not links:
            await update.message.reply_text(
                "❌ No links collected!\n"
                "Send video URLs first, then /done."
            )
            return BULK_COLLECT

        context.user_data["bulk_mode"] = True

        await update.message.reply_text(
            f"✅ {len(links)} links collected!\n\n"
            "📱 Choose Instagram account:",
            reply_markup=account_keyboard(),
        )
        return CHOOSE_ACCOUNT

    # Validate URL
    if not is_valid_url(text):
        await update.message.reply_text(
            "❌ Invalid URL!\n\n"
            "Send a valid video URL,\n"
            "/done to finish, or /cancel to exit."
        )
        return BULK_COLLECT

    # Check limit
    bulk_links = context.user_data.get("bulk_links", [])

    if len(bulk_links) >= MAX_BULK_LINKS:
        await update.message.reply_text(
            f"❌ Maximum {MAX_BULK_LINKS} links per batch!\n"
            "Send /done to proceed with current links."
        )
        return BULK_COLLECT

    # Add link
    bulk_links.append(text)
    context.user_data["bulk_links"] = bulk_links

    await update.message.reply_text(
        f"✅ Link #{len(bulk_links)} added!\n"
        f"📊 Total: {len(bulk_links)} links\n\n"
        "Send more URLs, /done to finish, or /cancel:"
    )
    return BULK_COLLECT


async def process_bulk_upload(
    query, context: ContextTypes.DEFAULT_TYPE, account: str
):
    """Process all collected bulk links"""
    links = context.user_data.get("bulk_links", [])
    user_id = query.from_user.id
    chat_id = query.message.chat_id

    await query.edit_message_text(
        f"⏳ Starting bulk upload...\n\n"
        f"📋 {len(links)} videos to process\n"
        f"📱 Account: @{account}\n"
        f"⏱️ Delay: {BULK_UPLOAD_DELAY}s between uploads\n\n"
        "This may take a while..."
    )

    success_count = 0
    fail_count = 0

    for i, url in enumerate(links):
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"⏳ [{i + 1}/{len(links)}] Downloading:\n{url[:60]}...",
            )

            media = download_media(url)

            # Use consistent spacing between uploads (not exponential)
            delay = i * BULK_UPLOAD_DELAY

            context.job_queue.run_once(
                upload_to_instagram,
                when=delay,
                data={
                    "file_path": media["file_path"],
                    "caption": media["caption"],
                    "chat_id": chat_id,
                    "user_id": user_id,
                    "source_url": url,
                    "account": account,
                },
                name=f"bulk_{user_id}_{i}_{datetime.now().timestamp()}",
            )

            success_count += 1

            await context.bot.send_message(
                chat_id=chat_id,
                text=f"✅ [{i + 1}/{len(links)}] Queued!\n"
                f"⏱️ Upload in {delay}s",
            )

        except Exception as e:
            fail_count += 1
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"❌ [{i + 1}/{len(links)}] Failed:\n{str(e)[:100]}",
            )
            log_upload(user_id, url, "", "failed", account)

    await context.bot.send_message(
        chat_id=chat_id,
        text=(
            "╔══════════════════════════════╗\n"
            "║    📋 BULK UPLOAD QUEUED     ║\n"
            "╠══════════════════════════════╣\n"
            f"║  ✅ Queued:  {success_count}\n"
            f"║  ❌ Failed:  {fail_count}\n"
            f"║  📱 Account: @{account}\n"
            f"║  ⏱️ Delay: {BULK_UPLOAD_DELAY}s between each\n"
            "╚══════════════════════════════╝"
        ),
        reply_markup=main_menu_keyboard(user_id),
    )

    # Cleanup
    context.user_data.pop("bulk_links", None)
    context.user_data.pop("bulk_mode", None)

    return ConversationHandler.END


# ============================================
#       ADMIN PANEL CALLBACK
# ============================================
async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin panel buttons"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id

    if not is_admin(user_id):
        await query.edit_message_text("⛔ Admin access required!")
        return ConversationHandler.END

    data = query.data

    if data == "ignore":
        return ADMIN_MENU

    if data == "back_main":
        await query.edit_message_text(
            "Main Menu:",
            reply_markup=main_menu_keyboard(user_id),
        )
        return ConversationHandler.END

    if data == "back_admin":
        await query.edit_message_text(
            "🔐 Admin Panel",
            reply_markup=admin_menu_keyboard(),
        )
        return ADMIN_MENU

    # --- USER MANAGEMENT ---

    if data == "admin_add_user":
        await query.edit_message_text(
            "➕ Add Authorized User\n\n"
            "Send the Telegram User ID:\n"
            "(User can get it from @userinfobot)",
            reply_markup=back_admin_button(),
        )
        return ADD_USER_ID

    if data == "admin_remove_user":
        users = get_all_authorized()

        if not users:
            await query.edit_message_text(
                "📋 No authorized users to remove.",
                reply_markup=back_admin_button(),
            )
            return ADMIN_MENU

        text = "➖ Remove Authorized User\n\n"
        text += "Current authorized users:\n"
        for uid in users:
            udata = users_col.find_one({"user_id": uid})
            name = udata.get("first_name", "Unknown") if udata else "Unknown"
            text += f"• {name} - `{uid}`\n"
        text += "\nSend the User ID to remove:"

        await query.edit_message_text(
            text,
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
        return REMOVE_USER_ID

    if data == "admin_list_users":
        users = get_all_authorized()

        if not users:
            text = "📋 No authorized users."
        else:
            text = f"📋 Authorized Users ({len(users)}):\n\n"
            for uid in users:
                udata = users_col.find_one({"user_id": uid})
                name = udata.get("first_name", "Unknown") if udata else "Unknown"
                uname = udata.get("username", "N/A") if udata else "N/A"
                text += f"• {name} (@{uname}) - `{uid}`\n"

        await query.edit_message_text(
            text,
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
        return ADMIN_MENU

    # --- ADMIN MANAGEMENT ---

    if data == "admin_add_admin":
        await query.edit_message_text(
            "👑 Add New Admin\n\n"
            "Send the Telegram User ID:",
            reply_markup=back_admin_button(),
        )
        return ADD_ADMIN_ID

    if data == "admin_remove_admin":
        admins = get_all_admins()

        text = "👑 Remove Admin\n\nCurrent admins:\n"
        for aid in admins:
            adat = users_col.find_one({"user_id": aid})
            name = adat.get("first_name", "Unknown") if adat else "Unknown"
            protected = " 🛡️ (protected)" if aid == FIRST_ADMIN_ID else ""
            text += f"• {name} - `{aid}`{protected}\n"
        text += "\nSend Admin ID to remove:"

        await query.edit_message_text(
            text,
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
        return REMOVE_ADMIN_ID

    if data == "admin_list_admins":
        admins = get_all_admins()

        text = f"👑 Admin List ({len(admins)}):\n\n"
        for aid in admins:
            adat = users_col.find_one({"user_id": aid})
            name = adat.get("first_name", "Unknown") if adat else "Unknown"
            uname = adat.get("username", "N/A") if adat else "N/A"
            protected = " 🛡️" if aid == FIRST_ADMIN_ID else ""
            text += f"• {name} (@{uname}) - `{aid}`{protected}\n"

        await query.edit_message_text(
            text,
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
        return ADMIN_MENU

    # --- INSTAGRAM MANAGEMENT ---

    if data == "admin_add_ig":
        await query.edit_message_text(
            "📱 Add Instagram Account\n\n"
            "Send the Instagram USERNAME\n"
            "(without @ symbol):",
            reply_markup=back_admin_button(),
        )
        return ADD_ACCOUNT_USER

    if data == "admin_remove_ig":
        accounts = get_all_ig_accounts()

        if not accounts:
            await query.edit_message_text(
                "📱 No Instagram accounts to remove.",
                reply_markup=back_admin_button(),
            )
            return ADMIN_MENU

        buttons = []
        for acc in accounts:
            with ig_clients_lock:
                connected = acc["username"] in instagram_clients
            icon = "🟢" if connected else "🔴"
            buttons.append(
                [
                    InlineKeyboardButton(
                        f"{icon} @{acc['username']}",
                        callback_data=f"rmig_{acc['username']}",
                    )
                ]
            )
        buttons.append(
            [InlineKeyboardButton("🔙 Back", callback_data="back_admin")]
        )

        await query.edit_message_text(
            "➖ Select account to remove:",
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return REMOVE_ACCOUNT

    if data == "admin_list_ig":
        accounts = get_all_ig_accounts()

        if not accounts:
            text = "📱 No Instagram accounts configured."
        else:
            text = f"📱 Instagram Accounts ({len(accounts)}):\n\n"
            for acc in accounts:
                with ig_clients_lock:
                    connected = acc["username"] in instagram_clients
                status = "🟢 Connected" if connected else "🔴 Offline"
                text += f"• @{acc['username']} - {status}\n"

        await query.edit_message_text(
            text, reply_markup=back_admin_button()
        )
        return ADMIN_MENU

    # --- GLOBAL STATS ---

    if data == "admin_global_stats":
        stats = get_all_stats()

        text = (
            "╔══════════════════════════════╗\n"
            "║     📊 GLOBAL STATISTICS     ║\n"
            "╠══════════════════════════════╣\n"
            f"║  👥 Users:       {stats.get('total_users', 0):<11} ║\n"
            f"║  👑 Admins:      {stats.get('total_admins', 0):<11} ║\n"
            f"║  🔑 Auth Users:  {stats.get('total_auth_users', 0):<11} ║\n"
            f"║  📱 IG Accounts: {stats.get('total_accounts', 0):<11} ║\n"
            "╠══════════════════════════════╣\n"
            f"║  📤 Uploads:     {stats.get('total_uploads', 0):<11} ║\n"
            f"║  ✅ Success:     {stats.get('total_success', 0):<11} ║\n"
            f"║  ❌ Failed:      {stats.get('total_failed', 0):<11} ║\n"
            f"║  📅 Today:       {stats.get('today_uploads', 0):<11} ║\n"
            f"║  ⏳ Pending:     {stats.get('total_pending', 0):<11} ║\n"
            "╚══════════════════════════════╝"
        )

        await query.edit_message_text(
            validate_message_length(text), 
            reply_markup=back_admin_button()
        )
        return ADMIN_MENU

    return ADMIN_MENU


# ============================================
#       ADMIN INPUT HANDLERS
# ============================================
async def add_user_id_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive user ID to authorize"""
    try:
        new_id = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text(
            "❌ Invalid! Send a numeric User ID:"
        )
        return ADD_USER_ID

    add_authorized_user(new_id, update.effective_user.id)

    await update.message.reply_text(
        f"✅ User `{new_id}` has been authorized!",
        parse_mode="Markdown",
        reply_markup=back_admin_button(),
    )
    return ADMIN_MENU


async def remove_user_id_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive user ID to remove"""
    try:
        rm_id = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text(
            "❌ Invalid! Send a numeric User ID:"
        )
        return REMOVE_USER_ID

    if remove_authorized_user(rm_id):
        await update.message.reply_text(
            f"✅ User `{rm_id}` has been removed!",
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
    else:
        await update.message.reply_text(
            f"❌ User `{rm_id}` not found in authorized list.",
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
    return ADMIN_MENU


async def add_admin_id_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive user ID to make admin"""
    try:
        new_id = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text(
            "❌ Invalid! Send a numeric User ID:"
        )
        return ADD_ADMIN_ID

    add_admin(new_id, update.effective_user.id)

    await update.message.reply_text(
        f"✅ User `{new_id}` is now an admin!",
        parse_mode="Markdown",
        reply_markup=back_admin_button(),
    )
    return ADMIN_MENU


async def remove_admin_id_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive admin ID to remove"""
    try:
        rm_id = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text(
            "❌ Invalid! Send a numeric User ID:"
        )
        return REMOVE_ADMIN_ID

    if rm_id == FIRST_ADMIN_ID:
        await update.message.reply_text(
            "❌ Cannot remove the primary admin!\n"
            "This admin is protected.",
            reply_markup=back_admin_button(),
        )
        return ADMIN_MENU

    if remove_admin(rm_id):
        await update.message.reply_text(
            f"✅ Admin `{rm_id}` has been removed!",
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
    else:
        await update.message.reply_text(
            f"❌ Admin `{rm_id}` not found.",
            parse_mode="Markdown",
            reply_markup=back_admin_button(),
        )
    return ADMIN_MENU


async def add_ig_user_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive Instagram username"""
    username = update.message.text.strip().replace("@", "")

    if not username or len(username) < 2:
        await update.message.reply_text(
            "❌ Invalid username. Try again:"
        )
        return ADD_ACCOUNT_USER

    context.user_data["new_ig_user"] = username

    await update.message.reply_text(
        f"📱 Username: @{username}\n\n"
        "Now send the Instagram PASSWORD:\n\n"
        "⚠️ Password will be encrypted.\n"
        "⚠️ Your message will be deleted."
    )
    return ADD_ACCOUNT_PASS


async def add_ig_pass_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Receive Instagram password"""
    password = update.message.text.strip()
    username = context.user_data.get("new_ig_user", "")

    # Delete password message
    try:
        await update.message.delete()
    except Exception:
        pass

    if not password or len(password) < 6:
        await update.effective_chat.send_message(
            "❌ Password too short (min 6 chars). Try again:"
        )
        return ADD_ACCOUNT_PASS

    status_msg = await update.effective_chat.send_message(
        f"⏳ Logging into @{username}...\n"
        "This may take a moment."
    )

    success, msg = login_ig_account(username, password)

    if success:
        save_ig_account(username, password, update.effective_user.id)
        await status_msg.edit_text(
            f"✅ @{username} connected successfully!\n\n"
            "Account saved and encrypted.",
            reply_markup=back_admin_button(),
        )
        return ADMIN_MENU
    else:
        await status_msg.edit_text(
            f"❌ Login failed for @{username}\n"
            f"Reason: {msg}\n\n"
            "Send USERNAME again to retry\n"
            "or /cancel to go back.",
        )
        return ADD_ACCOUNT_USER


async def remove_ig_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Handle Instagram account removal button"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "back_admin":
        await query.edit_message_text(
            "🔐 Admin Panel",
            reply_markup=admin_menu_keyboard(),
        )
        return ADMIN_MENU

    if data.startswith("rmig_"):
        username = data.replace("rmig_", "")

        if remove_ig_account(username):
            await query.edit_message_text(
                f"✅ @{username} has been removed!",
                reply_markup=back_admin_button(),
            )
        else:
            await query.edit_message_text(
                f"❌ @{username} not found.",
                reply_markup=back_admin_button(),
            )
        return ADMIN_MENU

    return ADMIN_MENU


# ============================================
#       SETTINGS HANDLERS
# ============================================
async def settings_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Handle settings menu"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    data = query.data

    if data == "back_main":
        await query.edit_message_text(
            "Main Menu:",
            reply_markup=main_menu_keyboard(user_id),
        )
        return ConversationHandler.END

    if data == "back_settings":
        await query.edit_message_text(
            "⚙️ User Settings",
            reply_markup=settings_keyboard(),
        )
        return SETTINGS_MENU

    if data == "setting_template":
        buttons = []
        for name in CAPTION_TEMPLATES:
            buttons.append(
                [
                    InlineKeyboardButton(
                        f"📝 {name.title()}",
                        callback_data=f"settemplate_{name}",
                    )
                ]
            )
        buttons.append(
            [
                InlineKeyboardButton(
                    "🔙 Back", callback_data="back_settings"
                )
            ]
        )

        await query.edit_message_text(
            "📝 Choose default caption template:",
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return SETTINGS_MENU

    if data == "setting_hashtags":
        buttons = []
        row = []
        for name in HASHTAG_SETS:
            row.append(
                InlineKeyboardButton(
                    f"#{name}", callback_data=f"sethashtag_{name}"
                )
            )
            if len(row) == 2:
                buttons.append(row)
                row = []
        if row:
            buttons.append(row)
        buttons.append(
            [
                InlineKeyboardButton(
                    "🚫 None", callback_data="sethashtag_none"
                )
            ]
        )
        buttons.append(
            [
                InlineKeyboardButton(
                    "🔙 Back", callback_data="back_settings"
                )
            ]
        )

        await query.edit_message_text(
            "#️⃣ Choose default hashtags:",
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return SETTINGS_MENU

    if data == "setting_account":
        with ig_clients_lock:
            accs = list(instagram_clients.keys())

        if not accs:
            await query.edit_message_text(
                "❌ No accounts available.",
                reply_markup=settings_keyboard(),
            )
            return SETTINGS_MENU

        buttons = []
        for acc in accs:
            buttons.append(
                [
                    InlineKeyboardButton(
                        f"📱 @{acc}", callback_data=f"setaccount_{acc}"
                    )
                ]
            )
        buttons.append(
            [
                InlineKeyboardButton(
                    "🔙 Back", callback_data="back_settings"
                )
            ]
        )

        await query.edit_message_text(
            "📱 Choose default account:",
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return SETTINGS_MENU

    if data.startswith("settemplate_"):
        tname = data.replace("settemplate_", "")
        save_user_settings(user_id, "default_template", tname)
        await query.edit_message_text(
            f"✅ Default template set to: {tname.title()}",
            reply_markup=settings_keyboard(),
        )
        return SETTINGS_MENU

    if data.startswith("sethashtag_"):
        hname = data.replace("sethashtag_", "")
        if hname == "none":
            save_user_settings(user_id, "default_hashtags", "")
            await query.edit_message_text(
                "✅ Default hashtags cleared!",
                reply_markup=settings_keyboard(),
            )
        else:
            save_user_settings(user_id, "default_hashtags", hname)
            await query.edit_message_text(
                f"✅ Default hashtags set to: {hname}",
                reply_markup=settings_keyboard(),
            )
        return SETTINGS_MENU

    if data.startswith("setaccount_"):
        acc = data.replace("setaccount_", "")
        save_user_settings(user_id, "default_account", acc)
        await query.edit_message_text(
            f"✅ Default account set to: @{acc}",
            reply_markup=settings_keyboard(),
        )
        return SETTINGS_MENU

    return SETTINGS_MENU


# ============================================
#       QUICK COMMANDS
# ============================================
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command"""
    cleanup_file(context.user_data.get("file_path"))
    context.user_data.clear()

    await update.message.reply_text(
        "❌ Action cancelled.",
        reply_markup=main_menu_keyboard(update.effective_user.id),
    )
    return ConversationHandler.END


async def quick_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stats command"""
    user_id = update.effective_user.id

    if not is_authorized(user_id):
        await update.message.reply_text("⛔ Access denied.")
        return

    stats = get_user_stats(user_id)
    await update.message.reply_text(
        f"📊 Quick Stats:\n"
        f"Total: {stats['total']} | "
        f"✅ {stats['success']} | "
        f"❌ {stats['failed']} | "
        f"Today: {stats['today']}"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    await update.message.reply_text(
        "╔══════════════════════════════╗\n"
        "║         ❓ BOT HELP          ║\n"
        "╠══════════════════════════════╣\n"
        "║                              ║\n"
        "║  /start  - Open main menu    ║\n"
        "║  /cancel - Cancel action     ║\n"
        "║  /stats  - View quick stats  ║\n"
        "║  /help   - Show this help    ║\n"
        "║                              ║\n"
        "╚══════════════════════════════╝"
    )


async def unknown_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle unknown messages"""
    user_id = update.effective_user.id

    if not is_authorized(user_id):
        return

    await update.message.reply_text(
        "❓ Unknown command.\n"
        "Use /start to open the main menu.",
        reply_markup=main_menu_keyboard(user_id),
    )


# ============================================
#       ERROR HANDLER
# ============================================
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all errors"""
    logger.error(
        f"Error: {context.error}",
        exc_info=context.error,
    )

    try:
        if update and update.effective_chat:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="❌ Something went wrong.\n"
                "Please try again with /start",
            )
    except Exception:
        pass


# ============================================
#       POST INIT - SET COMMANDS
# ============================================
async def post_init(application: Application):
    """Set bot commands after startup"""
    commands = [
        BotCommand("start", "🏠 Main Menu"),
        BotCommand("cancel", "❌ Cancel current action"),
        BotCommand("stats", "📊 Quick stats"),
        BotCommand("help", "❓ Help"),
    ]
    await application.bot.set_my_commands(commands)
    logger.info("✅ Bot commands registered!")


# ============================================
#       SHUTDOWN
# ============================================
async def shutdown(application: Application):
    """Cleanup on shutdown"""
    logger.info("🔄 Shutting down...")

    try:
        mongo_client.close()
        logger.info("✅ MongoDB closed.")
    except Exception:
        pass

    cleanup_old_downloads()
    logger.info("✅ Shutdown complete.")


# ============================================
#              MAIN FUNCTION
# ============================================
def main():
    """Start the bot"""
    print("")
    print("=" * 50)
    print("🎬 Instagram Reel Uploader Bot")
    print("=" * 50)
    print("")

    # Initialize admin
    init_first_admin()

    # Load Instagram accounts
    logger.info("📱 Loading Instagram accounts...")
    load_all_ig_accounts()
    logger.info(f"📱 {len(instagram_clients)} account(s) loaded.")

    # Build application
    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(shutdown)
        .build()
    )

    # ============================================
    #       CONVERSATION HANDLER
    # ============================================
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
        ],
        states={
            # First time setup
            SETUP_FIRST_ACCOUNT_USER: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    setup_first_account_user,
                ),
            ],
            SETUP_FIRST_ACCOUNT_PASS: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    setup_first_account_pass,
                ),
            ],
            # Upload flow
            GET_LINK: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    get_link,
                ),
            ],
            CAPTION_MENU: [
                CallbackQueryHandler(
                    caption_callback, pattern="^caption_"
                ),
                CallbackQueryHandler(
                    menu_callback, pattern="^back_"
                ),
            ],
            GET_NEW_CAPTION: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    get_new_caption,
                ),
            ],
            CHOOSE_TEMPLATE: [
                CallbackQueryHandler(
                    choose_template, pattern="^template_"
                ),
                CallbackQueryHandler(
                    choose_template, pattern="^back_caption$"
                ),
            ],
            CHOOSE_HASHTAGS: [
                CallbackQueryHandler(
                    choose_hashtags, pattern="^hashtag_"
                ),
                CallbackQueryHandler(
                    choose_hashtags, pattern="^back_caption$"
                ),
            ],
            CUSTOM_HASHTAGS: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    custom_hashtags,
                ),
            ],
            CHOOSE_ACCOUNT: [
                CallbackQueryHandler(
                    choose_account, pattern="^account_"
                ),
                CallbackQueryHandler(
                    menu_callback, pattern="^back_main$"
                ),
                CallbackQueryHandler(
                    choose_account, pattern="^ignore$"
                ),
            ],
            CHOOSE_TIMING: [
                CallbackQueryHandler(
                    choose_timing, pattern="^timing_"
                ),
                CallbackQueryHandler(
                    menu_callback, pattern="^back_main$"
                ),
            ],
            GET_SCHEDULE_TIME: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    get_schedule_time,
                ),
            ],
            # Bulk upload
            BULK_COLLECT: [
                MessageHandler(filters.TEXT, bulk_collect),
            ],
            # Admin panel
            ADMIN_MENU: [
                CallbackQueryHandler(
                    admin_callback, pattern="^admin_"
                ),
                CallbackQueryHandler(
                    menu_callback, pattern="^back_main$"
                ),
                CallbackQueryHandler(
                    admin_callback, pattern="^back_admin$"
                ),
                CallbackQueryHandler(
                    admin_callback, pattern="^ignore$"
                ),
            ],
            ADD_USER_ID: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    add_user_id_handler,
                ),
            ],
            REMOVE_USER_ID: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    remove_user_id_handler,
                ),
            ],
            ADD_ADMIN_ID: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    add_admin_id_handler,
                ),
            ],
            REMOVE_ADMIN_ID: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    remove_admin_id_handler,
                ),
            ],
            ADD_ACCOUNT_USER: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    add_ig_user_handler,
                ),
            ],
            ADD_ACCOUNT_PASS: [
                MessageHandler(
                    filters.TEXT & ~filters.COMMAND,
                    add_ig_pass_handler,
                ),
            ],
            REMOVE_ACCOUNT: [
                CallbackQueryHandler(
                    remove_ig_callback, pattern="^rmig_"
                ),
                CallbackQueryHandler(
                    remove_ig_callback, pattern="^back_admin$"
                ),
            ],
            # Settings
            SETTINGS_MENU: [
                CallbackQueryHandler(
                    settings_callback, pattern="^setting_"
                ),
                CallbackQueryHandler(
                    settings_callback, pattern="^settemplate_"
                ),
                CallbackQueryHandler(
                    settings_callback, pattern="^sethashtag_"
                ),
                CallbackQueryHandler(
                    settings_callback, pattern="^setaccount_"
                ),
                CallbackQueryHandler(
                    settings_callback, pattern="^back_settings$"
                ),
                CallbackQueryHandler(
                    menu_callback, pattern="^back_main$"
                ),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            CommandHandler("start", start),
        ],
        allow_reentry=True,
        per_message=False,
    )

    # Register handlers
    application.add_handler(conv_handler)

    # Standalone menu callbacks (outside conversation)
    application.add_handler(
        CallbackQueryHandler(menu_callback, pattern="^menu_")
    )
    application.add_handler(
        CallbackQueryHandler(menu_callback, pattern="^back_main$")
    )

    # Quick commands
    application.add_handler(CommandHandler("stats", quick_stats))
    application.add_handler(CommandHandler("help", help_command))

    # Unknown messages fallback
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, unknown_message)
    )

    # Error handler
    application.add_error_handler(error_handler)

    # ============================================
    #       SCHEDULED JOBS
    # ============================================
    job_queue = application.job_queue

    # Check scheduled posts every minute
    job_queue.run_repeating(
        check_scheduled_posts,
        interval=SCHEDULED_CHECK_INTERVAL,
        first=10,
        name="scheduled_checker",
    )

    # Cleanup old downloads every hour
    job_queue.run_repeating(
        cleanup_job,
        interval=3600,
        first=60,
        name="cleanup_job",
    )

    # ============================================
    #       START BOT
    # ============================================
    print(f"👑 Primary Admin: {FIRST_ADMIN_ID}")
    print(f"📱 IG Accounts:   {len(instagram_clients)}")

    try:
        admin_count = admins_col.count_documents({})
        auth_count = auth_col.count_documents({})
        print(f"👑 Total Admins:  {admin_count}")
        print(f"👥 Auth Users:    {auth_count}")
    except Exception:
        pass

    print("")
    print("✅ Bot is running! Press Ctrl+C to stop.")
    print("=" * 50)
    print("")

    logger.info("✅ Bot started successfully!")

    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )


# ============================================
#       RUN
# ============================================
if __name__ == "__main__":
    main()