# ============================================
#       SECURE CONFIGURATION FILE
#       Use environment variables instead!
# ============================================
import os

# Telegram Bot Token
# Get from @BotFather on Telegram
# SECURITY: Set via environment variable!
BOT_TOKEN = os.getenv('BOT_TOKEN', '16638638040:6638638040:AAE08LSPDOdI0ksjz8b8CuNrg-gnNzqS534')

# MongoDB Connection String
# Get from MongoDB Atlas Dashboard
# SECURITY: Set via environment variable!
MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://mariosglade_db_user:<db_password>@cluster0.fagx1yc.mongodb.net/?appName=Cluster0')

# Your Telegram User ID
# Get from @userinfobot on Telegram
FIRST_ADMIN_ID = int(os.getenv('FIRST_ADMIN_ID', '1623892821'))

# Encryption Key for Instagram Passwords
# LEAVE EMPTY first time - bot will generate it
# Then set it as environment variable
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '0r9gDlaMxS2Fi4-6J1Me4axMJ3cSSxTKtfdHL0b5VJY=')

# ============================================
#       RATE LIMITS & SETTINGS
# ============================================
RATE_LIMIT_SECONDS = 30
MAX_SCHEDULE_DAYS = 7
BULK_UPLOAD_DELAY = 300
MAX_FILE_SIZE_MB = 100
DOWNLOAD_TIMEOUT = 300
IG_UPLOAD_COOLDOWN = 60
MAX_CAPTION_LENGTH = 2200
SCHEDULED_CHECK_INTERVAL = 60
MAX_RETRIES = 3
MAX_BULK_LINKS = 20

# ============================================
#       SUPPORTED PLATFORMS
# ============================================
SUPPORTED_URL_PATTERNS = [
    r"(https?://)?(www\.)?(youtube\.com|youtu\.be)/",
    r"(https?://)?(www\.)?(tiktok\.com|vm\.tiktok\.com)/",
    r"(https?://)?(www\.)?instagram\.com/",
    r"(https?://)?(www\.)?twitter\.com/",
    r"(https?://)?(www\.)?x\.com/",
    r"(https?://)?(www\.)?facebook\.com/",
    r"(https?://)?(www\.)?reddit\.com/",
    r"(https?://)?(www\.)?vimeo\.com/",
    r"(https?://)?(www\.)?dailymotion\.com/",
    r"(https?://)?(www\.)?twitch\.tv/",
]

# ============================================
#       HASHTAG PRESETS
# ============================================
HASHTAG_SETS = {
    "viral": "#viral #trending #explore #fyp #reels #foryou",
    "funny": "#funny #comedy #lol #memes #humor #laugh",
    "fitness": "#fitness #gym #workout #health #motivation #fit",
    "tech": "#tech #technology #coding #programming #ai #developer",
    "travel": "#travel #wanderlust #explore #adventure #nature #world",
    "food": "#food #foodie #recipe #yummy #delicious #cooking",
    "music": "#music #song #beats #hiphop #rap #singer",
    "fashion": "#fashion #style #outfit #ootd #trendy #model",
    "gaming": "#gaming #gamer #gameplay #twitch #esports #ps5",
    "motivation": "#motivation #success #grind #hustle #mindset #goals",
}

# ============================================
#       CAPTION TEMPLATES
# ============================================
CAPTION_TEMPLATES = {
    "simple": "{caption}\n\n{hashtags}",
    "fire": "🔥 {caption} 🔥\n\n{hashtags}",
    "clean": "{caption}\n.\n.\n.\n{hashtags}",
    "star": "⭐ {caption} ⭐\n\n{hashtags}",
    "minimal": "{caption}",
    "arrow": "➤ {caption}\n\n{hashtags}",
    "wave": "〰️ {caption} 〰️\n\n{hashtags}",
}

# ============================================
#       HOW TO USE THIS SECURELY
# ============================================
"""
Instead of putting secrets directly in this file:

1. Create a .env file (add to .gitignore!):
   BOT_TOKEN=your_token_here
   MONGO_URI=your_mongo_uri
   FIRST_ADMIN_ID=123456789
   ENCRYPTION_KEY=your_key_here

2. Install python-dotenv:
   pip install python-dotenv

3. Load .env at the start of bot.py:
   from dotenv import load_dotenv
   load_dotenv()

4. Or set as system environment variables:
   export BOT_TOKEN="your_token"
   export MONGO_URI="your_uri"
   # etc.

NEVER commit .env or config.py with real credentials to Git!
"""
