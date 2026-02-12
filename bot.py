"""
REFACTORED INSTAGRAM LOGIN FUNCTIONS
Drop-in replacement for your existing bot.py login functions

These replace the login_ig_account, setup_first_account_pass,
and add_ig_pass_handler functions in your bot.py
"""

import os
import asyncio
import logging
from datetime import datetime
from typing import Optional, Tuple

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, ConversationHandler

from instagram_auth import InstagramAuthManager, LoginStatus, ChallengeMethod
from telegram_login_handlers import InstagramLoginHandler

# Assuming these are imported from your config
# from config import ACTIVE_ENCRYPTION_KEY

logger = logging.getLogger(__name__)

# ============================================
#       INITIALIZE AUTH MANAGER (GLOBAL)
# ============================================
# Add this to your bot.py global initialization section

# Initialize Instagram Auth Manager
ig_auth_manager = InstagramAuthManager(
    sessions_dir="sessions",
    encryption_key=ACTIVE_ENCRYPTION_KEY,  # Your existing encryption key
    mongo_collection=accounts_col,  # Your MongoDB collection for accounts
    session_timeout_days=90,
)

# Initialize Login Handler
ig_login_handler = InstagramLoginHandler(
    auth_manager=ig_auth_manager,
    active_clients=instagram_clients,  # Your existing clients dict
    clients_lock=ig_clients_lock,  # Your existing lock
)


# ============================================
#       UPDATED LOGIN FUNCTION
# ============================================

async def login_ig_account_v2(username: str, password: str) -> Tuple[bool, str, Optional[Client]]:
    """
    Production-grade Instagram login with session management
    
    This replaces your existing login_ig_account function
    
    Args:
        username: Raw Instagram username (will be sanitized)
        password: Instagram password
        
    Returns:
        Tuple of (success, message, client)
    """
    # Sanitize username
    username = ig_auth_manager.sanitize_username(username)
    
    # Validate username
    is_valid, error_msg = ig_auth_manager.validate_username(username)
    if not is_valid:
        return False, f"Invalid username: {error_msg}", None
    
    try:
        # Attempt login with session management
        client, status, message = await ig_auth_manager.login_with_session(
            username, password
        )
        
        if status == LoginStatus.SUCCESS:
            # Success - store in global clients dict
            with ig_clients_lock:
                instagram_clients[username] = client
            
            logger.info(f"✅ Instagram @{username} logged in successfully")
            return True, "Success", client
        
        elif status == LoginStatus.TWO_FACTOR_REQUIRED:
            return False, "2FA required - please complete via Telegram", None
        
        elif status == LoginStatus.CHALLENGE_REQUIRED:
            return False, "Challenge required - please complete via Telegram", None
        
        elif status == LoginStatus.BAD_PASSWORD:
            return False, "Incorrect password", None
        
        elif status == LoginStatus.RATE_LIMITED:
            return False, "Rate limited - wait a few minutes", None
        
        else:
            return False, message, None
    
    except Exception as e:
        logger.error(f"Login error for @{username}: {e}")
        return False, str(e)[:200], None


# ============================================
#       UPDATED FIRST ACCOUNT SETUP
# ============================================

async def setup_first_account_user_v2(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Receive Instagram username for first setup (with validation)
    
    This replaces your existing setup_first_account_user function
    """
    raw_username = update.message.text.strip()
    
    # Sanitize username
    username = ig_auth_manager.sanitize_username(raw_username)
    
    # Validate username
    is_valid, error_msg = ig_auth_manager.validate_username(username)
    
    if not is_valid:
        await update.message.reply_text(
            f"❌ Invalid username: {error_msg}\n\n"
            "Please send a valid Instagram username:"
        )
        return SETUP_FIRST_ACCOUNT_USER
    
    context.user_data["setup_ig_user"] = username
    
    await update.message.reply_text(
        f"📱 Username: @{username}\n\n"
        "Now send your Instagram PASSWORD:\n\n"
        "🔒 Security:\n"
        "• Password will be encrypted with AES-256\n"
        "• Your message will be deleted immediately\n"
        "• Password is never logged\n\n"
        "⚠️ Make sure this chat is private!"
    )
    
    return SETUP_FIRST_ACCOUNT_PASS


async def setup_first_account_pass_v2(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Receive Instagram password for first setup (with 2FA/challenge support)
    
    This replaces your existing setup_first_account_pass function
    """
    password = update.message.text.strip()
    username = context.user_data.get("setup_ig_user", "")
    
    # Delete password message immediately
    try:
        await update.message.delete()
    except Exception:
        pass
    
    if not password or len(password) < 6:
        await update.effective_chat.send_message(
            "❌ Password too short (minimum 6 characters)\n\n"
            "Please send your Instagram password:"
        )
        return SETUP_FIRST_ACCOUNT_PASS
    
    status_msg = await update.effective_chat.send_message(
        f"⏳ Logging into @{username}...\n"
        "This may take a moment."
    )
    
    try:
        # Attempt login
        client, status, message = await ig_auth_manager.login_with_session(
            username, password
        )
        
        if status == LoginStatus.SUCCESS:
            # Success
            with ig_clients_lock:
                instagram_clients[username] = client
            
            save_ig_account(username, password, update.effective_user.id)
            
            await status_msg.edit_text(
                f"✅ @{username} connected successfully!\n\n"
                "🎉 Setup complete! You can now use the bot.\n"
                "💾 Session saved for future use."
            )
            
            await update.effective_chat.send_message(
                "Choose an option:",
                reply_markup=main_menu_keyboard(update.effective_user.id),
            )
            
            return ConversationHandler.END
        
        elif status == LoginStatus.TWO_FACTOR_REQUIRED:
            # 2FA needed - store username and password
            context.user_data['ig_username'] = username
            context.user_data['ig_password'] = password
            
            await status_msg.edit_text(
                "🔐 Two-Factor Authentication Required\n\n"
                "Instagram has sent a verification code to your device.\n\n"
                "Please send the 6-digit code:"
            )
            
            # Transition to 2FA state
            return SETUP_2FA_CODE  # New state you'll need to add
        
        elif status == LoginStatus.CHALLENGE_REQUIRED:
            # Challenge needed
            context.user_data['ig_username'] = username
            context.user_data['ig_password'] = password
            
            keyboard = [
                [
                    InlineKeyboardButton("📧 Email", callback_data=f"challenge_email:{username}"),
                    InlineKeyboardButton("📱 SMS", callback_data=f"challenge_sms:{username}"),
                ],
                [InlineKeyboardButton("❌ Cancel", callback_data="challenge_cancel")],
            ]
            
            await status_msg.edit_text(
                "🛡️ Security Challenge Required\n\n"
                "Instagram needs to verify your identity.\n\n"
                "Choose how to receive your verification code:",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            
            # Transition to challenge state
            return SETUP_CHALLENGE_METHOD  # New state you'll need to add
        
        elif status == LoginStatus.BAD_PASSWORD:
            await status_msg.edit_text(
                f"❌ Incorrect password for @{username}\n\n"
                "Please check and send the correct password:"
            )
            return SETUP_FIRST_ACCOUNT_PASS
        
        elif status == LoginStatus.RATE_LIMITED:
            await status_msg.edit_text(
                "⏸️ Rate Limited\n\n"
                "Instagram has temporarily blocked login attempts.\n"
                "Please wait 5-10 minutes and try again.\n\n"
                "Use /start to retry later."
            )
            return ConversationHandler.END
        
        else:
            await status_msg.edit_text(
                f"❌ Login failed: {message}\n\n"
                "Send Instagram USERNAME again to retry:"
            )
            return SETUP_FIRST_ACCOUNT_USER
    
    except Exception as e:
        logger.error(f"Setup error for @{username}: {e}")
        await status_msg.edit_text(
            f"❌ Unexpected error: {str(e)[:100]}\n\n"
            "Send Instagram USERNAME to retry:"
        )
        return SETUP_FIRST_ACCOUNT_USER


# ============================================
#       NEW 2FA HANDLER FOR SETUP
# ============================================

async def setup_2fa_code_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Handle 2FA code during first account setup
    
    Add this as a new handler in your bot
    """
    username = context.user_data.get('ig_username', '')
    code = update.message.text.strip()
    
    # Delete code message
    try:
        await update.message.delete()
    except:
        pass
    
    # Validate code
    if not code.isdigit() or len(code) != 6:
        await update.effective_chat.send_message(
            "❌ Invalid code format\n\n"
            "Please send the 6-digit code:"
        )
        return SETUP_2FA_CODE
    
    status_msg = await update.effective_chat.send_message(
        "⏳ Verifying code..."
    )
    
    try:
        # Complete 2FA
        client, status, message = await ig_auth_manager.complete_2fa(username, code)
        
        if status == LoginStatus.SUCCESS:
            # Success
            with ig_clients_lock:
                instagram_clients[username] = client
            
            password = context.user_data.get('ig_password', '')
            save_ig_account(username, password, update.effective_user.id)
            
            # Clear password
            context.user_data.pop('ig_password', None)
            
            await status_msg.edit_text(
                f"✅ Two-Factor Authentication Successful!\n\n"
                f"@{username} is now connected.\n"
                "🎉 Setup complete!"
            )
            
            await update.effective_chat.send_message(
                "Choose an option:",
                reply_markup=main_menu_keyboard(update.effective_user.id),
            )
            
            return ConversationHandler.END
        else:
            await status_msg.edit_text(
                f"❌ Verification failed: {message}\n\n"
                "Please send the code again or /cancel to abort:"
            )
            return SETUP_2FA_CODE
    
    except Exception as e:
        logger.error(f"2FA error: {e}")
        await status_msg.edit_text(
            f"❌ Error: {str(e)[:100]}\n\n"
            "Try again or /cancel"
        )
        return SETUP_2FA_CODE


# ============================================
#       NEW CHALLENGE HANDLERS FOR SETUP
# ============================================

async def setup_challenge_method_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Handle challenge method selection during setup
    
    Add this as a new callback handler
    """
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data == "challenge_cancel":
        username = context.user_data.get('ig_username', '')
        ig_auth_manager.cancel_challenge(username)
        context.user_data.pop('ig_password', None)
        
        await query.edit_message_text(
            "❌ Setup cancelled\n\n"
            "Use /start to try again."
        )
        return ConversationHandler.END
    
    # Parse method
    if data.startswith("challenge_email:"):
        method = ChallengeMethod.EMAIL
        method_name = "Email"
        username = data.split(':')[1]
    elif data.startswith("challenge_sms:"):
        method = ChallengeMethod.SMS
        method_name = "SMS"
        username = data.split(':')[1]
    else:
        await query.edit_message_text("❌ Invalid selection")
        return ConversationHandler.END
    
    status_msg = await query.edit_message_text(
        f"📤 Sending code via {method_name}..."
    )
    
    try:
        success, message = await ig_auth_manager.send_challenge_code(username, method)
        
        if success:
            await status_msg.edit_text(
                f"✅ Code sent to your {method_name.lower()}!\n\n"
                "Please send the code you received:"
            )
            return SETUP_CHALLENGE_CODE
        else:
            await status_msg.edit_text(
                f"❌ Failed to send code: {message}\n\n"
                "Use /start to try again."
            )
            return ConversationHandler.END
    
    except Exception as e:
        logger.error(f"Challenge send error: {e}")
        await status_msg.edit_text(
            f"❌ Error: {str(e)[:100]}\n\n"
            "Use /start to try again."
        )
        return ConversationHandler.END


async def setup_challenge_code_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Handle challenge code verification during setup
    
    Add this as a new handler
    """
    username = context.user_data.get('ig_username', '')
    code = update.message.text.strip()
    
    # Delete code message
    try:
        await update.message.delete()
    except:
        pass
    
    if not code or len(code) < 4:
        await update.effective_chat.send_message(
            "❌ Code too short\n\n"
            "Please send the verification code:"
        )
        return SETUP_CHALLENGE_CODE
    
    status_msg = await update.effective_chat.send_message(
        "⏳ Verifying challenge code..."
    )
    
    try:
        # Complete challenge
        client, status, message = await ig_auth_manager.complete_challenge(username, code)
        
        if status == LoginStatus.SUCCESS:
            # Success
            with ig_clients_lock:
                instagram_clients[username] = client
            
            password = context.user_data.get('ig_password', '')
            save_ig_account(username, password, update.effective_user.id)
            
            # Clear password
            context.user_data.pop('ig_password', None)
            
            await status_msg.edit_text(
                f"✅ Challenge Verification Successful!\n\n"
                f"@{username} is now connected.\n"
                "🎉 Setup complete!"
            )
            
            await update.effective_chat.send_message(
                "Choose an option:",
                reply_markup=main_menu_keyboard(update.effective_user.id),
            )
            
            return ConversationHandler.END
        else:
            await status_msg.edit_text(
                f"❌ Verification failed: {message}\n\n"
                "Please try again or /cancel:"
            )
            return SETUP_CHALLENGE_CODE
    
    except Exception as e:
        logger.error(f"Challenge error: {e}")
        await status_msg.edit_text(
            f"❌ Error: {str(e)[:100]}\n\n"
            "Try again or /cancel"
        )
        return SETUP_CHALLENGE_CODE


# ============================================
#       UPDATED ADMIN ADD ACCOUNT HANDLERS
# ============================================

async def add_ig_user_handler_v2(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Receive Instagram username for admin adding account (with validation)
    
    This replaces your existing add_ig_user_handler function
    """
    raw_username = update.message.text.strip()
    
    # Sanitize username
    username = ig_auth_manager.sanitize_username(raw_username)
    
    # Validate username
    is_valid, error_msg = ig_auth_manager.validate_username(username)
    
    if not is_valid:
        await update.message.reply_text(
            f"❌ Invalid username: {error_msg}\n\n"
            "Please send a valid Instagram username:"
        )
        return ADD_ACCOUNT_USER
    
    context.user_data["new_ig_user"] = username
    
    await update.message.reply_text(
        f"📱 Username: @{username}\n\n"
        "Now send the Instagram PASSWORD:\n\n"
        "🔒 Security:\n"
        "• Password will be encrypted\n"
        "• Your message will be deleted\n"
        "• Password is never logged"
    )
    
    return ADD_ACCOUNT_PASS


async def add_ig_pass_handler_v2(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """
    Receive Instagram password for admin (with 2FA/challenge support)
    
    This replaces your existing add_ig_pass_handler function
    """
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
    
    try:
        # Attempt login
        client, status, message = await ig_auth_manager.login_with_session(
            username, password
        )
        
        if status == LoginStatus.SUCCESS:
            # Success
            with ig_clients_lock:
                instagram_clients[username] = client
            
            save_ig_account(username, password, update.effective_user.id)
            
            await status_msg.edit_text(
                f"✅ @{username} connected successfully!\n\n"
                "Account saved and encrypted.",
                reply_markup=back_admin_button(),
            )
            
            return ADMIN_MENU
        
        elif status == LoginStatus.TWO_FACTOR_REQUIRED:
            # Store for 2FA
            context.user_data['ig_username'] = username
            context.user_data['ig_password'] = password
            context.user_data['return_to_admin'] = True
            
            await status_msg.edit_text(
                "🔐 Two-Factor Authentication Required\n\n"
                "Please send the 6-digit code:"
            )
            
            return ADD_ACCOUNT_2FA  # New state
        
        elif status == LoginStatus.CHALLENGE_REQUIRED:
            # Store for challenge
            context.user_data['ig_username'] = username
            context.user_data['ig_password'] = password
            context.user_data['return_to_admin'] = True
            
            keyboard = [
                [
                    InlineKeyboardButton("📧 Email", callback_data=f"challenge_email:{username}"),
                    InlineKeyboardButton("📱 SMS", callback_data=f"challenge_sms:{username}"),
                ],
                [InlineKeyboardButton("❌ Cancel", callback_data="challenge_cancel_admin")],
            ]
            
            await status_msg.edit_text(
                "🛡️ Security Challenge Required\n\n"
                "Choose verification method:",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            
            return ADD_ACCOUNT_CHALLENGE_METHOD  # New state
        
        elif status == LoginStatus.BAD_PASSWORD:
            await status_msg.edit_text(
                f"❌ Incorrect password for @{username}\n\n"
                "Send correct password or /cancel:"
            )
            return ADD_ACCOUNT_PASS
        
        elif status == LoginStatus.RATE_LIMITED:
            await status_msg.edit_text(
                "⏸️ Rate limited - wait 5-10 minutes\n\n"
                "Use /admin to return to panel."
            )
            return ADMIN_MENU
        
        else:
            await status_msg.edit_text(
                f"❌ Login failed: {message}\n\n"
                "Send USERNAME again or /cancel"
            )
            return ADD_ACCOUNT_USER
    
    except Exception as e:
        logger.error(f"Admin add account error: {e}")
        await status_msg.edit_text(
            f"❌ Error: {str(e)[:100]}\n\n"
            "Send USERNAME to retry or /cancel"
        )
        return ADD_ACCOUNT_USER


# ============================================
#       LOAD ALL ACCOUNTS ON STARTUP
# ============================================

async def load_all_ig_accounts_v2():
    """
    Load all saved Instagram accounts on startup (async version)
    
    This replaces your existing load_all_ig_accounts function
    """
    try:
        accounts = list(accounts_col.find({}))
        
        logger.info(f"Loading {len(accounts)} Instagram accounts...")
        
        for acc in accounts:
            try:
                username = acc['username']
                decrypted_pass = decrypt_password(acc["password"])
                
                # Use new login method
                client, status, message = await ig_auth_manager.login_with_session(
                    username, decrypted_pass
                )
                
                if status == LoginStatus.SUCCESS:
                    with ig_clients_lock:
                        instagram_clients[username] = client
                    logger.info(f"✅ Loaded @{username}")
                else:
                    logger.warning(f"⚠️ Failed to load @{username}: {message}")
                    if status in [LoginStatus.TWO_FACTOR_REQUIRED, LoginStatus.CHALLENGE_REQUIRED]:
                        logger.warning(f"   Account @{username} requires manual re-login")
                
            except Exception as e:
                logger.error(f"❌ Failed to load @{acc.get('username', 'unknown')}: {e}")
        
        logger.info(f"✅ Loaded {len(instagram_clients)} accounts successfully")
        
    except Exception as e:
        logger.error(f"Error loading accounts: {e}")


# ============================================
#       SESSION REFRESH JOB
# ============================================

async def refresh_ig_sessions_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Periodic job to refresh Instagram sessions
    
    Add this to your job queue:
    job_queue.run_repeating(refresh_ig_sessions_job, interval=3600, first=300)
    """
    try:
        logger.info("Running session refresh job...")
        
        accounts = list(accounts_col.find({}))
        
        for account in accounts:
            username = account['username']
            
            try:
                with ig_clients_lock:
                    client = instagram_clients.get(username)
                
                if client:
                    # Verify session
                    is_valid = await ig_auth_manager.verify_session(client)
                    
                    if is_valid:
                        continue
                    else:
                        logger.info(f"Session expired for @{username}, refreshing...")
                
                # Re-login if needed
                password = decrypt_password(account['password'])
                
                client, status, message = await ig_auth_manager.login_with_session(
                    username, password
                )
                
                if status == LoginStatus.SUCCESS:
                    with ig_clients_lock:
                        instagram_clients[username] = client
                    logger.info(f"✅ Session refreshed for @{username}")
                else:
                    logger.warning(f"Failed to refresh @{username}: {message}")
            
            except Exception as e:
                logger.error(f"Error refreshing @{username}: {e}")
        
        # Cleanup expired pending auth
        await ig_auth_manager.cleanup_expired_pending_auth()
        
    except Exception as e:
        logger.error(f"Session refresh job error: {e}")
