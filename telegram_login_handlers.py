"""
Telegram Conversation Handlers for Instagram Authentication
Handles 2FA and challenge flows via Telegram messages
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, ConversationHandler

from instagram_auth import (
    InstagramAuthManager,
    LoginStatus,
    ChallengeMethod,
)

logger = logging.getLogger(__name__)

# ============================================
#       CONVERSATION STATES
# ============================================
# These integrate with your existing states
(
    IG_ACCOUNT_USERNAME,
    IG_ACCOUNT_PASSWORD,
    IG_2FA_CODE,
    IG_CHALLENGE_METHOD,
    IG_CHALLENGE_CODE,
) = range(5)  # Adjust numbers to fit your existing state range


class InstagramLoginHandler:
    """
    Handles Instagram login conversations via Telegram
    Supports 2FA and challenge flows
    """
    
    def __init__(
        self,
        auth_manager: InstagramAuthManager,
        active_clients: dict,
        clients_lock: asyncio.Lock,
    ):
        """
        Initialize login handler
        
        Args:
            auth_manager: InstagramAuthManager instance
            active_clients: Dict to store active Instagram clients
            clients_lock: Lock for thread-safe client access
        """
        self.auth_manager = auth_manager
        self.active_clients = active_clients
        self.clients_lock = clients_lock
        
        # Track login attempts per user
        self.login_attempts = {}
        
        logger.info("InstagramLoginHandler initialized")
    
    # ============================================
    #       USERNAME INPUT
    # ============================================
    
    async def receive_username(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        is_admin_flow: bool = False
    ) -> int:
        """
        Receive and validate Instagram username
        
        Args:
            update: Telegram update
            context: Telegram context
            is_admin_flow: Whether this is admin adding account vs first setup
            
        Returns:
            Next conversation state
        """
        user_id = update.effective_user.id
        raw_username = update.message.text.strip()
        
        # Sanitize username
        username = self.auth_manager.sanitize_username(raw_username)
        
        # Validate username
        is_valid, error_msg = self.auth_manager.validate_username(username)
        
        if not is_valid:
            await update.message.reply_text(
                f"❌ Invalid username: {error_msg}\n\n"
                f"Please send a valid Instagram username:"
            )
            return IG_ACCOUNT_USERNAME
        
        # Store username in context
        context.user_data['ig_username'] = username
        context.user_data['is_admin_flow'] = is_admin_flow
        
        # Request password
        await update.message.reply_text(
            f"📱 Username: @{username}\n\n"
            f"Now send your Instagram PASSWORD:\n\n"
            f"🔒 Security:\n"
            f"• Password will be encrypted with AES-256\n"
            f"• Your message will be deleted immediately\n"
            f"• Password is never logged\n\n"
            f"⚠️ Make sure this chat is private!"
        )
        
        return IG_ACCOUNT_PASSWORD
    
    # ============================================
    #       PASSWORD INPUT & LOGIN ATTEMPT
    # ============================================
    
    async def receive_password(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE
    ) -> int:
        """
        Receive password and attempt login
        
        Returns:
            Next conversation state based on login result
        """
        user_id = update.effective_user.id
        username = context.user_data.get('ig_username', '')
        password = update.message.text.strip()
        
        # Delete password message immediately
        try:
            await update.message.delete()
        except Exception as e:
            logger.warning(f"Failed to delete password message: {e}")
        
        # Validate password
        if not password or len(password) < 6:
            await update.effective_chat.send_message(
                "❌ Password too short (minimum 6 characters)\n\n"
                "Please send your Instagram password:"
            )
            return IG_ACCOUNT_PASSWORD
        
        # Store password temporarily (will be cleared after login)
        context.user_data['ig_password'] = password
        
        # Show status message
        status_msg = await update.effective_chat.send_message(
            f"⏳ Logging into @{username}...\n\n"
            f"This may take a moment."
        )
        
        try:
            # Attempt login with session management
            client, status, message = await self.auth_manager.login_with_session(
                username, password
            )
            
            if status == LoginStatus.SUCCESS:
                # Success - store client
                async with self.clients_lock:
                    self.active_clients[username] = client
                
                # Clear password from context
                context.user_data.pop('ig_password', None)
                
                await status_msg.edit_text(
                    f"✅ Successfully logged in as @{username}!\n\n"
                    f"🎉 Account connected and ready to use.\n"
                    f"💾 Session saved for future use."
                )
                
                logger.info(f"User {user_id} successfully logged into @{username}")
                return ConversationHandler.END
            
            elif status == LoginStatus.TWO_FACTOR_REQUIRED:
                # 2FA needed
                await status_msg.edit_text(
                    f"🔐 Two-Factor Authentication Required\n\n"
                    f"Instagram has sent a verification code to your device.\n\n"
                    f"Please send the 6-digit code:"
                )
                
                logger.info(f"2FA required for @{username}")
                return IG_2FA_CODE
            
            elif status == LoginStatus.CHALLENGE_REQUIRED:
                # Challenge needed - show method selection
                keyboard = [
                    [
                        InlineKeyboardButton("📧 Email", callback_data=f"challenge_email:{username}"),
                        InlineKeyboardButton("📱 SMS", callback_data=f"challenge_sms:{username}"),
                    ],
                    [InlineKeyboardButton("❌ Cancel", callback_data="challenge_cancel")],
                ]
                
                await status_msg.edit_text(
                    f"🛡️ Security Challenge Required\n\n"
                    f"Instagram needs to verify your identity.\n\n"
                    f"Choose how to receive your verification code:",
                    reply_markup=InlineKeyboardMarkup(keyboard)
                )
                
                logger.info(f"Challenge required for @{username}")
                return IG_CHALLENGE_METHOD
            
            elif status == LoginStatus.BAD_PASSWORD:
                # Wrong password
                context.user_data.pop('ig_password', None)
                
                await status_msg.edit_text(
                    f"❌ Incorrect password for @{username}\n\n"
                    f"Please check your password and try again.\n\n"
                    f"Send the correct password or /cancel to abort:"
                )
                
                logger.warning(f"Bad password attempt for @{username}")
                return IG_ACCOUNT_PASSWORD
            
            elif status == LoginStatus.RATE_LIMITED:
                # Rate limited
                context.user_data.pop('ig_password', None)
                
                await status_msg.edit_text(
                    f"⏸️ Rate Limited\n\n"
                    f"Instagram has temporarily blocked login attempts.\n\n"
                    f"Please wait 5-10 minutes and try again.\n\n"
                    f"Use /start to retry later."
                )
                
                logger.warning(f"Rate limited for @{username}")
                return ConversationHandler.END
            
            else:
                # Other error
                context.user_data.pop('ig_password', None)
                
                await status_msg.edit_text(
                    f"❌ Login Failed\n\n"
                    f"Error: {message}\n\n"
                    f"Please try again:\n"
                    f"• Use /start to restart setup\n"
                    f"• Make sure you can login on Instagram app first"
                )
                
                logger.error(f"Login failed for @{username}: {message}")
                return ConversationHandler.END
        
        except Exception as e:
            # Unexpected error
            logger.error(f"Unexpected error during login for @{username}: {e}")
            context.user_data.pop('ig_password', None)
            
            try:
                await status_msg.edit_text(
                    f"❌ Unexpected Error\n\n"
                    f"Something went wrong during login.\n"
                    f"Error: {str(e)[:100]}\n\n"
                    f"Please try again with /start"
                )
            except:
                pass
            
            return ConversationHandler.END
    
    # ============================================
    #       TWO-FACTOR AUTHENTICATION
    # ============================================
    
    async def receive_2fa_code(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE
    ) -> int:
        """
        Receive and verify 2FA code
        
        Returns:
            Next conversation state
        """
        user_id = update.effective_user.id
        username = context.user_data.get('ig_username', '')
        code = update.message.text.strip()
        
        # Delete code message
        try:
            await update.message.delete()
        except:
            pass
        
        # Validate code format
        if not code.isdigit() or len(code) != 6:
            await update.message.reply_text(
                "❌ Invalid code format\n\n"
                "Please send the 6-digit code:"
            )
            return IG_2FA_CODE
        
        status_msg = await update.effective_chat.send_message(
            "⏳ Verifying code..."
        )
        
        try:
            # Complete 2FA
            client, status, message = await self.auth_manager.complete_2fa(
                username, code
            )
            
            if status == LoginStatus.SUCCESS:
                # Success
                async with self.clients_lock:
                    self.active_clients[username] = client
                
                context.user_data.pop('ig_password', None)
                
                await status_msg.edit_text(
                    f"✅ Two-Factor Authentication Successful!\n\n"
                    f"@{username} is now connected.\n"
                    f"💾 Session saved for future use."
                )
                
                logger.info(f"2FA completed successfully for @{username}")
                return ConversationHandler.END
            
            else:
                # Failed
                await status_msg.edit_text(
                    f"❌ Verification Failed\n\n"
                    f"{message}\n\n"
                    f"Please try again or /cancel to abort:"
                )
                
                logger.warning(f"2FA failed for @{username}: {message}")
                return IG_2FA_CODE
        
        except Exception as e:
            logger.error(f"2FA error for @{username}: {e}")
            
            await status_msg.edit_text(
                f"❌ Error verifying code\n\n"
                f"{str(e)[:100]}\n\n"
                f"Try again or /cancel"
            )
            
            return IG_2FA_CODE
    
    # ============================================
    #       CHALLENGE HANDLING
    # ============================================
    
    async def challenge_method_callback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE
    ) -> int:
        """
        Handle challenge method selection
        
        Returns:
            Next conversation state
        """
        query = update.callback_query
        await query.answer()
        
        data = query.data
        
        if data == "challenge_cancel":
            username = context.user_data.get('ig_username', '')
            self.auth_manager.cancel_challenge(username)
            context.user_data.pop('ig_password', None)
            
            await query.edit_message_text(
                "❌ Login cancelled\n\n"
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
        
        # Send challenge code
        status_msg = await query.edit_message_text(
            f"📤 Sending verification code via {method_name}..."
        )
        
        try:
            success, message = await self.auth_manager.send_challenge_code(
                username, method
            )
            
            if success:
                await status_msg.edit_text(
                    f"✅ Code Sent!\n\n"
                    f"A verification code has been sent to your {method_name.lower()}.\n\n"
                    f"Please send the code you received:"
                )
                
                logger.info(f"Challenge code sent for @{username} via {method_name}")
                return IG_CHALLENGE_CODE
            
            else:
                await status_msg.edit_text(
                    f"❌ Failed to send code\n\n"
                    f"{message}\n\n"
                    f"Use /start to try again."
                )
                
                logger.error(f"Failed to send challenge code for @{username}: {message}")
                return ConversationHandler.END
        
        except Exception as e:
            logger.error(f"Challenge code send error for @{username}: {e}")
            
            await status_msg.edit_text(
                f"❌ Error sending code\n\n"
                f"{str(e)[:100]}\n\n"
                f"Use /start to try again."
            )
            
            return ConversationHandler.END
    
    async def receive_challenge_code(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE
    ) -> int:
        """
        Receive and verify challenge code
        
        Returns:
            Next conversation state
        """
        user_id = update.effective_user.id
        username = context.user_data.get('ig_username', '')
        code = update.message.text.strip()
        
        # Delete code message
        try:
            await update.message.delete()
        except:
            pass
        
        # Validate code (usually 6 digits but can vary)
        if not code or len(code) < 4:
            await update.message.reply_text(
                "❌ Code too short\n\n"
                "Please send the verification code:"
            )
            return IG_CHALLENGE_CODE
        
        status_msg = await update.effective_chat.send_message(
            "⏳ Verifying challenge code..."
        )
        
        try:
            # Complete challenge
            client, status, message = await self.auth_manager.complete_challenge(
                username, code
            )
            
            if status == LoginStatus.SUCCESS:
                # Success
                async with self.clients_lock:
                    self.active_clients[username] = client
                
                context.user_data.pop('ig_password', None)
                
                await status_msg.edit_text(
                    f"✅ Challenge Verification Successful!\n\n"
                    f"@{username} is now connected.\n"
                    f"💾 Session saved for future use."
                )
                
                logger.info(f"Challenge completed successfully for @{username}")
                return ConversationHandler.END
            
            else:
                # Failed
                await status_msg.edit_text(
                    f"❌ Verification Failed\n\n"
                    f"{message}\n\n"
                    f"Please try again or /cancel to abort:"
                )
                
                logger.warning(f"Challenge failed for @{username}: {message}")
                return IG_CHALLENGE_CODE
        
        except Exception as e:
            logger.error(f"Challenge error for @{username}: {e}")
            
            await status_msg.edit_text(
                f"❌ Error verifying code\n\n"
                f"{str(e)[:100]}\n\n"
                f"Try again or /cancel"
            )
            
            return IG_CHALLENGE_CODE
    
    # ============================================
    #       CONVERSATION CANCEL
    # ============================================
    
    async def cancel_login(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE
    ) -> int:
        """
        Cancel login conversation
        """
        username = context.user_data.get('ig_username', '')
        
        # Cancel any pending auth
        if username:
            self.auth_manager.cancel_2fa(username)
            self.auth_manager.cancel_challenge(username)
        
        # Clear sensitive data
        context.user_data.pop('ig_password', None)
        context.user_data.pop('ig_username', None)
        
        await update.message.reply_text(
            "❌ Login cancelled\n\n"
            "Use /start to try again."
        )
        
        logger.info(f"Login cancelled by user {update.effective_user.id}")
        return ConversationHandler.END


# ============================================
#       HELPER FUNCTIONS FOR INTEGRATION
# ============================================

def create_login_conversation_handler(
    login_handler: InstagramLoginHandler,
    entry_state: int,
    username_state: int,
    password_state: int,
    twofa_state: int,
    challenge_method_state: int,
    challenge_code_state: int,
):
    """
    Create a ConversationHandler for Instagram login
    
    Args:
        login_handler: InstagramLoginHandler instance
        entry_state: State number for entry point
        username_state: State number for username input
        password_state: State number for password input
        twofa_state: State number for 2FA code
        challenge_method_state: State number for challenge method selection
        challenge_code_state: State number for challenge code input
        
    Returns:
        ConversationHandler configured for login flow
    """
    from telegram.ext import MessageHandler, CallbackQueryHandler, filters
    
    # Note: This is a sub-handler that should be integrated into your main conversation
    # You can use these states within your existing conversation handler
    
    states = {
        username_state: [
            MessageHandler(
                filters.TEXT & ~filters.COMMAND,
                login_handler.receive_username,
            ),
        ],
        password_state: [
            MessageHandler(
                filters.TEXT & ~filters.COMMAND,
                login_handler.receive_password,
            ),
        ],
        twofa_state: [
            MessageHandler(
                filters.TEXT & ~filters.COMMAND,
                login_handler.receive_2fa_code,
            ),
        ],
        challenge_method_state: [
            CallbackQueryHandler(
                login_handler.challenge_method_callback,
                pattern="^challenge_",
            ),
        ],
        challenge_code_state: [
            MessageHandler(
                filters.TEXT & ~filters.COMMAND,
                login_handler.receive_challenge_code,
            ),
        ],
    }
    
    return states


async def check_and_refresh_sessions(
    auth_manager: InstagramAuthManager,
    active_clients: dict,
    clients_lock: asyncio.Lock,
    accounts_collection,
    decrypt_password_func,
):
    """
    Periodic job to check and refresh Instagram sessions
    
    Args:
        auth_manager: InstagramAuthManager instance
        active_clients: Dict of active clients
        clients_lock: Lock for thread-safe access
        accounts_collection: MongoDB collection with saved accounts
        decrypt_password_func: Function to decrypt passwords
    """
    try:
        # Get all saved accounts
        accounts = list(accounts_collection.find({}))
        
        for account in accounts:
            username = account['username']
            
            try:
                # Check if client exists and is valid
                async with clients_lock:
                    client = active_clients.get(username)
                
                if client:
                    # Verify session is still valid
                    is_valid = await auth_manager.verify_session(client)
                    
                    if is_valid:
                        logger.info(f"Session valid for @{username}")
                        continue
                    else:
                        logger.warning(f"Session expired for @{username}, refreshing...")
                
                # Need to re-login
                password = decrypt_password_func(account['password'])
                
                client, status, message = await auth_manager.login_with_session(
                    username, password
                )
                
                if status == LoginStatus.SUCCESS:
                    async with clients_lock:
                        active_clients[username] = client
                    logger.info(f"✅ Session refreshed for @{username}")
                else:
                    logger.warning(f"Failed to refresh session for @{username}: {message}")
            
            except Exception as e:
                logger.error(f"Error refreshing session for @{username}: {e}")
        
        # Cleanup expired pending authentications
        await auth_manager.cleanup_expired_pending_auth()
        
    except Exception as e:
        logger.error(f"Error in session refresh job: {e}")
