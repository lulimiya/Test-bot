"""
Production-Grade Instagram Authentication Module
Handles login, 2FA, challenges, session management, and error recovery
"""

import os
import json
import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, Any
from enum import Enum

from instagrapi import Client
from instagrapi.exceptions import (
    LoginRequired,
    ChallengeRequired,
    TwoFactorRequired,
    BadPassword,
    PleaseWaitFewMinutes,
    RateLimitError,
    ClientError,
    UnknownError,
)
from cryptography.fernet import Fernet
from pymongo.collection import Collection

logger = logging.getLogger(__name__)


class LoginStatus(Enum):
    """Login attempt status codes"""
    SUCCESS = "success"
    BAD_PASSWORD = "bad_password"
    TWO_FACTOR_REQUIRED = "2fa_required"
    CHALLENGE_REQUIRED = "challenge_required"
    RATE_LIMITED = "rate_limited"
    SESSION_EXPIRED = "session_expired"
    NETWORK_ERROR = "network_error"
    UNKNOWN_ERROR = "unknown_error"


class ChallengeMethod(Enum):
    """Challenge verification methods"""
    EMAIL = 0
    SMS = 1


class InstagramAuthManager:
    """
    Production-grade Instagram authentication manager
    Handles login, session persistence, 2FA, and challenges
    """
    
    def __init__(
        self,
        sessions_dir: str = "sessions",
        encryption_key: Optional[str] = None,
        mongo_collection: Optional[Collection] = None,
        session_timeout_days: int = 90,
    ):
        """
        Initialize the authentication manager
        
        Args:
            sessions_dir: Directory to store session files
            encryption_key: Fernet encryption key for password encryption
            mongo_collection: MongoDB collection for session storage
            session_timeout_days: Days before session is considered expired
        """
        self.sessions_dir = sessions_dir
        self.mongo_collection = mongo_collection
        self.session_timeout_days = session_timeout_days
        
        # Create sessions directory if it doesn't exist
        os.makedirs(self.sessions_dir, exist_ok=True)
        
        # Setup encryption
        if encryption_key:
            self.cipher = Fernet(
                encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
            )
        else:
            logger.warning("No encryption key provided - passwords will not be encrypted")
            self.cipher = None
        
        # Pending authentication states (for 2FA and challenges)
        self.pending_auth: Dict[str, Dict[str, Any]] = {}
        
        logger.info("InstagramAuthManager initialized")
    
    # ============================================
    #       USERNAME SANITIZATION
    # ============================================
    
    @staticmethod
    def sanitize_username(username: str) -> str:
        """
        Sanitize Instagram username
        - Remove leading '@'
        - Strip whitespace
        - Convert to lowercase
        - Remove invalid characters
        
        Args:
            username: Raw username input
            
        Returns:
            Sanitized username
        """
        if not username:
            return ""
        
        # Remove whitespace
        username = username.strip()
        
        # Remove leading '@'
        if username.startswith('@'):
            username = username[1:]
        
        # Convert to lowercase
        username = username.lower()
        
        # Remove any remaining whitespace
        username = username.strip()
        
        return username
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validate Instagram username format
        
        Args:
            username: Username to validate (should be pre-sanitized)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < 1:
            return False, "Username too short"
        
        if len(username) > 30:
            return False, "Username too long (max 30 characters)"
        
        # Instagram usernames: alphanumeric, dots, underscores
        if not re.match(r'^[a-z0-9._]+$', username):
            return False, "Username can only contain letters, numbers, dots, and underscores"
        
        # Cannot start or end with dot
        if username.startswith('.') or username.endswith('.'):
            return False, "Username cannot start or end with a dot"
        
        # Cannot have consecutive dots
        if '..' in username:
            return False, "Username cannot have consecutive dots"
        
        return True, ""
    
    # ============================================
    #       SESSION MANAGEMENT
    # ============================================
    
    def _get_session_file_path(self, username: str) -> str:
        """Get the file path for a username's session"""
        return os.path.join(self.sessions_dir, f"{username}.json")
    
    def _get_session_metadata_path(self, username: str) -> str:
        """Get the file path for session metadata"""
        return os.path.join(self.sessions_dir, f"{username}_meta.json")
    
    async def save_session_to_file(
        self,
        username: str,
        client: Client,
        additional_data: Optional[Dict] = None
    ) -> bool:
        """
        Save Instagram session to file
        
        Args:
            username: Instagram username
            client: Authenticated Instagram client
            additional_data: Additional metadata to save
            
        Returns:
            Success status
        """
        try:
            session_file = self._get_session_file_path(username)
            meta_file = self._get_session_metadata_path(username)
            
            # Save session settings
            await asyncio.to_thread(client.dump_settings, session_file)
            
            # Save metadata
            metadata = {
                'username': username,
                'saved_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=self.session_timeout_days)).isoformat(),
            }
            
            if additional_data:
                metadata.update(additional_data)
            
            async with asyncio.Lock():
                with open(meta_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
            
            logger.info(f"Session saved to file for @{username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save session for @{username}: {e}")
            return False
    
    async def load_session_from_file(
        self,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """
        Load Instagram session from file
        
        Args:
            username: Instagram username
            
        Returns:
            Session settings dict or None if not found/expired
        """
        try:
            session_file = self._get_session_file_path(username)
            meta_file = self._get_session_metadata_path(username)
            
            # Check if session file exists
            if not os.path.exists(session_file):
                logger.info(f"No session file found for @{username}")
                return None
            
            # Check metadata and expiry
            if os.path.exists(meta_file):
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                
                expires_at = datetime.fromisoformat(metadata.get('expires_at', ''))
                if datetime.now() > expires_at:
                    logger.info(f"Session expired for @{username}")
                    # Clean up expired session
                    await self.delete_session(username)
                    return None
            
            # Load session settings
            with open(session_file, 'r') as f:
                settings = json.load(f)
            
            logger.info(f"Session loaded from file for @{username}")
            return settings
            
        except Exception as e:
            logger.error(f"Failed to load session for @{username}: {e}")
            return None
    
    async def save_session_to_mongo(
        self,
        username: str,
        session_data: Dict[str, Any],
        encrypted_password: Optional[str] = None
    ) -> bool:
        """
        Save session to MongoDB
        
        Args:
            username: Instagram username
            session_data: Session settings dict
            encrypted_password: Encrypted password (optional)
            
        Returns:
            Success status
        """
        if not self.mongo_collection:
            return False
        
        try:
            document = {
                'username': username,
                'session_data': session_data,
                'saved_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(days=self.session_timeout_days),
                'updated_at': datetime.now(),
            }
            
            if encrypted_password:
                document['encrypted_password'] = encrypted_password
            
            await asyncio.to_thread(
                self.mongo_collection.update_one,
                {'username': username},
                {'$set': document},
                upsert=True
            )
            
            logger.info(f"Session saved to MongoDB for @{username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save session to MongoDB for @{username}: {e}")
            return False
    
    async def load_session_from_mongo(
        self,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """
        Load session from MongoDB
        
        Args:
            username: Instagram username
            
        Returns:
            Session data or None if not found/expired
        """
        if not self.mongo_collection:
            return None
        
        try:
            doc = await asyncio.to_thread(
                self.mongo_collection.find_one,
                {'username': username}
            )
            
            if not doc:
                logger.info(f"No MongoDB session found for @{username}")
                return None
            
            # Check expiry
            if datetime.now() > doc.get('expires_at', datetime.now()):
                logger.info(f"MongoDB session expired for @{username}")
                await self.delete_session_from_mongo(username)
                return None
            
            logger.info(f"Session loaded from MongoDB for @{username}")
            return doc.get('session_data')
            
        except Exception as e:
            logger.error(f"Failed to load session from MongoDB for @{username}: {e}")
            return None
    
    async def delete_session(self, username: str) -> bool:
        """
        Delete session from both file and MongoDB
        
        Args:
            username: Instagram username
            
        Returns:
            Success status
        """
        success = True
        
        # Delete from file
        try:
            session_file = self._get_session_file_path(username)
            meta_file = self._get_session_metadata_path(username)
            
            if os.path.exists(session_file):
                os.remove(session_file)
            if os.path.exists(meta_file):
                os.remove(meta_file)
                
            logger.info(f"File session deleted for @{username}")
        except Exception as e:
            logger.error(f"Failed to delete file session for @{username}: {e}")
            success = False
        
        # Delete from MongoDB
        await self.delete_session_from_mongo(username)
        
        return success
    
    async def delete_session_from_mongo(self, username: str) -> bool:
        """Delete session from MongoDB only"""
        if not self.mongo_collection:
            return False
        
        try:
            await asyncio.to_thread(
                self.mongo_collection.delete_one,
                {'username': username}
            )
            logger.info(f"MongoDB session deleted for @{username}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete MongoDB session for @{username}: {e}")
            return False
    
    # ============================================
    #       LOGIN CORE FUNCTIONS
    # ============================================
    
    async def create_client(self, session_data: Optional[Dict] = None) -> Client:
        """
        Create an Instagram client instance
        
        Args:
            session_data: Optional session data to load
            
        Returns:
            Configured Instagram client
        """
        client = Client()
        client.delay_range = [1, 3]
        
        # Set additional client settings for stability
        client.request_timeout = 10
        
        if session_data:
            try:
                await asyncio.to_thread(client.set_settings, session_data)
                logger.info("Client created with existing session")
            except Exception as e:
                logger.warning(f"Failed to load session data into client: {e}")
        
        return client
    
    async def verify_session(self, client: Client) -> bool:
        """
        Verify if a session is still valid
        
        Args:
            client: Instagram client with loaded session
            
        Returns:
            True if session is valid, False otherwise
        """
        try:
            # Try to fetch timeline - lightweight operation
            await asyncio.to_thread(client.get_timeline_feed)
            logger.info("Session verification successful")
            return True
        except LoginRequired:
            logger.info("Session verification failed - login required")
            return False
        except Exception as e:
            logger.warning(f"Session verification error: {e}")
            return False
    
    async def login_with_session(
        self,
        username: str,
        password: str
    ) -> Tuple[Optional[Client], LoginStatus, str]:
        """
        Attempt to login using saved session, fallback to fresh login
        
        Args:
            username: Sanitized Instagram username
            password: Instagram password
            
        Returns:
            Tuple of (client, status, message)
        """
        # Try to load session from MongoDB first
        session_data = await self.load_session_from_mongo(username)
        
        # Fallback to file session
        if not session_data:
            session_data = await self.load_session_from_file(username)
        
        if session_data:
            try:
                # Create client with session
                client = await self.create_client(session_data)
                
                # Verify session is still valid
                if await self.verify_session(client):
                    logger.info(f"✅ Logged in @{username} using saved session")
                    return client, LoginStatus.SUCCESS, "Logged in using saved session"
                else:
                    logger.info(f"Session invalid for @{username}, performing fresh login")
                    await self.delete_session(username)
                    
            except Exception as e:
                logger.warning(f"Failed to use saved session for @{username}: {e}")
                await self.delete_session(username)
        
        # Perform fresh login
        return await self.fresh_login(username, password)
    
    async def fresh_login(
        self,
        username: str,
        password: str
    ) -> Tuple[Optional[Client], LoginStatus, str]:
        """
        Perform fresh Instagram login
        
        Args:
            username: Sanitized Instagram username
            password: Instagram password
            
        Returns:
            Tuple of (client, status, message)
        """
        try:
            client = await self.create_client()
            
            # Attempt login
            await asyncio.to_thread(client.login, username, password)
            
            # Save session after successful login
            await self.save_session_to_file(username, client)
            
            if self.mongo_collection and self.cipher:
                encrypted_pwd = self.cipher.encrypt(password.encode()).decode()
                session_settings = await asyncio.to_thread(client.get_settings)
                await self.save_session_to_mongo(username, session_settings, encrypted_pwd)
            
            logger.info(f"✅ Fresh login successful for @{username}")
            return client, LoginStatus.SUCCESS, "Login successful"
            
        except BadPassword:
            logger.warning(f"Bad password for @{username}")
            return None, LoginStatus.BAD_PASSWORD, "Incorrect password"
            
        except TwoFactorRequired as e:
            logger.info(f"2FA required for @{username}")
            # Store client for 2FA continuation
            self.pending_auth[username] = {
                'client': client,
                'password': password,
                'timestamp': datetime.now(),
                'type': '2fa',
            }
            return None, LoginStatus.TWO_FACTOR_REQUIRED, "Two-factor authentication required"
            
        except ChallengeRequired as e:
            logger.info(f"Challenge required for @{username}")
            # Store client for challenge continuation
            self.pending_auth[username] = {
                'client': client,
                'password': password,
                'timestamp': datetime.now(),
                'type': 'challenge',
            }
            return None, LoginStatus.CHALLENGE_REQUIRED, "Challenge verification required"
            
        except (PleaseWaitFewMinutes, RateLimitError) as e:
            logger.warning(f"Rate limited for @{username}")
            return None, LoginStatus.RATE_LIMITED, "Rate limited - please wait a few minutes"
            
        except ClientError as e:
            logger.error(f"Client error for @{username}: {e}")
            return None, LoginStatus.NETWORK_ERROR, f"Network error: {str(e)[:100]}"
            
        except Exception as e:
            logger.error(f"Unknown login error for @{username}: {e}")
            return None, LoginStatus.UNKNOWN_ERROR, f"Login failed: {str(e)[:100]}"
    
    # ============================================
    #       TWO-FACTOR AUTHENTICATION
    # ============================================
    
    async def complete_2fa(
        self,
        username: str,
        code: str,
        timeout_minutes: int = 5
    ) -> Tuple[Optional[Client], LoginStatus, str]:
        """
        Complete two-factor authentication
        
        Args:
            username: Instagram username
            code: 2FA verification code
            timeout_minutes: Timeout for pending auth state
            
        Returns:
            Tuple of (client, status, message)
        """
        # Check if pending auth exists
        if username not in self.pending_auth:
            logger.warning(f"No pending 2FA for @{username}")
            return None, LoginStatus.UNKNOWN_ERROR, "No pending authentication found"
        
        auth_data = self.pending_auth[username]
        
        # Check timeout
        time_elapsed = (datetime.now() - auth_data['timestamp']).total_seconds() / 60
        if time_elapsed > timeout_minutes:
            logger.warning(f"2FA timeout for @{username}")
            del self.pending_auth[username]
            return None, LoginStatus.UNKNOWN_ERROR, "Authentication timeout - please start over"
        
        # Check if correct type
        if auth_data['type'] != '2fa':
            return None, LoginStatus.UNKNOWN_ERROR, "Invalid authentication type"
        
        try:
            client = auth_data['client']
            password = auth_data['password']
            
            # Complete 2FA login
            await asyncio.to_thread(client.login, username, password, verification_code=code)
            
            # Save session
            await self.save_session_to_file(username, client)
            
            if self.mongo_collection and self.cipher:
                encrypted_pwd = self.cipher.encrypt(password.encode()).decode()
                session_settings = await asyncio.to_thread(client.get_settings)
                await self.save_session_to_mongo(username, session_settings, encrypted_pwd)
            
            # Clear pending auth
            del self.pending_auth[username]
            
            logger.info(f"✅ 2FA completed successfully for @{username}")
            return client, LoginStatus.SUCCESS, "Two-factor authentication successful"
            
        except Exception as e:
            logger.error(f"2FA completion failed for @{username}: {e}")
            # Don't delete pending auth - user might retry
            return None, LoginStatus.UNKNOWN_ERROR, f"2FA failed: {str(e)[:100]}"
    
    def is_2fa_pending(self, username: str) -> bool:
        """Check if 2FA is pending for username"""
        return (
            username in self.pending_auth and
            self.pending_auth[username]['type'] == '2fa'
        )
    
    def cancel_2fa(self, username: str) -> bool:
        """Cancel pending 2FA authentication"""
        if username in self.pending_auth:
            del self.pending_auth[username]
            logger.info(f"2FA cancelled for @{username}")
            return True
        return False
    
    # ============================================
    #       CHALLENGE HANDLING
    # ============================================
    
    async def get_challenge_methods(
        self,
        username: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Get available challenge verification methods
        
        Args:
            username: Instagram username
            
        Returns:
            Tuple of (success, methods_dict, message)
        """
        if username not in self.pending_auth:
            return False, None, "No pending challenge found"
        
        auth_data = self.pending_auth[username]
        
        if auth_data['type'] != 'challenge':
            return False, None, "Invalid authentication type"
        
        try:
            client = auth_data['client']
            
            # Get challenge info
            challenge_info = await asyncio.to_thread(
                lambda: client.challenge_code_handler.__self__
            )
            
            # Available methods (usually email and SMS)
            methods = {
                'email': 'Send code to email',
                'sms': 'Send code to phone (SMS)',
            }
            
            return True, methods, "Challenge methods retrieved"
            
        except Exception as e:
            logger.error(f"Failed to get challenge methods for @{username}: {e}")
            return False, None, f"Error: {str(e)[:100]}"
    
    async def send_challenge_code(
        self,
        username: str,
        method: ChallengeMethod
    ) -> Tuple[bool, str]:
        """
        Request challenge code via email or SMS
        
        Args:
            username: Instagram username
            method: Challenge method (EMAIL or SMS)
            
        Returns:
            Tuple of (success, message)
        """
        if username not in self.pending_auth:
            return False, "No pending challenge found"
        
        auth_data = self.pending_auth[username]
        
        if auth_data['type'] != 'challenge':
            return False, "Invalid authentication type"
        
        try:
            client = auth_data['client']
            
            # Request code via selected method
            await asyncio.to_thread(client.challenge_code_handler, username, method.value)
            
            logger.info(f"Challenge code requested for @{username} via {method.name}")
            return True, f"Code sent via {method.name}"
            
        except Exception as e:
            logger.error(f"Failed to send challenge code for @{username}: {e}")
            return False, f"Error sending code: {str(e)[:100]}"
    
    async def complete_challenge(
        self,
        username: str,
        code: str,
        timeout_minutes: int = 10
    ) -> Tuple[Optional[Client], LoginStatus, str]:
        """
        Complete challenge verification
        
        Args:
            username: Instagram username
            code: Verification code received via email/SMS
            timeout_minutes: Timeout for pending challenge
            
        Returns:
            Tuple of (client, status, message)
        """
        if username not in self.pending_auth:
            return None, LoginStatus.UNKNOWN_ERROR, "No pending challenge found"
        
        auth_data = self.pending_auth[username]
        
        # Check timeout
        time_elapsed = (datetime.now() - auth_data['timestamp']).total_seconds() / 60
        if time_elapsed > timeout_minutes:
            logger.warning(f"Challenge timeout for @{username}")
            del self.pending_auth[username]
            return None, LoginStatus.UNKNOWN_ERROR, "Challenge timeout - please start over"
        
        if auth_data['type'] != 'challenge':
            return None, LoginStatus.UNKNOWN_ERROR, "Invalid authentication type"
        
        try:
            client = auth_data['client']
            password = auth_data['password']
            
            # Submit challenge code
            await asyncio.to_thread(client.challenge_code_handler, username, code)
            
            # Complete login
            await asyncio.to_thread(client.login, username, password)
            
            # Save session
            await self.save_session_to_file(username, client)
            
            if self.mongo_collection and self.cipher:
                encrypted_pwd = self.cipher.encrypt(password.encode()).decode()
                session_settings = await asyncio.to_thread(client.get_settings)
                await self.save_session_to_mongo(username, session_settings, encrypted_pwd)
            
            # Clear pending auth
            del self.pending_auth[username]
            
            logger.info(f"✅ Challenge completed successfully for @{username}")
            return client, LoginStatus.SUCCESS, "Challenge verification successful"
            
        except Exception as e:
            logger.error(f"Challenge completion failed for @{username}: {e}")
            return None, LoginStatus.UNKNOWN_ERROR, f"Challenge failed: {str(e)[:100]}"
    
    def is_challenge_pending(self, username: str) -> bool:
        """Check if challenge is pending for username"""
        return (
            username in self.pending_auth and
            self.pending_auth[username]['type'] == 'challenge'
        )
    
    def cancel_challenge(self, username: str) -> bool:
        """Cancel pending challenge"""
        if username in self.pending_auth:
            del self.pending_auth[username]
            logger.info(f"Challenge cancelled for @{username}")
            return True
        return False
    
    # ============================================
    #       CLEANUP
    # ============================================
    
    async def cleanup_expired_pending_auth(self, timeout_minutes: int = 15):
        """
        Clean up expired pending authentications
        
        Args:
            timeout_minutes: Timeout for pending auth states
        """
        now = datetime.now()
        expired = []
        
        for username, data in self.pending_auth.items():
            time_elapsed = (now - data['timestamp']).total_seconds() / 60
            if time_elapsed > timeout_minutes:
                expired.append(username)
        
        for username in expired:
            del self.pending_auth[username]
            logger.info(f"Expired pending auth cleaned up for @{username}")
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired pending authentications")
