import sys
import os
import asyncio
import aiohttp
import logging
import hashlib
import base64
import binascii
import json
import re
import unicodedata
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                           QTextEdit, QFileDialog, QMessageBox,
                           QCheckBox, QComboBox, QProgressBar, QTabWidget,
                           QGridLayout, QSpinBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QSize
from PyQt6.QtGui import QFont, QIntValidator, QIcon


def setup_logging():
    if os.name == 'nt':  # Windows
        base_dir = os.path.join(os.getenv('LOCALAPPDATA'), 'Inkbunny', 'Downloader', 'Logs')
    elif os.name == 'posix':  # Linux/macOS
        if sys.platform == 'darwin':  # macOS
            base_dir = str(Path.home() / 'Library' / 'Application Support' / 'Inkbunny' / 'Downloader' / 'Logs')
        else:  # Linux
            base_dir = str(Path.home() / '.local' / 'share' / 'inkbunny-downloader' / 'logs')
    else:
        base_dir = str(Path.home() / 'InkbunnyLogs')

    os.makedirs(base_dir, exist_ok=True)
    
    log_filename = os.path.join(base_dir, datetime.now().strftime('%Y%m%d_%H%M%S.log'))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()


class SecureStorage:
    def __init__(self):
        self.salt = b'inkbunny_downloader_salt'
        self.iterations = 100000
        
        # 머신 고유 정보로 키 생성(운영체제, 사용자 이름 등)
        machine_info = f"{os.name}_{os.getlogin() if hasattr(os, 'getlogin') else 'user'}"
        self.key = self._derive_key(machine_info.encode())
        self.cipher_suite = Fernet(self.key)
        
    def _derive_key(self, seed: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(seed))
        return key
        
    def encrypt(self, data: str) -> str:
        encrypted = self.cipher_suite.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
        
    def decrypt(self, encrypted_data: str) -> str:
        try:
            decrypted = self.cipher_suite.decrypt(base64.urlsafe_b64decode(encrypted_data))
            return decrypted.decode()
        except (binascii.Error, ValueError, Exception) as e:
            logger.error(f"Failed to decrypt data: {str(e)}")
            return ""


class SettingsManager:
    def __init__(self):
        self.settings = QSettings('InkbunnyDownloader', 'Settings')
        self.secure_storage = SecureStorage()
        
    def save_credentials(self, username: str, password: str, remember: bool):
        self.settings.setValue('remember_me', remember)
        
        if remember:
            self.settings.setValue('username', username)
            try:
                encrypted_password = self.secure_storage.encrypt(password)
                self.settings.setValue('password', encrypted_password)
            except Exception as e:
                logger.error(f"Failed to encrypt password: {str(e)}")
                # 암호화 실패시 비밀번호 저장하지 않음
                self.settings.remove('password')
        else:
            self.settings.remove('username')
            self.settings.remove('password')
            
    def load_credentials(self) -> Tuple[str, str, bool]:
        remember = self.settings.value('remember_me', False, type=bool)
        username = ""
        password = ""
        
        if remember:
            username = self.settings.value('username', '')
            encrypted_password = self.settings.value('password', '')
            if encrypted_password:
                try:
                    password = self.secure_storage.decrypt(encrypted_password)
                except Exception as e:
                    logger.error(f"Failed to decrypt password: {str(e)}")
                    # 복호화 실패시 비밀번호 설정 삭제
                    self.settings.remove('password')
                    
        return username, password, remember
        
    def save_download_settings(self, artist: str, save_dir: str, max_downloads: int, concurrent_downloads: int):
        self.settings.setValue('artist_username', artist)
        self.settings.setValue('save_directory', save_dir)
        self.settings.setValue('max_downloads', max_downloads)
        self.settings.setValue('concurrent_downloads', concurrent_downloads)
        
    def load_download_settings(self) -> Tuple[str, str, int, int]:
        artist = self.settings.value('artist_username', '')
        save_dir = self.settings.value('save_directory', str(Path.home() / 'Downloads'))
        max_downloads = self.settings.value('max_downloads', 0, type=int)
        concurrent_downloads = self.settings.value('concurrent_downloads', 3, type=int)
        
        return artist, save_dir, max_downloads, concurrent_downloads
        
    def save_theme_settings(self, use_system_theme: bool, theme: str):
        self.settings.setValue('use_system_theme', use_system_theme)
        self.settings.setValue('theme', theme)
        
    def load_theme_settings(self) -> Tuple[bool, str]:
        use_system_theme = self.settings.value('use_system_theme', True, type=bool)
        theme = self.settings.value('theme', 'light')
        
        return use_system_theme, theme


@dataclass
class APIConfig:
    base_url: str
    submissions_per_page: int
    delay: Dict[str, float]
    concurrent_downloads: int


@dataclass
class Credentials:
    username: str
    password: str


@dataclass
class DownloadConfig:
    save_directory: str
    artist_username: str
    max_downloads: int


@dataclass
class DownloadFile:
    url: str
    filename: str
    submission_id: str
    title: str


class ConfigValidator:
    @staticmethod
    def validate_config(config: Dict[str, Any]) -> bool:
        required_fields = {
            'api': ['base_url', 'submissions_per_page', 'delay', 'concurrent_downloads'],
            'credentials': ['username', 'password'],
            'download': ['artist_username', 'save_directory', 'max_downloads']
        }
        
        try:
            for section, fields in required_fields.items():
                if section not in config:
                    raise ValueError(f"Missing section: {section}")
                for field in fields:
                    if field not in config[section]:
                        raise ValueError(f"Missing field: {field} in section {section}")
                        
            if 'between_files' not in config['api']['delay'] or 'between_pages' not in config['api']['delay']:
                raise ValueError("Missing delay configuration")
                
            return True
        except ValueError as e:
            logger.error(f"Configuration validation failed: {e}")
            return False


class APIClient:
    def __init__(self, api_config: APIConfig, credentials: Credentials):
        self.api_config = api_config
        self.credentials = credentials
        self.session_id: Optional[str] = None
        self.retry_count = 3
        self.retry_delay = 5
        self.base_url = self.api_config.base_url.rstrip('/')
        self._session = None
        
    async def initialize(self):
        self._session = aiohttp.ClientSession()
        
    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None
            
    async def _make_request(self, method: str, url: str, data=None, params=None) -> Optional[Dict]:
        if not self._session:
            await self.initialize()
            
        for attempt in range(self.retry_count):
            try:
                if method.lower() == 'get':
                    async with self._session.get(url, params=params) as response:
                        if response.status == 200:
                            return await response.json()
                elif method.lower() == 'post':
                    async with self._session.post(url, data=data) as response:
                        if response.status == 200:
                            return await response.json()
                            
                logger.error(f"Request failed with status {response.status}")
                
            except aiohttp.ClientError as e:
                logger.error(f"Request attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(self.retry_delay)
                    
        return None
            
    async def login(self) -> bool:
        login_url = f"{self.base_url}/api_login.php"
        data = {
            "username": self.credentials.username,
            "password": self.credentials.password,
            "output_mode": "json"
        }
        
        data = await self._make_request('post', login_url, data=data)
        
        if data and "sid" in data:
            self.session_id = data["sid"]
            logger.info("Login successful!")
            return True
            
        logger.error("Login failed")
        return False
        
    async def get_user_id(self, username: str) -> Optional[str]:
        if not self.session_id:
            raise ValueError("Not logged in")
            
        search_url = f"{self.base_url}/api_search.php"
        params = {
            "sid": self.session_id,
            "username": username,
            "submissions_per_page": 1,
            "output_mode": "json"
        }
        
        data = await self._make_request('get', search_url, params=params)
        
        if data and "submissions" in data and data["submissions"]:
            return data["submissions"][0]["user_id"]
            
        return None
        
    async def get_user_submissions(self, user_id: str, page: int = 1) -> Tuple[List[Dict], int]:
        if not self.session_id:
            raise ValueError("Not logged in")
            
        search_url = f"{self.base_url}/api_search.php"
        params = {
            "sid": self.session_id,
            "user_id": user_id,
            "page": page,
            "submissions_per_page": self.api_config.submissions_per_page,
            "type": "1,2,3,4,5",  # All submission types
            "orderby": "create_datetime",
            "random": "no",
            "output_mode": "json"
        }
        
        data = await self._make_request('get', search_url, params=params)
        
        if data:
            total_pages = int(data.get("pages_count", 1))
            return data.get("submissions", []), total_pages
            
        return [], 0
        
    async def get_submission_files(self, submission_id: str) -> List[Dict]:
        if not self.session_id:
            raise ValueError("Not logged in")
            
        files_url = f"{self.base_url}/api_submissions.php"
        params = {
            "sid": self.session_id,
            "submission_ids": submission_id,
            "show_description": "yes",
            "show_files": "yes",
            "show_file_urls": "yes",
            "output_mode": "json"
        }
        
        data = await self._make_request('get', files_url, params=params)
        
        if data:
            return data.get("submissions", [])
            
        return []


class FileDownloader:
    def __init__(self, save_directory: str, artist_username: str, retry_count: int = 3, retry_delay: int = 5):
        self.save_directory = save_directory
        self.artist_username = artist_username
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.session = None
        
        # 숨겨진 디렉토리에 다운로드 이력 저장
        if os.name == 'nt':  # Windows
            history_dir = os.path.join(os.getenv('LOCALAPPDATA'), 'Inkbunny', 'Downloader', 'History')
        elif os.name == 'posix':  # Linux/macOS
            if sys.platform == 'darwin':  # macOS
                history_dir = str(Path.home() / 'Library' / 'Application Support' / 'Inkbunny' / 'Downloader' / 'History')
            else:  # Linux
                history_dir = str(Path.home() / '.local' / 'share' / 'inkbunny-downloader' / 'history')
        else:
            history_dir = str(Path.home() / '.inkbunny_history')
            
        os.makedirs(history_dir, exist_ok=True)
        
        # 아티스트 이름을 해시화하여 파일명 생성
        artist_hash = hashlib.md5(artist_username.encode()).hexdigest()[:10]
        self.download_history_file = os.path.join(history_dir, f"dl_history_{artist_hash}.dat")
        self.download_history = self._load_download_history()
        
    async def initialize(self):
        self.session = aiohttp.ClientSession()
        
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
            
    def _load_download_history(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.download_history_file):
            try:
                with open(self.download_history_file, 'rb') as f:
                    # 간단한 XOR 인코딩 적용해서 일반 텍스트로 노출되지 않도록 함
                    data = f.read()
                    if data:
                        # XOR 디코딩 (키: 0x42)
                        decoded_data = bytes([b ^ 0x42 for b in data])
                        return json.loads(decoded_data)
            except (json.JSONDecodeError, IOError, Exception) as e:
                logger.error(f"Failed to parse download history file: {e}")
        return {}
        
    def _save_download_history(self):
        try:
            os.makedirs(os.path.dirname(self.download_history_file), exist_ok=True)
            
            # JSON 데이터를 XOR 인코딩하여 저장
            json_data = json.dumps(self.download_history, indent=None)
            encoded_data = bytes([ord(c) ^ 0x42 for c in json_data])
            
            with open(self.download_history_file, 'wb') as f:
                f.write(encoded_data)
        except Exception as e:
            logger.error(f"Failed to save download history: {e}")
            
    def _sanitize_filename(self, filename: str) -> str:
        # Remove invalid characters
        invalid_chars = '<>:"/\\|?*'
        sanitized = ''.join(c for c in filename if c not in invalid_chars)
        
        # Replace multiple spaces with a single space
        sanitized = ' '.join(sanitized.split())
        
        # Replace problematic characters with underscores
        sanitized = sanitized.replace(' ', '_')
        
        # Ensure filename isn't too long
        if len(sanitized) > 100:
            name_parts = sanitized.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                sanitized = f"{base_name[:95]}...{extension}"
            else:
                sanitized = f"{sanitized[:95]}..."
                
        return sanitized
        
    async def download_file(self, download_file: DownloadFile) -> Tuple[bool, str]:
        if not self.session:
            await self.initialize()
            
        # Create artist folder
        artist_folder = os.path.join(self.save_directory, self.artist_username)
        os.makedirs(artist_folder, exist_ok=True)
        
        # Sanitize filename
        sanitized_filename = self._sanitize_filename(download_file.filename)
        filepath = Path(artist_folder) / sanitized_filename
        
        # Check download history
        submission_id = download_file.submission_id
        if submission_id in self.download_history:
            if self.download_history[submission_id].get("completed", False):
                logger.info(f"File already downloaded according to history: {sanitized_filename}")
                
                # Mark as skipped in history
                self.download_history[submission_id]["skipped"] = True
                self._save_download_history()
                
                return True, self.download_history[submission_id].get("file_hash", "")
                
        # Check if file exists
        if filepath.exists():
            logger.info(f"File already exists: {sanitized_filename}")
            file_hash = await self._calculate_file_hash(filepath)
            
            # Update download history
            self.download_history[submission_id] = {
                "filename": sanitized_filename,
                "url": download_file.url,
                "completed": True,
                "skipped": True,
                "file_hash": file_hash,
                "size": filepath.stat().st_size,
                "timestamp": datetime.now().isoformat()
            }
            self._save_download_history()
            
            return True, file_hash
            
        # Check for partial download
        temp_filepath = Path(f"{filepath}.part")
        downloaded_size = 0
        resume_download = False
        
        if temp_filepath.exists():
            downloaded_size = temp_filepath.stat().st_size
            logger.info(f"Found partial download for {sanitized_filename}, size: {downloaded_size} bytes")
            resume_download = True
        
        for attempt in range(self.retry_count):
            try:
                headers = {}
                if resume_download and downloaded_size > 0:
                    headers['Range'] = f'bytes={downloaded_size}-'
                    
                async with self.session.get(download_file.url, headers=headers) as response:
                    if response.status == 200 or (resume_download and response.status == 206):
                        mode = 'ab' if resume_download else 'wb'
                        
                        # Record in download history as in progress
                        self.download_history[submission_id] = {
                            "filename": sanitized_filename,
                            "url": download_file.url,
                            "completed": False,
                            "partial_path": str(temp_filepath),
                            "downloaded_size": downloaded_size,
                            "timestamp": datetime.now().isoformat()
                        }
                        self._save_download_history()
                        
                        with open(temp_filepath, mode) as f:
                            while True:
                                chunk = await response.content.read(8192)
                                if not chunk:
                                    break
                                f.write(chunk)
                                
                        # Download completed, rename file
                        temp_filepath.rename(filepath)
                        
                        logger.info(f"Successfully downloaded: {sanitized_filename}")
                        file_hash = await self._calculate_file_hash(filepath)
                        
                        # Update download history
                        self.download_history[submission_id] = {
                            "filename": sanitized_filename,
                            "url": download_file.url,
                            "completed": True,
                            "resumed": resume_download,
                            "skipped": False,
                            "file_hash": file_hash,
                            "size": filepath.stat().st_size,
                            "timestamp": datetime.now().isoformat()
                        }
                        self._save_download_history()
                        
                        return True, file_hash
                    else:
                        logger.error(f"Download failed (HTTP {response.status}): {download_file.url}")
                        
            except aiohttp.ClientError as e:
                logger.error(f"Download attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(self.retry_delay)
                    
        return False, ""
        
    async def _calculate_file_hash(self, filepath: Path) -> str:
        hasher = hashlib.sha256()
        
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
                
        return hasher.hexdigest()


class DownloadTracker:
    def __init__(self):
        self.downloaded_files = 0
        self.total_files = 0
        self.failed_downloads = 0
        self.skipped_files = 0
        self.resumed_downloads = 0
        self.file_hashes = {}
        
    def add_files(self, count: int):
        self.total_files += count
        
    def register_download(self, success: bool, file_hash: str = "", resumed: bool = False, skipped: bool = False):
        if success:
            if skipped:
                self.skipped_files += 1
            else:
                self.downloaded_files += 1
                
            if resumed:
                self.resumed_downloads += 1
                
            if file_hash:
                self.file_hashes[file_hash] = True
        else:
            self.failed_downloads += 1
            
    def get_stats(self) -> Dict[str, int]:
        return {
            "downloaded": self.downloaded_files,
            "resumed": self.resumed_downloads,
            "skipped": self.skipped_files,
            "failed": self.failed_downloads,
            "total": self.total_files
        }
        
    def get_progress_percentage(self) -> int:
        if self.total_files == 0:
            return 0
        return int((self.downloaded_files + self.failed_downloads + self.skipped_files) / self.total_files * 100)


class DownloaderThread(QThread):
    progress_signal = pyqtSignal(str)
    progress_update = pyqtSignal(int, int, int)  # current, total, percentage
    download_complete = pyqtSignal()
    error_signal = pyqtSignal(str)
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = True
        self.downloader = None
        self.tracker = DownloadTracker()
        self.api_client = None
        
    def run(self):
        asyncio.run(self.download_process())
        
    async def download_process(self):
        try:
            # Setup API client
            self.api_client = APIClient(
                APIConfig(**self.config['api']),
                Credentials(**self.config['credentials'])
            )
            
            await self.api_client.initialize()
            
            # Setup file downloader
            self.downloader = FileDownloader(
                self.config['download']['save_directory'],
                self.config['download']['artist_username']
            )
            
            await self.downloader.initialize()
            
            # Login process
            self.progress_signal.emit("Attempting to login...")
            if not await self.api_client.login():
                self.error_signal.emit("Login failed! Check your credentials.")
                return
                
            self.progress_signal.emit("Login successful!")
            
            # Get artist info
            artist_username = self.config['download']['artist_username']
            self.progress_signal.emit(f"Looking up artist: {artist_username}")
            
            user_id = await self.api_client.get_user_id(artist_username)
            if not user_id:
                self.error_signal.emit(f"Could not find artist: {artist_username}")
                return
                
            self.progress_signal.emit(f"Starting download for artist: {artist_username}")
            
            # Start downloading process
            await self._process_artist_submissions(user_id)
            
        except Exception as e:
            error_message = f"Program error: {str(e)}"
            logger.error(error_message)
            self.error_signal.emit(error_message)
        finally:
            # Cleanup
            if self.api_client:
                await self.api_client.close()
            if self.downloader:
                await self.downloader.close()
                
    async def _process_artist_submissions(self, user_id: str):
        page = 1
        total_downloads = 0
        max_downloads = self.config['download']['max_downloads']
        
        # Get initial page to determine total
        submissions, total_pages = await self.api_client.get_user_submissions(user_id, page)
        if not submissions:
            self.progress_signal.emit("No submissions found.")
            self.download_complete.emit()
            return
            
        self.progress_signal.emit(f"Found {total_pages} pages of submissions")
        
        # Process all pages
        should_continue = True
        while page <= total_pages and self.running and should_continue:
            if page > 1:  
                submissions, _ = await self.api_client.get_user_submissions(user_id, page)
                if not submissions:
                    self.progress_signal.emit("No more submissions found.")
                    break
            
            self.progress_signal.emit(f"\nProcessing page {page} of {total_pages}...")
            
            # Collect all files to download
            download_files = await self._collect_download_files(submissions)
            
            # Update tracker
            self.tracker.add_files(len(download_files))
            self.progress_update.emit(
                self.tracker.downloaded_files,
                self.tracker.total_files,
                self.tracker.get_progress_percentage()
            )
            
            # Download files with concurrency limit
            downloads_this_page = await self._download_files_concurrent(download_files)
            total_downloads += downloads_this_page
            
            # Check if we've reached max downloads
            if max_downloads > 0 and total_downloads >= max_downloads:
                self.progress_signal.emit(f"Reached maximum download limit ({max_downloads} files).")
                should_continue = False
                break
            
            self.progress_signal.emit(f"Page {page} completed")
            
            if page == total_pages or not should_continue:
                self.progress_signal.emit("Download completed.")
                break
                
            page += 1
            await asyncio.sleep(self.api_client.api_config.delay['between_pages'])
            
        self.progress_signal.emit(f"\nDownload completed! Total files downloaded: {total_downloads}")
        self.download_complete.emit()
        
    async def _collect_download_files(self, submissions: List[Dict]) -> List[DownloadFile]:
        download_files = []
        
        for submission in submissions:
            if not self.running:
                break
                
            submission_id = submission["submission_id"]
            title = submission.get("title", "untitled")
            
            # Get detailed file info
            files_info = await self.api_client.get_submission_files(submission_id)
            
            for file_info in files_info:
                for file_obj in file_info.get("files", []):
                    url = file_obj.get("file_url_full") or file_obj.get("file_url_screen")
                    if not url:
                        continue
                        
                    original_filename = file_obj.get("file_name", "")
                    clean_title = self._clean_filename(title)
                    filename = f"{clean_title}_{original_filename}"
                    
                    download_files.append(DownloadFile(
                        url=url,
                        filename=filename,
                        submission_id=submission_id,
                        title=title
                    ))
                    
        return download_files
        
    def _clean_filename(self, name: str) -> str:
        # Normalize unicode characters
        clean_name = unicodedata.normalize('NFKD', name)
        
        # Replace invalid characters with underscores
        invalid_chars = r'[<>:"/\\|?*\x00-\x1f]'
        clean_name = re.sub(invalid_chars, '_', clean_name)
        
        # Remove leading/trailing whitespace and dots
        clean_name = clean_name.strip('. ')
        
        # Replace multiple spaces with a single space
        clean_name = ' '.join(clean_name.split())
        
        # Add a prefix if the name starts with a reserved Windows name
        reserved_names = {'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                         'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                         'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'}
        
        name_parts = clean_name.split('.')
        if name_parts[0].upper() in reserved_names:
            clean_name = f"_{clean_name}"
            
        # Ensure filename isn't too long (Windows has a 255 character limit for paths)
        if len(clean_name) > 100:
            name_parts = clean_name.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                clean_name = f"{base_name[:95]}...{extension}"
            else:
                clean_name = f"{clean_name[:95]}..."
                
        return clean_name
        
    async def _download_files_concurrent(self, download_files: List[DownloadFile]) -> int:
        if not download_files:
            return 0
            
        successful_downloads = 0
        concurrent_limit = self.config['api']['concurrent_downloads']
        
        # Process downloads in batches
        for i in range(0, len(download_files), concurrent_limit):
            if not self.running:
                break
                
            batch = download_files[i:i + concurrent_limit]
            
            # Create download tasks
            tasks = []
            for download_file in batch:
                tasks.append(self.downloader.download_file(download_file))
                
            # Run downloads concurrently
            results = await asyncio.gather(*tasks)
            
            # Process results
            for success, file_hash in results:
                is_resumed = False
                is_skipped = False
                
                # Check if this was a resumed or skipped download
                submission_id = batch[results.index((success, file_hash))].submission_id
                if submission_id in self.downloader.download_history:
                    history_entry = self.downloader.download_history[submission_id]
                    if history_entry.get("resumed", False):
                        is_resumed = True
                    if history_entry.get("skipped", False):
                        is_skipped = True
                
                self.tracker.register_download(success, file_hash, resumed=is_resumed, skipped=is_skipped)
                
                if success:
                    successful_downloads += 1
                    
                    # Update the log with appropriate message
                    file_name = batch[results.index((success, file_hash))].filename
                    if is_resumed:
                        self.progress_signal.emit(f"Resumed and completed download: {file_name}")
                    elif is_skipped:
                        self.progress_signal.emit(f"Skipped existing file: {file_name}")
                    
            # Update progress
            stats = self.tracker.get_stats()
            self.progress_signal.emit(
                f"Progress: {stats['downloaded']} downloaded, {stats['resumed']} resumed, "
                f"{stats['skipped']} skipped, {stats['failed']} failed"
            )
            self.progress_update.emit(
                self.tracker.downloaded_files + self.tracker.skipped_files,
                self.tracker.total_files,
                self.tracker.get_progress_percentage()
            )
            
            # Add delay between batches
            if i + concurrent_limit < len(download_files) and self.running:
                await asyncio.sleep(self.api_client.api_config.delay['between_files'])
                
        return successful_downloads
        
    def stop(self):
        self.running = False


class ThemeManager:
    def __init__(self):
        self.settings_manager = SettingsManager()
        self.use_system_theme, self.theme = self.settings_manager.load_theme_settings()
        
    def get_system_theme(self):
        return "dark" if QApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark else "light"
        
    def get_current_theme(self):
        if self.use_system_theme:
            return self.get_system_theme()
        return self.theme
        
    def set_theme(self, use_system_theme, theme=None):
        self.use_system_theme = use_system_theme
        if not use_system_theme and theme:
            self.theme = theme
        self.settings_manager.save_theme_settings(self.use_system_theme, self.theme)
        
    def get_stylesheet(self):
        current_theme = self.get_current_theme()
        
        if current_theme == "light":
            return """
                QMainWindow, QWidget {
                    background-color: #f5f5f5;
                }
                QLabel, QCheckBox {
                    font-size: 12px;
                    color: #333333;
                }
                QLineEdit, QSpinBox, QComboBox {
                    padding: 8px;
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                    background-color: white;
                    font-size: 12px;
                }
                QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                    border: 1px solid #66afe9;
                }
                QPushButton {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    font-size: 12px;
                    color: white;
                    background-color: #007bff;
                }
                QPushButton:hover {
                    background-color: #0056b3;
                }
                QPushButton:pressed {
                    background-color: #004085;
                }
                QPushButton:disabled {
                    background-color: #cccccc;
                }
                QPushButton#stopButton {
                    background-color: #6c757d;
                }
                QPushButton#stopButton:hover {
                    background-color: #5a6268;
                }
                QPushButton#browseButton {
                    background-color: #6c757d;
                }
                QPushButton#browseButton:hover {
                    background-color: #5a6268;
                }
                QTextEdit {
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                    background-color: white;
                    color: #212529;
                    font-family: "Consolas", monospace;
                    font-size: 12px;
                    padding: 8px;
                }
                QProgressBar {
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                    background-color: white;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #007bff;
                }
                QTabWidget::pane {
                    border: 1px solid #cccccc;
                    background-color: white;
                }
                QTabBar::tab {
                    background-color: #e9ecef;
                    border: 1px solid #cccccc;
                    border-bottom: none;
                    padding: 8px 16px;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background-color: white;
                }
            """
        else:  # Dark theme
            return """
                QMainWindow, QWidget {
                    background-color: #212529;
                }
                QLabel, QCheckBox {
                    font-size: 12px;
                    color: #f8f9fa;
                }
                QLineEdit, QSpinBox, QComboBox {
                    padding: 8px;
                    border: 1px solid #495057;
                    border-radius: 4px;
                    background-color: #343a40;
                    color: #f8f9fa;
                    font-size: 12px;
                }
                QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                    border: 1px solid #0d6efd;
                }
                QPushButton {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    font-size: 12px;
                    color: white;
                    background-color: #0d6efd;
                }
                QPushButton:hover {
                    background-color: #0b5ed7;
                }
                QPushButton:pressed {
                    background-color: #0a58ca;
                }
                QPushButton:disabled {
                    background-color: #6c757d;
                }
                QPushButton#stopButton {
                    background-color: #6c757d;
                }
                QPushButton#stopButton:hover {
                    background-color: #5c636a;
                }
                QPushButton#browseButton {
                    background-color: #6c757d;
                }
                QPushButton#browseButton:hover {
                    background-color: #5c636a;
                }
                QTextEdit {
                    border: 1px solid #495057;
                    border-radius: 4px;
                    background-color: #343a40;
                    color: #f8f9fa;
                    font-family: "Consolas", monospace;
                    font-size: 12px;
                    padding: 8px;
                }
                QProgressBar {
                    border: 1px solid #495057;
                    border-radius: 4px;
                    background-color: #343a40;
                    color: #f8f9fa;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #0d6efd;
                }
                QTabWidget::pane {
                    border: 1px solid #495057;
                    background-color: #343a40;
                }
                QTabBar::tab {
                    background-color: #1e2125;
                    border: 1px solid #495057;
                    border-bottom: none;
                    padding: 8px 16px;
                    color: #f8f9fa;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background-color: #343a40;
                }
            """


class LoginTab(QWidget):
    def __init__(self, settings_manager):
        super().__init__()
        self.settings_manager = settings_manager
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Username layout
        username_layout = QVBoxLayout()
        username_label = QLabel("Username")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your Inkbunny username")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        
        # Password layout
        password_layout = QVBoxLayout()
        password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        
        # Remember me checkbox
        self.remember_me = QCheckBox("Remember Me")
        
        # Add layouts to main layout
        layout.addLayout(username_layout)
        layout.addLayout(password_layout)
        layout.addWidget(self.remember_me)
        layout.addStretch()
        
    def load_settings(self):
        username, password, remember = self.settings_manager.load_credentials()
        self.username_input.setText(username)
        self.password_input.setText(password)
        self.remember_me.setChecked(remember)
        
    def get_credentials(self) -> Tuple[str, str, bool]:
        return (
            self.username_input.text(),
            self.password_input.text(),
            self.remember_me.isChecked()
        )
        
    def save_settings(self):
        username, password, remember = self.get_credentials()
        self.settings_manager.save_credentials(username, password, remember)


class DownloadTab(QWidget):
    def __init__(self, settings_manager):
        super().__init__()
        self.settings_manager = settings_manager
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Artist username layout
        artist_layout = QVBoxLayout()
        artist_label = QLabel("Artist Username")
        self.artist_input = QLineEdit()
        self.artist_input.setPlaceholderText("Enter artist's username to download")
        artist_layout.addWidget(artist_label)
        artist_layout.addWidget(self.artist_input)

        # Max downloads layout
        max_downloads_layout = QVBoxLayout()
        max_downloads_label = QLabel("Maximum Files to Download (0 = no limit)")
        self.max_downloads_input = QLineEdit()
        self.max_downloads_input.setPlaceholderText("Enter maximum files")
        self.max_downloads_input.setValidator(QIntValidator(0, 10000))
        max_downloads_layout.addWidget(max_downloads_label)
        max_downloads_layout.addWidget(self.max_downloads_input)
        
        # Concurrent downloads layout
        concurrent_layout = QVBoxLayout()
        concurrent_label = QLabel("Concurrent Downloads")
        self.concurrent_input = QSpinBox()
        self.concurrent_input.setRange(1, 10)
        self.concurrent_input.setValue(3)
        concurrent_layout.addWidget(concurrent_label)
        concurrent_layout.addWidget(self.concurrent_input)
        
        # Save directory layout
        dir_layout = QVBoxLayout()
        dir_label = QLabel("Save Directory")
        dir_input_layout = QHBoxLayout()
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText("Select save directory")
        self.dir_button = QPushButton("Browse")
        self.dir_button.setObjectName("browseButton")
        self.dir_button.clicked.connect(self.select_directory)
        dir_input_layout.addWidget(self.dir_input)
        dir_input_layout.addWidget(self.dir_button)
        dir_layout.addWidget(dir_label)
        dir_layout.addLayout(dir_input_layout)
        
        # Add layouts to main layout
        layout.addLayout(artist_layout)
        layout.addLayout(max_downloads_layout)
        layout.addLayout(concurrent_layout)
        layout.addLayout(dir_layout)
        layout.addStretch()
        
    def load_settings(self):
        artist, save_dir, max_downloads, concurrent_downloads = self.settings_manager.load_download_settings()
        self.artist_input.setText(artist)
        self.dir_input.setText(save_dir)
        self.max_downloads_input.setText(str(max_downloads))
        self.concurrent_input.setValue(concurrent_downloads)
        
    def get_settings(self) -> Tuple[str, str, int, int]:
        return (
            self.artist_input.text(),
            self.dir_input.text(),
            int(self.max_downloads_input.text() or 0),
            self.concurrent_input.value()
        )
        
    def save_settings(self):
        artist, save_dir, max_downloads, concurrent_downloads = self.get_settings()
        self.settings_manager.save_download_settings(
            artist, save_dir, max_downloads, concurrent_downloads
        )
        
    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Save Directory")
        if directory:
            self.dir_input.setText(directory)


class SettingsTab(QWidget):
    theme_changed = pyqtSignal()
    
    def __init__(self, theme_manager):
        super().__init__()
        self.theme_manager = theme_manager
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Theme settings
        theme_group_layout = QVBoxLayout()
        theme_label = QLabel("Theme Settings")
        theme_label.setStyleSheet("font-weight: bold;")
        
        # System theme checkbox
        self.system_theme_check = QCheckBox("Use System Theme")
        self.system_theme_check.toggled.connect(self.toggle_system_theme)
        
        # Theme selection
        theme_selection_layout = QHBoxLayout()
        theme_selection_label = QLabel("Select Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_selection_layout.addWidget(theme_selection_label)
        theme_selection_layout.addWidget(self.theme_combo)
        
        # Add to group layout
        theme_group_layout.addWidget(theme_label)
        theme_group_layout.addWidget(self.system_theme_check)
        theme_group_layout.addLayout(theme_selection_layout)
        
        # Add to main layout
        layout.addLayout(theme_group_layout)
        layout.addStretch()
        
    def load_settings(self):
        use_system_theme, theme = self.theme_manager.use_system_theme, self.theme_manager.theme
        self.system_theme_check.setChecked(use_system_theme)
        self.theme_combo.setCurrentText("Light" if theme == "light" else "Dark")
        self.theme_combo.setEnabled(not use_system_theme)
        
    def toggle_system_theme(self, checked):
        self.theme_combo.setEnabled(not checked)
        self.theme_manager.set_theme(checked, self.theme_manager.theme)
        self.theme_changed.emit()
        
    def change_theme(self, theme_text):
        if not self.system_theme_check.isChecked():
            theme = "light" if theme_text == "Light" else "dark"
            self.theme_manager.set_theme(False, theme)
            self.theme_changed.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Inkbunny Downloader")
        self.setMinimumSize(700, 500)
        
        # Set icon
        self.setWindowIcon(QIcon('icon.ico'))
        
        # Initialize managers
        self.settings_manager = SettingsManager()
        self.theme_manager = ThemeManager()
        
        self.init_ui()
        self.apply_theme()
        
        self.download_thread = None

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.login_tab = LoginTab(self.settings_manager)
        self.download_tab = DownloadTab(self.settings_manager)
        self.settings_tab = SettingsTab(self.theme_manager)
        
        # Connect signals
        self.settings_tab.theme_changed.connect(self.apply_theme)
        
        # Add tabs
        self.tab_widget.addTab(self.login_tab, "Login")
        self.tab_widget.addTab(self.download_tab, "Download Settings")
        self.tab_widget.addTab(self.settings_tab, "App Settings")
        
        main_layout.addWidget(self.tab_widget)
        
        # Progress display and controls
        progress_layout = QVBoxLayout()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v/%m - %p%")
        progress_layout.addWidget(self.progress_bar)
        
        # Text log
        self.progress_display = QTextEdit()
        self.progress_display.setReadOnly(True)
        self.progress_display.setMinimumHeight(150)
        progress_layout.addWidget(self.progress_display)
        
        # Button layout
        button_layout = QHBoxLayout()
        self.download_button = QPushButton("Start Download")
        self.stop_button = QPushButton("Stop Download")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setEnabled(False)
        
        self.download_button.clicked.connect(self.start_download)
        self.stop_button.clicked.connect(self.stop_download)
        
        button_layout.addStretch()
        button_layout.addWidget(self.download_button)
        button_layout.addWidget(self.stop_button)
        
        progress_layout.addLayout(button_layout)
        main_layout.addLayout(progress_layout)

    def apply_theme(self):
        stylesheet = self.theme_manager.get_stylesheet()
        self.setStyleSheet(stylesheet)

    def validate_inputs(self):
        # Get data from tabs
        username, password, _ = self.login_tab.get_credentials()
        artist, save_dir, max_downloads, _ = self.download_tab.get_settings()
        
        if not username:
            QMessageBox.warning(self, "Validation Error", "Please enter your username")
            self.tab_widget.setCurrentWidget(self.login_tab)
            return False
            
        if not password:
            QMessageBox.warning(self, "Validation Error", "Please enter your password")
            self.tab_widget.setCurrentWidget(self.login_tab)
            return False
            
        if not artist:
            QMessageBox.warning(self, "Validation Error", "Please enter an artist username")
            self.tab_widget.setCurrentWidget(self.download_tab)
            return False
            
        if not save_dir:
            QMessageBox.warning(self, "Validation Error", "Please select a save directory")
            self.tab_widget.setCurrentWidget(self.download_tab)
            return False
            
        return True

    def create_config_dict(self):
        username, password, _ = self.login_tab.get_credentials()
        artist, save_dir, max_downloads, concurrent_downloads = self.download_tab.get_settings()
        
        return {
            "credentials": {
                "username": username,
                "password": password
            },
            "download": {
                "save_directory": save_dir,
                "artist_username": artist,
                "max_downloads": max_downloads
            },
            "api": {
                "base_url": "https://inkbunny.net/",
                "submissions_per_page": 100,
                "concurrent_downloads": concurrent_downloads,
                "delay": {
                    "between_files": 1.0,
                    "between_pages": 2.0
                }
            }
        }

    def start_download(self):
        if not self.validate_inputs():
            return
            
        # Save settings
        self.login_tab.save_settings()
        self.download_tab.save_settings()
            
        config_dict = self.create_config_dict()
        
        # Update UI
        self.download_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_display.clear()
        self.progress_bar.setValue(0)
        
        # Start download thread
        self.download_thread = DownloaderThread(config_dict)
        self.download_thread.progress_signal.connect(self.update_progress_text)
        self.download_thread.progress_update.connect(self.update_progress_bar)
        self.download_thread.download_complete.connect(self.download_finished)
        self.download_thread.error_signal.connect(self.handle_error)
        self.download_thread.start()

    def stop_download(self):
        if self.download_thread and self.download_thread.isRunning():
            reply = QMessageBox.question(self, 'Confirmation', 
                                       'Are you sure you want to stop the download?',
                                       QMessageBox.StandardButton.Yes | 
                                       QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.download_thread.stop()
                self.progress_display.append("\nStopping download...")
                self.stop_button.setEnabled(False)

    def update_progress_text(self, message):
        self.progress_display.append(message)
        self.progress_display.verticalScrollBar().setValue(
            self.progress_display.verticalScrollBar().maximum()
        )

    def update_progress_bar(self, current, total, percentage):
        self.progress_bar.setMaximum(total if total > 0 else 1)
        self.progress_bar.setValue(current)
        
        # Update window title with progress
        if total > 0:
            self.setWindowTitle(f"Inkbunny Downloader - {percentage}%")

    def download_finished(self):
        self.download_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_display.append("\nDownload process completed!")
        
        # Reset window title
        self.setWindowTitle("Inkbunny Downloader")
        
        # Show download stats if available
        if self.download_thread and hasattr(self.download_thread, 'tracker'):
            stats = self.download_thread.tracker.get_stats()
            summary = (
                f"\nDownload Summary:\n"
                f"- Total files processed: {stats['total']}\n"
                f"- Successfully downloaded: {stats['downloaded']}\n"
                f"- Resumed and completed: {stats['resumed']}\n"
                f"- Skipped (already exists): {stats['skipped']}\n"
                f"- Failed: {stats['failed']}"
            )
            self.progress_display.append(summary)

    def handle_error(self, error_message):
        self.progress_display.append(f"\nError: {error_message}")
        self.download_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def closeEvent(self, event):
        if self.download_thread and self.download_thread.isRunning():
            reply = QMessageBox.question(self, 'Confirmation', 
                                    'A download is in progress. Are you sure you want to quit?',
                                    QMessageBox.StandardButton.Yes | 
                                    QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.download_thread.stop()
                self.download_thread.wait()
            else:
                event.ignore()
                return
        event.accept()


def main():
    app = QApplication(sys.argv)
    
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
