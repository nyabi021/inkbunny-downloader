import sys
import os
import asyncio
import aiohttp
import json
import re
import unicodedata
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                           QTextEdit, QFileDialog, QMessageBox,
                           QCheckBox, QComboBox, QProgressBar, QTabWidget,
                           QGridLayout, QSpinBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QSize
from PyQt6.QtGui import QFont, QIntValidator, QIcon

# 인증 정보 암호화/복호화 (간소화된 버전)
class SecureStorage:
    def __init__(self):
        pass
        
    def encrypt(self, data: str) -> str:
        return data
        
    def decrypt(self, encrypted_data: str) -> str:
        return encrypted_data

# 설정 관리 클래스
class SettingsManager:
    def __init__(self):
        self.settings = QSettings('InkbunnyDownloader', 'Settings')
        self.secure_storage = SecureStorage()
        
    def save_credentials(self, username: str, password: str, remember: bool):
        self.settings.setValue('remember_me', remember)
        if remember:
            self.settings.setValue('username', username)
            self.settings.setValue('password', password)
        else:
            self.settings.remove('username')
            self.settings.remove('password')
            
    def load_credentials(self) -> Tuple[str, str, bool]:
        remember = self.settings.value('remember_me', False, type=bool)
        username = "" if not remember else self.settings.value('username', '')
        password = "" if not remember else self.settings.value('password', '')
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

# 데이터 클래스 정의
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

# Inkbunny API 클라이언트
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
                print(f"Request failed with status {response.status}")
            except aiohttp.ClientError as e:
                print(f"Request attempt {attempt + 1} failed: {str(e)}")
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
            print("Login successful!")
            return True
        print("Login failed")
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
            "type": "1,2,3,4,5",
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

# 파일 다운로더
class FileDownloader:
    def __init__(self, save_directory: str, artist_username: str, retry_count: int = 3, retry_delay: int = 5):
        self.save_directory = save_directory
        self.artist_username = artist_username
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.session = None
        
    async def initialize(self):
        self.session = aiohttp.ClientSession()
        
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
            
    def _sanitize_filename(self, filename: str) -> str:
        invalid_chars = '<>:"/\\|?*'
        sanitized = ''.join(c for c in filename if c not in invalid_chars)
        sanitized = ' '.join(sanitized.split())
        sanitized = sanitized.replace(' ', '_')
        if len(sanitized) > 100:
            name_parts = sanitized.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                sanitized = f"{base_name[:95]}...{extension}"
            else:
                sanitized = f"{sanitized[:95]}..."
        return sanitized
        
    async def download_file(self, download_file: DownloadFile) -> bool:
        if not self.session:
            await self.initialize()
        artist_folder = os.path.join(self.save_directory, self.artist_username)
        os.makedirs(artist_folder, exist_ok=True)
        sanitized_filename = self._sanitize_filename(download_file.filename)
        filepath = Path(artist_folder) / sanitized_filename
        for attempt in range(self.retry_count):
            try:
                async with self.session.get(download_file.url) as response:
                    if response.status == 200:
                        with open(filepath, 'wb') as f:
                            while True:
                                chunk = await response.content.read(8192)
                                if not chunk:
                                    break
                                f.write(chunk)
                        print(f"Successfully downloaded: {sanitized_filename}")
                        return True
                    else:
                        print(f"Download failed (HTTP {response.status}): {download_file.url}")
            except aiohttp.ClientError as e:
                print(f"Download attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(self.retry_delay)
        return False

# 다운로드 진행 상황 추적
class DownloadTracker:
    def __init__(self):
        self.downloaded_files = 0
        self.total_files = 0
        self.failed_downloads = 0
        
    def add_files(self, count: int):
        self.total_files += count
        
    def register_download(self, success: bool):
        if success:
            self.downloaded_files += 1
        else:
            self.failed_downloads += 1
            
    def get_stats(self) -> Dict[str, int]:
        return {
            "downloaded": self.downloaded_files,
            "failed": self.failed_downloads,
            "total": self.total_files
        }
        
    def get_progress_percentage(self) -> int:
        if self.total_files == 0:
            return 0
        return int((self.downloaded_files + self.failed_downloads) / self.total_files * 100)

# 다운로드 스레드
class DownloaderThread(QThread):
    progress_signal = pyqtSignal(str)
    progress_update = pyqtSignal(int, int, int)
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
            self.api_client = APIClient(APIConfig(**self.config['api']), Credentials(**self.config['credentials']))
            await self.api_client.initialize()
            self.downloader = FileDownloader(self.config['download']['save_directory'], self.config['download']['artist_username'])
            await self.downloader.initialize()
            self.progress_signal.emit("Attempting to login...")
            if not await self.api_client.login():
                self.error_signal.emit("Login failed! Check your credentials.")
                return
            self.progress_signal.emit("Login successful!")
            artist_username = self.config['download']['artist_username']
            self.progress_signal.emit(f"Looking up artist: {artist_username}")
            user_id = await self.api_client.get_user_id(artist_username)
            if not user_id:
                self.error_signal.emit(f"Could not find artist: {artist_username}")
                return
            self.progress_signal.emit(f"Starting download for artist: {artist_username}")
            await self._process_artist_submissions(user_id)
        except Exception as e:
            error_message = f"Program error: {str(e)}"
            print(error_message)
            self.error_signal.emit(error_message)
        finally:
            if self.api_client:
                await self.api_client.close()
            if self.downloader:
                await self.downloader.close()
                
    async def _process_artist_submissions(self, user_id: str):
        page = 1
        total_downloads = 0
        max_downloads = self.config['download']['max_downloads']
        submissions, total_pages = await self.api_client.get_user_submissions(user_id, page)
        if not submissions:
            self.progress_signal.emit("No submissions found.")
            self.download_complete.emit()
            return
        self.progress_signal.emit(f"Found {total_pages} pages of submissions")
        should_continue = True
        while page <= total_pages and self.running and should_continue:
            if page > 1:
                submissions, _ = await self.api_client.get_user_submissions(user_id, page)
                if not submissions:
                    self.progress_signal.emit("No more submissions found.")
                    break
            self.progress_signal.emit(f"\nProcessing page {page} of {total_pages}...")
            download_files = await self._collect_download_files(submissions)
            self.tracker.add_files(len(download_files))
            self.progress_update.emit(self.tracker.downloaded_files, self.tracker.total_files, self.tracker.get_progress_percentage())
            downloads_this_page = await self._download_files_concurrent(download_files)
            total_downloads += downloads_this_page
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
            files_info = await self.api_client.get_submission_files(submission_id)
            for file_info in files_info:
                for file_obj in file_info.get("files", []):
                    url = file_obj.get("file_url_full") or file_obj.get("file_url_screen")
                    if not url:
                        continue
                    original_filename = file_obj.get("file_name", "")
                    clean_title = self._clean_filename(title)
                    filename = f"{clean_title}_{original_filename}"
                    download_files.append(DownloadFile(url=url, filename=filename, submission_id=submission_id, title=title))
        return download_files
        
    def _clean_filename(self, name: str) -> str:
        clean_name = unicodedata.normalize('NFKD', name)
        invalid_chars = r'[<>:"/\\|?*\x00-\x1f]'
        clean_name = re.sub(invalid_chars, '_', clean_name)
        clean_name = clean_name.strip('. ')
        clean_name = ' '.join(clean_name.split())
        reserved_names = {'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                         'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                         'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'}
        name_parts = clean_name.split('.')
        if name_parts[0].upper() in reserved_names:
            clean_name = f"_{clean_name}"
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
        for i in range(0, len(download_files), concurrent_limit):
            if not self.running:
                break
            batch = download_files[i:i + concurrent_limit]
            tasks = [self.downloader.download_file(download_file) for download_file in batch]
            results = await asyncio.gather(*tasks)
            for idx, success in enumerate(results):
                self.tracker.register_download(success)
                if success:
                    successful_downloads += 1
                    file_name = batch[idx].filename
                    self.progress_signal.emit(f"Downloaded: {file_name}")
                else:
                    file_name = batch[idx].filename
                    self.progress_signal.emit(f"Failed to download: {file_name}")
            stats = self.tracker.get_stats()
            self.progress_signal.emit(f"Progress: {stats['downloaded']} downloaded, {stats['failed']} failed")
            self.progress_update.emit(self.tracker.downloaded_files, self.tracker.total_files, self.tracker.get_progress_percentage())
            if i + concurrent_limit < len(download_files) and self.running:
                await asyncio.sleep(self.api_client.api_config.delay['between_files'])
        return successful_downloads
        
    def stop(self):
        self.running = False

# 테마 관리 클래스
class ThemeManager:
    def __init__(self):
        self.settings_manager = SettingsManager()
        self.use_system_theme, self.theme = self.settings_manager.load_theme_settings()
        
    def get_system_theme(self):
        return "dark" if QApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark else "light"
        
    def get_current_theme(self):
        return self.get_system_theme() if self.use_system_theme else self.theme
        
    def set_theme(self, use_system_theme, theme=None):
        self.use_system_theme = use_system_theme
        if not use_system_theme and theme:
            self.theme = theme
        self.settings_manager.save_theme_settings(self.use_system_theme, self.theme)
        
    def get_stylesheet(self):
        current_theme = self.get_current_theme()
        if current_theme == "light":
            return """
                QMainWindow, QWidget {background-color: #f5f5f5;}
                QLabel, QCheckBox {font-size: 12px; color: #333333;}
                QLineEdit, QSpinBox, QComboBox {padding: 8px; border: 1px solid #cccccc; border-radius: 4px; background-color: white; font-size: 12px;}
                QLineEdit:focus, QSpinBox:focus, QComboBox:focus {border: 1px solid #66afe9;}
                QPushButton {padding: 8px 16px; border: none; border-radius: 4px; font-size: 12px; color: white; background-color: #007bff;}
                QPushButton:hover {background-color: #0056b3;}
                QPushButton:pressed {background-color: #004085;}
                QPushButton:disabled {background-color: #cccccc;}
                QPushButton#stopButton {background-color: #6c757d;}
                QPushButton#stopButton:hover {background-color: #5a6268;}
                QPushButton#browseButton {background-color: #6c757d;}
                QPushButton#browseButton:hover {background-color: #5a6268;}
                QTextEdit {border: 1px solid #cccccc; border-radius: 4px; background-color: white; color: #212529; font-family: "Consolas", monospace; font-size: 12px; padding: 8px;}
                QProgressBar {border: 1px solid #cccccc; border-radius: 4px; background-color: white; text-align: center;}
                QProgressBar::chunk {background-color: #007bff;}
                QTabWidget::pane {border: 1px solid #cccccc; background-color: white;}
                QTabBar::tab {background-color: #e9ecef; border: 1px solid #cccccc; border-bottom: none; padding: 8px 16px; border-top-left-radius: 4px; border-top-right-radius: 4px;}
                QTabBar::tab:selected {background-color: white;}
            """
        else:
            return """
                QMainWindow, QWidget {background-color: #212529;}
                QLabel, QCheckBox {font-size: 12px; color: #f8f9fa;}
                QLineEdit, QSpinBox, QComboBox {padding: 8px; border: 1px solid #495057; border-radius: 4px; background-color: #343a40; color: #f8f9fa; font-size: 12px;}
                QLineEdit:focus, QSpinBox:focus, QComboBox:focus {border: 1px solid #0d6efd;}
                QPushButton {padding: 8px 16px; border: none; border-radius: 4px; font-size: 12px; color: white; background-color: #0d6efd;}
                QPushButton:hover {background-color: #0b5ed7;}
                QPushButton:pressed {background-color: #0a58ca;}
                QPushButton:disabled {background-color: #6c757d;}
                QPushButton#stopButton {background-color: #6c757d;}
                QPushButton#stopButton:hover {background-color: #5c636a;}
                QPushButton#browseButton {background-color: #6c757d;}
                QPushButton#browseButton:hover {background-color: #5c636a;}
                QTextEdit {border: 1px solid #495057; border-radius: 4px; background-color: #343a40; color: #f8f9fa; font-family: "Consolas", monospace; font-size: 12px; padding: 8px;}
                QProgressBar {border: 1px solid #495057; border-radius: 4px; background-color: #343a40; color: #f8f9fa; text-align: center;}
                QProgressBar::chunk {background-color: #0d6efd;}
                QTabWidget::pane {border: 1px solid #495057; background-color: #343a40;}
                QTabBar::tab {background-color: #1e2125; border: 1px solid #495057; border-bottom: none; padding: 8px 16px; color: #f8f9fa; border-top-left-radius: 4px; border-top-right-radius: 4px;}
                QTabBar::tab:selected {background-color: #343a40;}
            """

# 로그인 탭
class LoginTab(QWidget):
    def __init__(self, settings_manager):
        super().__init__()
        self.settings_manager = settings_manager
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        username_layout = QVBoxLayout()
        username_label = QLabel("Username")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your Inkbunny username")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        password_layout = QVBoxLayout()
        password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        self.remember_me = QCheckBox("Remember Me")
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
        return (self.username_input.text(), self.password_input.text(), self.remember_me.isChecked())
        
    def save_settings(self):
        username, password, remember = self.get_credentials()
        self.settings_manager.save_credentials(username, password, remember)

# 다운로드 설정 탭
class DownloadTab(QWidget):
    def __init__(self, settings_manager):
        super().__init__()
        self.settings_manager = settings_manager
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        artist_layout = QVBoxLayout()
        artist_label = QLabel("Artist Username")
        self.artist_input = QLineEdit()
        self.artist_input.setPlaceholderText("Enter artist's username to download")
        artist_layout.addWidget(artist_label)
        artist_layout.addWidget(self.artist_input)
        max_downloads_layout = QVBoxLayout()
        max_downloads_label = QLabel("Maximum Files to Download (0 = no limit)")
        self.max_downloads_input = QLineEdit()
        self.max_downloads_input.setValidator(QIntValidator(0, 10000))
        max_downloads_layout.addWidget(max_downloads_label)
        max_downloads_layout.addWidget(self.max_downloads_input)
        concurrent_layout = QVBoxLayout()
        concurrent_label = QLabel("Concurrent Downloads")
        self.concurrent_input = QSpinBox()
        self.concurrent_input.setRange(1, 10)
        self.concurrent_input.setValue(3)
        concurrent_layout.addWidget(concurrent_label)
        concurrent_layout.addWidget(self.concurrent_input)
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
        return (self.artist_input.text(), self.dir_input.text(), int(self.max_downloads_input.text() or 0), self.concurrent_input.value())
        
    def save_settings(self):
        artist, save_dir, max_downloads, concurrent_downloads = self.get_settings()
        self.settings_manager.save_download_settings(artist, save_dir, max_downloads, concurrent_downloads)
        
    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Save Directory")
        if directory:
            self.dir_input.setText(directory)

# 앱 설정 탭
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
        theme_group_layout = QVBoxLayout()
        theme_label = QLabel("Theme Settings")
        theme_label.setStyleSheet("font-weight: bold;")
        self.system_theme_check = QCheckBox("Use System Theme")
        self.system_theme_check.toggled.connect(self.toggle_system_theme)
        theme_selection_layout = QHBoxLayout()
        theme_selection_label = QLabel("Select Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_selection_layout.addWidget(theme_selection_label)
        theme_selection_layout.addWidget(self.theme_combo)
        theme_group_layout.addWidget(theme_label)
        theme_group_layout.addWidget(self.system_theme_check)
        theme_group_layout.addLayout(theme_selection_layout)
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

# 메인 윈도우
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Inkbunny Downloader")
        self.setMinimumSize(700, 500)
        self.setWindowIcon(QIcon('icon.ico'))
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
        self.tab_widget = QTabWidget()
        self.login_tab = LoginTab(self.settings_manager)
        self.download_tab = DownloadTab(self.settings_manager)
        self.settings_tab = SettingsTab(self.theme_manager)
        self.settings_tab.theme_changed.connect(self.apply_theme)
        self.tab_widget.addTab(self.login_tab, "Login")
        self.tab_widget.addTab(self.download_tab, "Download Settings")
        self.tab_widget.addTab(self.settings_tab, "App Settings")
        main_layout.addWidget(self.tab_widget)
        progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v/%m - %p%")
        progress_layout.addWidget(self.progress_bar)
        self.progress_display = QTextEdit()
        self.progress_display.setReadOnly(True)
        self.progress_display.setMinimumHeight(150)
        progress_layout.addWidget(self.progress_display)
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
        self.setStyleSheet(self.theme_manager.get_stylesheet())

    def validate_inputs(self):
        username, password, _ = self.login_tab.get_credentials()
        artist, save_dir, _, _ = self.download_tab.get_settings()
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
            "credentials": {"username": username, "password": password},
            "download": {"save_directory": save_dir, "artist_username": artist, "max_downloads": max_downloads},
            "api": {
                "base_url": "https://inkbunny.net/",
                "submissions_per_page": 100,
                "concurrent_downloads": concurrent_downloads,
                "delay": {"between_files": 1.0, "between_pages": 2.0}
            }
        }

    def start_download(self):
        if not self.validate_inputs():
            return
        self.login_tab.save_settings()
        self.download_tab.save_settings()
        config_dict = self.create_config_dict()
        self.download_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_display.clear()
        self.progress_bar.setValue(0)
        self.download_thread = DownloaderThread(config_dict)
        self.download_thread.progress_signal.connect(self.update_progress_text)
        self.download_thread.progress_update.connect(self.update_progress_bar)
        self.download_thread.download_complete.connect(self.download_finished)
        self.download_thread.error_signal.connect(self.handle_error)
        self.download_thread.start()

    def stop_download(self):
        if self.download_thread and self.download_thread.isRunning():
            reply = QMessageBox.question(self, 'Confirmation', 'Are you sure you want to stop the download?',
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.download_thread.stop()
                self.progress_display.append("\nStopping download...")
                self.stop_button.setEnabled(False)

    def update_progress_text(self, message):
        self.progress_display.append(message)
        self.progress_display.verticalScrollBar().setValue(self.progress_display.verticalScrollBar().maximum())

    def update_progress_bar(self, current, total, percentage):
        self.progress_bar.setMaximum(total if total > 0 else 1)
        self.progress_bar.setValue(current)
        if total > 0:
            self.setWindowTitle(f"Inkbunny Downloader - {percentage}%")

    def download_finished(self):
        self.download_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_display.append("\nDownload process completed!")
        self.setWindowTitle("Inkbunny Downloader")
        if self.download_thread and hasattr(self.download_thread, 'tracker'):
            stats = self.download_thread.tracker.get_stats()
            summary = f"\nDownload Summary:\n- Total files processed: {stats['total']}\n- Successfully downloaded: {stats['downloaded']}\n- Failed: {stats['failed']}"
            self.progress_display.append(summary)

    def handle_error(self, error_message):
        self.progress_display.append(f"\nError: {error_message}")
        self.download_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def closeEvent(self, event):
        if self.download_thread and self.download_thread.isRunning():
            reply = QMessageBox.question(self, 'Confirmation', 'A download is in progress. Are you sure you want to quit?',
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.download_thread.stop()
                self.download_thread.wait()
            else:
                event.ignore()
                return
        event.accept()

# 메인 함수
def main():
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
