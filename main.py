"""
Pydabse - 基于文件系统的轻量级键值存储数据库
作者: 7676686 & DeekSeek R1 & Github Copilot
Main dev: 7676686
Idea and review: DeekSeek R1
Help:Github Copilot
创建日期: 2025-12-01
最后修改: 2025-12-06 
版本: 2.1
功能: 支持多数据库、事务、加密、索引等高级功能，带完整的日志记录
Lincense: GPL-3.0
"""

import os
import json
import time
import shutil
import zipfile
import hashlib
import csv
import threading
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass, asdict
import inspect
import traceback


# ==================== 日志配置 ====================
def setup_logging(level=logging.INFO, log_file=None):
    """配置日志记录"""
    log_format = '[%(asctime)s][%(name)s][%(levelname)s]:%(message)s'
    
    # 创建根记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # 清除已有的处理器
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # 文件处理器（如果指定了日志文件）
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # 设置第三方库的日志级别
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    return root_logger


# ==================== 异常定义 ====================
class DatabaseError(Exception):
    """数据库基础异常"""
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        logging.error(f"DatabaseError [{error_code}]: {message}")


class DatabaseNotFoundError(DatabaseError):
    """数据库不存在异常"""
    def __init__(self, message, database_name=None):
        super().__init__(message, "DB_NOT_FOUND")
        self.database_name = database_name


class KeyNotFoundError(DatabaseError):
    """键不存在异常"""
    def __init__(self, message, key=None):
        super().__init__(message, "KEY_NOT_FOUND")
        self.key = key


class TransactionError(DatabaseError):
    """事务异常"""
    def __init__(self, message):
        super().__init__(message, "TRANSACTION_ERROR")


class EncryptionError(DatabaseError):
    """加密异常"""
    def __init__(self, message):
        super().__init__(message, "ENCRYPTION_ERROR")


# ==================== 配置类 ====================
@dataclass
class DatabaseConfig:
    """数据库配置类"""
    base_dir: str = "DataBase"
    auto_backup: bool = True
    backup_dir: str = "backups"
    compression: bool = True
    encryption_key: Optional[str] = None
    cache_size: int = 1000  # LRU缓存大小
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    auto_cleanup: bool = True
    cleanup_interval: int = 3600  # 清理间隔（秒）
    log_level: str = "INFO"  # 日志级别
    log_file: Optional[str] = None  # 日志文件
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DatabaseConfig':
        return cls(**data)


# ==================== 加密模块 ====================
class EncryptionManager:
    """加密管理器"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key
        self.logger = logging.getLogger(__name__ + ".EncryptionManager")
    
    def encrypt(self, data: str) -> str:
        """加密数据"""
        if not self.encryption_key or not data:
            return data
        
        try:
            key_bytes = self.encryption_key.encode('utf-8')
            data_bytes = data.encode('utf-8')
            encrypted = bytearray()
            
            for i, byte in enumerate(data_bytes):
                key_byte = key_bytes[i % len(key_bytes)]
                encrypted.append(byte ^ key_byte)
            
            self.logger.debug(f"加密数据成功，长度: {len(data)}")
            return encrypted.hex()
        except Exception as e:
            self.logger.error(f"加密数据失败: {str(e)}")
            raise EncryptionError(f"加密失败: {str(e)}")
    
    def decrypt(self, encrypted_hex: str) -> str:
        """解密数据"""
        if not self.encryption_key or not encrypted_hex:
            return encrypted_hex
        
        try:
            key_bytes = self.encryption_key.encode('utf-8')
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            decrypted = bytearray()
            
            for i, byte in enumerate(encrypted_bytes):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(byte ^ key_byte)
            
            self.logger.debug(f"解密数据成功，长度: {len(encrypted_hex)}")
            return decrypted.decode('utf-8')
        except Exception as e:
            self.logger.error(f"解密数据失败: {str(e)}")
            raise EncryptionError(f"解密失败: {str(e)}")
    
    def hash_key(self, key: str, salt: str = "") -> str:
        """哈希键名"""
        try:
            return hashlib.sha256((key + salt).encode()).hexdigest()[:16]
        except Exception as e:
            self.logger.error(f"哈希键名失败: {str(e)}")
            return key


# ==================== 缓存模块 ====================
class LRUCache:
    """LRU缓存实现"""
    
    def __init__(self, capacity: int = 1000):
        self.capacity = capacity
        self.cache = {}
        self.order = []  # 最近使用的键在最后
        self.hits = 0
        self.misses = 0
        self.logger = logging.getLogger(__name__ + ".LRUCache")
        self.logger.info(f"初始化LRU缓存，容量: {capacity}")
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存项"""
        if key not in self.cache:
            self.misses += 1
            self.logger.debug(f"缓存未命中: {key}")
            return None
        
        # 更新使用顺序
        self.order.remove(key)
        self.order.append(key)
        self.hits += 1
        self.logger.debug(f"缓存命中: {key}")
        return self.cache[key]
    
    def set(self, key: str, value: Any) -> None:
        """设置缓存项"""
        if key in self.cache:
            self.order.remove(key)
            self.logger.debug(f"更新缓存: {key}")
        elif len(self.cache) >= self.capacity:
            # 移除最久未使用的
            oldest = self.order.pop(0)
            del self.cache[oldest]
            self.logger.debug(f"缓存已满，移除最旧项: {oldest}")
        
        self.cache[key] = value
        self.order.append(key)
        self.logger.debug(f"设置缓存: {key}")
    
    def delete(self, key: str) -> None:
        """删除缓存项"""
        if key in self.cache:
            del self.cache[key]
            self.order.remove(key)
            self.logger.debug(f"删除缓存: {key}")
    
    def clear(self) -> None:
        """清空缓存"""
        self.cache.clear()
        self.order.clear()
        self.logger.debug("清空缓存")
    
    def stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        hit_rate = self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0
        return {
            "size": len(self.cache),
            "capacity": self.capacity,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate
        }


# ==================== 索引模块 ====================
class IndexManager:
    """索引管理器"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.indices = {}
        self.index_file = os.path.join(db_path, "__indices.json")
        self.logger = logging.getLogger(__name__ + ".IndexManager")
        self._load_indices()
    
    def _load_indices(self) -> None:
        """加载索引"""
        try:
            if os.path.exists(self.index_file):
                with open(self.index_file, 'r') as f:
                    self.indices = json.load(f)
                self.logger.info(f"从 {self.index_file} 加载了 {len(self.indices)} 个索引")
            else:
                self.indices = {}
                self.logger.debug("未找到索引文件，创建新索引")
        except Exception as e:
            self.logger.error(f"加载索引失败: {str(e)}")
            self.indices = {}
    
    def _save_indices(self) -> None:
        """保存索引"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(self.indices, f, indent=2)
            self.logger.debug(f"保存索引到 {self.index_file}")
        except Exception as e:
            self.logger.error(f"保存索引失败: {str(e)}")
    
    def create_index(self, index_name: str, field: str) -> None:
        """创建索引"""
        try:
            if index_name in self.indices:
                raise DatabaseError(f"索引 {index_name} 已存在")
            
            self.logger.info(f"创建索引: {index_name} (字段: {field})")
            
            self.indices[index_name] = {
                "field": field,
                "values": {},
                "created": datetime.now().isoformat(),
                "size": 0
            }
            
            # 构建索引
            count = 0
            for file_name in os.listdir(self.db_path):
                if file_name.endswith('.json') and not file_name.startswith('__'):
                    key = file_name[:-5]
                    file_path = os.path.join(self.db_path, file_name)
                    
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                        
                        if field in data.get('value', {}):
                            field_value = str(data['value'][field])
                            if field_value not in self.indices[index_name]["values"]:
                                self.indices[index_name]["values"][field_value] = []
                            self.indices[index_name]["values"][field_value].append(key)
                            count += 1
                    except Exception as e:
                        self.logger.warning(f"处理文件 {file_name} 时出错: {str(e)}")
                        continue
            
            self.indices[index_name]["size"] = count
            self._save_indices()
            self.logger.info(f"索引 {index_name} 创建完成，包含 {count} 个条目")
            
        except Exception as e:
            self.logger.error(f"创建索引失败: {str(e)}")
            raise
    
    def search_by_index(self, index_name: str, value: Any) -> List[str]:
        """通过索引搜索"""
        try:
            if index_name not in self.indices:
                raise DatabaseError(f"索引 {index_name} 不存在")
            
            value_str = str(value)
            result = self.indices[index_name]["values"].get(value_str, [])
            self.logger.debug(f"索引搜索: {index_name}={value}，找到 {len(result)} 个结果")
            return result
            
        except Exception as e:
            self.logger.error(f"索引搜索失败: {str(e)}")
            raise
    
    def add_to_index(self, index_name: str, key: str, data: Dict) -> None:
        """向索引添加项"""
        try:
            if index_name in self.indices:
                field = self.indices[index_name]["field"]
                if field in data:
                    field_value = str(data[field])
                    if field_value not in self.indices[index_name]["values"]:
                        self.indices[index_name]["values"][field_value] = []
                    
                    # 避免重复添加
                    if key not in self.indices[index_name]["values"][field_value]:
                        self.indices[index_name]["values"][field_value].append(key)
                        self.indices[index_name]["size"] += 1
                        self._save_indices()
                        self.logger.debug(f"向索引 {index_name} 添加: {key}={field_value}")
                        
        except Exception as e:
            self.logger.error(f"向索引添加项失败: {str(e)}")
    
    def remove_from_index(self, index_name: str, key: str, data: Dict) -> None:
        """从索引移除项"""
        try:
            if index_name in self.indices:
                field = self.indices[index_name]["field"]
                if field in data:
                    field_value = str(data[field])
                    if field_value in self.indices[index_name]["values"]:
                        if key in self.indices[index_name]["values"][field_value]:
                            self.indices[index_name]["values"][field_value].remove(key)
                            self.indices[index_name]["size"] -= 1
                            
                            # 如果该值没有其他键了，删除该值
                            if not self.indices[index_name]["values"][field_value]:
                                del self.indices[index_name]["values"][field_value]
                            
                            self._save_indices()
                            self.logger.debug(f"从索引 {index_name} 移除: {key}={field_value}")
                            
        except Exception as e:
            self.logger.error(f"从索引移除项失败: {str(e)}")


# ==================== 主数据库类 ====================
class FileDatabase:
    """
    基于文件系统的键值存储数据库
    
    特性:
    - 多数据库支持
    - 事务处理
    - 数据加密
    - LRU缓存
    - 索引支持
    - 过期时间
    - 数据备份和恢复
    - 导入导出
    - 统计信息
    """
    
    def __init__(self, db_name: str, config: Optional[DatabaseConfig] = None):
        """
        初始化数据库
        
        Args:
            db_name: 数据库名称
            config: 数据库配置
        """
        # 设置日志
        self.config = config or DatabaseConfig()
        setup_logging(
            level=getattr(logging, self.config.log_level, logging.INFO),
            log_file=self.config.log_file
        )
        self.logger = logging.getLogger(__name__ + ".FileDatabase")
        self.logger.info(f"初始化数据库: {db_name}")
        
        # 初始化配置
        self.db_name = db_name
        self.databases = [db_name]
        self.current_db_index = 0
        self.base_dir = self.config.base_dir
        
        # 初始化组件
        self.lock = threading.RLock()
        self.cache = LRUCache(self.config.cache_size)
        self.transaction_log = []
        self.in_transaction = False
        self.encryption_manager = EncryptionManager(self.config.encryption_key)
        
        # 确保基础目录存在
        os.makedirs(self.base_dir, exist_ok=True)
        
        # 创建初始数据库
        self._ensure_db_exists(db_name)
        
        # 初始化索引管理器
        self.indices = IndexManager(self.get_current_db_path())
        
        # 加载元数据
        self._load_metadata()
        
        # 自动清理线程（如果启用）
        if self.config.auto_cleanup:
            self._start_cleanup_thread()
        
        self.logger.info(f"数据库 {db_name} 初始化完成")
    
    def _ensure_db_exists(self, db_name: str) -> None:
        """确保数据库目录存在"""
        try:
            db_path = os.path.join(self.base_dir, db_name)
            os.makedirs(db_path, exist_ok=True)
            
            # 创建默认文件（如果不存在）
            default_file = os.path.join(db_path, "__default.json")
            if not os.path.exists(default_file):
                default_data = {
                    "created": datetime.now().isoformat(),
                    "modified": datetime.now().isoformat(),
                    "description": f"Database '{db_name}'",
                    "version": "2.1"
                }
                self._write_json(default_file, default_data)
                self.logger.debug(f"创建默认文件: {default_file}")
            
        except Exception as e:
            self.logger.error(f"确保数据库存在失败: {str(e)}")
            raise
    
    def get_current_db_path(self) -> str:
        """获取当前数据库路径"""
        return os.path.join(self.base_dir, self.databases[self.current_db_index])
    
    def _get_file_path(self, key: str) -> str:
        """获取键对应的文件路径"""
        # 如果启用了加密，对键进行哈希
        if self.config.encryption_key:
            key = self.encryption_manager.hash_key(key, self.config.encryption_key)
        
        return os.path.join(self.get_current_db_path(), f"{key}.json")
    
    def _write_json(self, file_path: str, data: Any) -> None:
        """写入JSON文件（带压缩）"""
        try:
            # 检查文件大小限制
            if self.config.max_file_size > 0:
                data_str = json.dumps(data)
                if len(data_str) > self.config.max_file_size:
                    raise DatabaseError(f"数据大小超过限制: {len(data_str)} > {self.config.max_file_size}")
            
            # 如果需要加密
            if self.config.encryption_key and not file_path.endswith("__metadata.json") and not file_path.endswith("__indices.json"):
                data_str = json.dumps(data)
                encrypted = self.encryption_manager.encrypt(data_str)
                data = {"encrypted": True, "data": encrypted}
            
            # 写入文件
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            self.logger.debug(f"写入文件: {file_path}")
            
        except Exception as e:
            self.logger.error(f"写入JSON文件失败: {str(e)}")
            raise
    
    def _read_json(self, file_path: str) -> Any:
        """读取JSON文件"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"文件不存在: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 如果需要解密
            if isinstance(data, dict) and data.get("encrypted"):
                if not self.config.encryption_key:
                    raise EncryptionError("数据已加密但未提供密钥")
                decrypted = self.encryption_manager.decrypt(data["data"])
                data = json.loads(decrypted)
            
            self.logger.debug(f"读取文件: {file_path}")
            return data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON解析错误: {file_path} - {str(e)}")
            raise DatabaseError(f"文件 {file_path} 不是有效的JSON格式")
        except FileNotFoundError as e:
            self.logger.debug(f"文件不存在: {file_path}")
            raise KeyNotFoundError(f"键不存在")
        except Exception as e:
            self.logger.error(f"读取JSON文件失败: {str(e)}")
            raise
    
    def _load_metadata(self) -> None:
        """加载数据库元数据"""
        metadata_file = os.path.join(self.get_current_db_path(), "__metadata.json")
        
        try:
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    self.metadata = json.load(f)
                self.logger.debug(f"加载元数据: {metadata_file}")
            else:
                self.metadata = {
                    "created": datetime.now().isoformat(),
                    "modified": datetime.now().isoformat(),
                    "key_count": 0,
                    "total_size": 0,
                    "operations": 0
                }
                self._save_metadata()
                
        except Exception as e:
            self.logger.error(f"加载元数据失败: {str(e)}")
            self.metadata = {}
    
    def _save_metadata(self) -> None:
        """保存数据库元数据"""
        try:
            metadata_file = os.path.join(self.get_current_db_path(), "__metadata.json")
            self.metadata["modified"] = datetime.now().isoformat()
            
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            
            self.logger.debug(f"保存元数据: {metadata_file}")
            
        except Exception as e:
            self.logger.error(f"保存元数据失败: {str(e)}")
    
    def _update_metadata(self, operation: str, key: Optional[str] = None) -> None:
        """更新元数据"""
        with self.lock:
            try:
                self.metadata["operations"] = self.metadata.get("operations", 0) + 1
                
                if operation == "add":
                    self.metadata["key_count"] = self.metadata.get("key_count", 0) + 1
                elif operation == "delete":
                    self.metadata["key_count"] = max(0, self.metadata.get("key_count", 0) - 1)
                
                self._save_metadata()
                self.logger.debug(f"更新元数据: {operation} {key}")
                
            except Exception as e:
                self.logger.error(f"更新元数据失败: {str(e)}")
    
    # ==================== 基础CRUD操作 ====================
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        存储键值对
        
        Args:
            key: 键名
            value: 值（可以是任何JSON可序列化的对象）
            ttl: 过期时间（秒），None表示永不过期
        """
        with self.lock:
            try:
                self.logger.info(f"存储键值对: {key} (ttl: {ttl})")
                file_path = self._get_file_path(key)
                
                # 准备数据
                data = {
                    "value": value,
                    "created": datetime.now().isoformat(),
                    "modified": datetime.now().isoformat(),
                }
                
                if ttl:
                    data["expires"] = time.time() + ttl
                
                # 如果在事务中，记录操作
                if self.in_transaction:
                    # 检查键是否存在以记录旧值
                    old_data = None
                    try:
                        old_data = self._read_json(file_path)
                    except:
                        pass
                    self.transaction_log.append(("put", key, old_data, data.copy()))
                    self.logger.debug(f"事务记录PUT操作: {key}")
                
                # 写入文件
                self._write_json(file_path, data)
                
                # 更新缓存
                self.cache.set(key, data)
                
                # 更新索引（如果值是字典）
                if isinstance(value, dict):
                    for index_name in self.indices.indices:
                        self.indices.add_to_index(index_name, key, value)
                
                # 更新元数据
                self._update_metadata("add", key)
                
                self.logger.info(f"存储成功: {key}")
                
            except Exception as e:
                self.logger.error(f"存储键值对失败: {key} - {str(e)}")
                raise
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取键对应的值
        
        Args:
            key: 键名
            default: 如果键不存在返回的默认值
        
        Returns:
            键对应的值，如果键不存在返回default
        """
        with self.lock:
            try:
                self.logger.debug(f"获取键: {key}")
                
                # 检查缓存
                cached = self.cache.get(key)
                if cached:
                    # 检查是否过期
                    if "expires" in cached and cached["expires"] < time.time():
                        self.logger.debug(f"键已过期: {key}")
                        self.delete(key)
                        return default
                    return cached["value"]
                
                # 从文件读取
                try:
                    file_path = self._get_file_path(key)
                    data = self._read_json(file_path)
                    
                    # 检查是否过期
                    if "expires" in data and data["expires"] < time.time():
                        self.logger.debug(f"键已过期: {key}")
                        self.delete(key)
                        return default
                    
                    # 更新缓存
                    self.cache.set(key, data)
                    
                    self.logger.debug(f"获取成功: {key}")
                    return data["value"]
                    
                except KeyNotFoundError:
                    self.logger.debug(f"键不存在: {key}")
                    return default
                    
            except Exception as e:
                self.logger.error(f"获取键值失败: {key} - {str(e)}")
                return default
    
    def delete(self, key: str) -> bool:
        """
        删除键值对
        
        Args:
            key: 键名
        
        Returns:
            是否成功删除
        """
        with self.lock:
            try:
                self.logger.info(f"删除键: {key}")
                file_path = self._get_file_path(key)
                
                # 如果在事务中，记录操作
                if self.in_transaction:
                    # 先读取当前值
                    try:
                        current_data = self._read_json(file_path)
                        self.transaction_log.append(("delete", key, current_data, None))
                        self.logger.debug(f"事务记录DELETE操作: {key}")
                    except:
                        pass
                
                # 删除文件
                try:
                    # 先获取值以更新索引
                    try:
                        data = self._read_json(file_path)
                        if isinstance(data.get("value"), dict):
                            for index_name in self.indices.indices:
                                self.indices.remove_from_index(index_name, key, data["value"])
                    except:
                        pass
                    
                    os.remove(file_path)
                    
                    # 清除缓存
                    self.cache.delete(key)
                    
                    # 更新元数据
                    self._update_metadata("delete", key)
                    
                    self.logger.info(f"删除成功: {key}")
                    return True
                    
                except FileNotFoundError:
                    self.logger.warning(f"删除失败，键不存在: {key}")
                    return False
                    
            except Exception as e:
                self.logger.error(f"删除键值失败: {key} - {str(e)}")
                return False
    
    def exists(self, key: str) -> bool:
        """检查键是否存在"""
        with self.lock:
            try:
                file_path = self._get_file_path(key)
                exists = os.path.exists(file_path)
                self.logger.debug(f"检查键是否存在: {key} = {exists}")
                return exists
            except Exception as e:
                self.logger.error(f"检查键是否存在失败: {key} - {str(e)}")
                return False
    
    def keys(self, pattern: Optional[str] = None) -> List[str]:
        """
        获取所有键
        
        Args:
            pattern: 键名模式（支持*通配符）
        
        Returns:
            键名列表
        """
        with self.lock:
            try:
                db_path = self.get_current_db_path()
                keys = []
                
                for file_name in os.listdir(db_path):
                    if file_name.endswith('.json') and not file_name.startswith('__'):
                        key = file_name[:-5]
                        
                        # 模式匹配
                        if pattern:
                            if '*' in pattern:
                                # 简单通配符匹配
                                import re
                                pattern_regex = pattern.replace('*', '.*')
                                if re.match(pattern_regex, key):
                                    keys.append(key)
                            elif pattern in key:
                                keys.append(key)
                        else:
                            keys.append(key)
                
                self.logger.debug(f"获取键列表，模式: {pattern}, 数量: {len(keys)}")
                return keys
                
            except Exception as e:
                self.logger.error(f"获取键列表失败: {str(e)}")
                return []
    
    # ==================== 多数据库管理 ====================
    def create_database(self, name: str) -> int:
        """
        创建新数据库
        
        Args:
            name: 数据库名称
        
        Returns:
            数据库索引
        """
        with self.lock:
            try:
                self.logger.info(f"创建数据库: {name}")
                
                if name in self.databases:
                    raise DatabaseError(f"数据库 '{name}' 已存在")
                
                self.databases.append(name)
                self._ensure_db_exists(name)
                
                index = self.databases.index(name)
                self.logger.info(f"数据库创建成功: {name} (索引: {index})")
                return index
                
            except Exception as e:
                self.logger.error(f"创建数据库失败: {name} - {str(e)}")
                raise
    
    def use_database(self, identifier: Union[str, int]) -> None:
        """
        切换当前使用的数据库
        
        Args:
            identifier: 数据库名称或索引
        """
        with self.lock:
            try:
                old_db = self.databases[self.current_db_index] if self.databases else None
                
                if isinstance(identifier, int):
                    if 0 <= identifier < len(self.databases):
                        self.current_db_index = identifier
                    else:
                        raise DatabaseError(f"数据库索引 {identifier} 无效")
                else:
                    if identifier in self.databases:
                        self.current_db_index = self.databases.index(identifier)
                    else:
                        raise DatabaseNotFoundError(f"数据库 '{identifier}' 不存在")
                
                # 重新加载元数据和索引
                self._load_metadata()
                self.indices = IndexManager(self.get_current_db_path())
                
                # 清空缓存
                self.cache.clear()
                
                new_db = self.databases[self.current_db_index]
                self.logger.info(f"切换数据库: {old_db} -> {new_db}")
                
            except Exception as e:
                self.logger.error(f"切换数据库失败: {identifier} - {str(e)}")
                raise
    
    def list_databases(self) -> List[str]:
        """列出所有数据库"""
        with self.lock:
            try:
                dbs = self.databases.copy()
                self.logger.debug(f"列出数据库，数量: {len(dbs)}")
                return dbs
            except Exception as e:
                self.logger.error(f"列出数据库失败: {str(e)}")
                return []
    
    def drop_database(self, name: str) -> bool:
        """
        删除数据库
        
        Args:
            name: 数据库名称
        
        Returns:
            是否成功删除
        """
        with self.lock:
            try:
                self.logger.info(f"删除数据库: {name}")
                
                if name not in self.databases:
                    self.logger.warning(f"数据库不存在: {name}")
                    return False
                
                # 不能删除当前数据库
                if self.databases[self.current_db_index] == name:
                    raise DatabaseError("不能删除当前正在使用的数据库")
                
                # 删除目录
                db_path = os.path.join(self.base_dir, name)
                if os.path.exists(db_path):
                    shutil.rmtree(db_path)
                    self.logger.debug(f"删除数据库目录: {db_path}")
                
                # 从列表中移除
                self.databases.remove(name)
                
                # 如果删除的是当前数据库之前的数据库，调整索引
                db_index = self.databases.index(name) if name in self.databases else -1
                if db_index >= 0 and db_index < self.current_db_index:
                    self.current_db_index -= 1
                
                self.logger.info(f"数据库删除成功: {name}")
                return True
                
            except Exception as e:
                self.logger.error(f"删除数据库失败: {name} - {str(e)}")
                return False
    
    # ==================== 事务处理 ====================
    def begin_transaction(self) -> None:
        """开始事务"""
        with self.lock:
            try:
                if self.in_transaction:
                    raise TransactionError("事务已在进行中")
                
                self.in_transaction = True
                self.transaction_log = []
                self.logger.info("开始事务")
                
            except Exception as e:
                self.logger.error(f"开始事务失败: {str(e)}")
                raise
    
    def commit(self) -> None:
        """提交事务"""
        with self.lock:
            try:
                if not self.in_transaction:
                    raise TransactionError("没有活动的事务")
                
                # 事务提交时不执行特殊操作，因为操作已经实时执行
                # 这里主要是为了与事务API兼容
                
                self.in_transaction = False
                self.transaction_log = []
                self.logger.info("提交事务")
                
            except Exception as e:
                self.logger.error(f"提交事务失败: {str(e)}")
                raise
    
    def rollback(self) -> None:
        """回滚事务"""
        with self.lock:
            try:
                if not self.in_transaction:
                    raise TransactionError("没有活动的事务")
                
                self.logger.info("回滚事务")
                
                # 反向执行事务日志
                rollback_count = 0
                for operation in reversed(self.transaction_log):
                    op_type, key, old_data, new_data = operation
                    
                    if op_type == "put":
                        # 恢复之前的状态
                        file_path = self._get_file_path(key)
                        if old_data is not None:
                            # 如果之前有数据，恢复它
                            self._write_json(file_path, old_data)
                            self.cache.set(key, old_data)
                            rollback_count += 1
                        else:
                            # 如果之前没有数据，删除文件
                            try:
                                os.remove(file_path)
                                self.cache.delete(key)
                                rollback_count += 1
                            except:
                                pass
                    elif op_type == "delete":
                        # 恢复删除的数据
                        if old_data is not None:
                            file_path = self._get_file_path(key)
                            self._write_json(file_path, old_data)
                            self.cache.set(key, old_data)
                            rollback_count += 1
                
                self.in_transaction = False
                self.transaction_log = []
                
                self.logger.info(f"事务回滚完成，恢复了 {rollback_count} 个操作")
                
            except Exception as e:
                self.logger.error(f"回滚事务失败: {str(e)}")
                raise
    
    # ==================== 批量操作 ====================
    def batch_put(self, items: List[Tuple[str, Any]]) -> None:
        """
        批量存储键值对
        
        Args:
            items: [(key1, value1), (key2, value2), ...]
        """
        with self.lock:
            try:
                self.logger.info(f"批量存储 {len(items)} 个键值对")
                
                for key, value in items:
                    self.put(key, value)
                
                self.logger.info(f"批量存储完成")
                
            except Exception as e:
                self.logger.error(f"批量存储失败: {str(e)}")
                raise
    
    def batch_delete(self, keys: List[str]) -> int:
        """
        批量删除键值对
        
        Args:
            keys: 要删除的键列表
        
        Returns:
            成功删除的数量
        """
        with self.lock:
            try:
                self.logger.info(f"批量删除 {len(keys)} 个键")
                
                count = 0
                for key in keys:
                    if self.delete(key):
                        count += 1
                
                self.logger.info(f"批量删除完成，成功删除 {count} 个键")
                return count
                
            except Exception as e:
                self.logger.error(f"批量删除失败: {str(e)}")
                return 0
    
    # ==================== 查询和搜索 ====================
    def search(self, value_pattern: str, case_sensitive: bool = False) -> List[Tuple[str, Any]]:
        """
        搜索包含特定值的数据
        
        Args:
            value_pattern: 要搜索的值模式
            case_sensitive: 是否区分大小写
        
        Returns:
            [(key1, value1), (key2, value2), ...]
        """
        with self.lock:
            try:
                self.logger.info(f"搜索: {value_pattern} (区分大小写: {case_sensitive})")
                
                results = []
                
                if not case_sensitive:
                    value_pattern = value_pattern.lower()
                
                for key in self.keys():
                    value = self.get(key)
                    if value is None:
                        continue
                    
                    value_str = str(value)
                    if not case_sensitive:
                        value_str = value_str.lower()
                    
                    if value_pattern in value_str:
                        results.append((key, value))
                
                self.logger.info(f"搜索完成，找到 {len(results)} 个结果")
                return results
                
            except Exception as e:
                self.logger.error(f"搜索失败: {str(e)}")
                return []
    
    def filter(self, predicate) -> List[Tuple[str, Any]]:
        """
        使用谓词函数过滤数据
        
        Args:
            predicate: 函数，接受(key, value)返回bool
        
        Returns:
            [(key1, value1), (key2, value2), ...]
        """
        with self.lock:
            try:
                self.logger.info(f"使用谓词过滤数据")
                
                results = []
                
                for key in self.keys():
                    value = self.get(key)
                    if value is not None and predicate(key, value):
                        results.append((key, value))
                
                self.logger.info(f"过滤完成，找到 {len(results)} 个结果")
                return results
                
            except Exception as e:
                self.logger.error(f"过滤数据失败: {str(e)}")
                return []
    
    # ==================== 索引功能 ====================
    def create_index(self, index_name: str, field: str) -> None:
        """
        创建索引
        
        Args:
            index_name: 索引名称
            field: 要索引的字段名
        """
        with self.lock:
            self.indices.create_index(index_name, field)
    
    def search_by_index(self, index_name: str, value: Any) -> List[str]:
        """
        通过索引搜索
        
        Args:
            index_name: 索引名称
            value: 要搜索的值
        
        Returns:
            匹配的键列表
        """
        with self.lock:
            return self.indices.search_by_index(index_name, value)
    
    # ==================== 统计功能 ====================
    def stats(self) -> Dict:
        """
        获取数据库统计信息
        
        Returns:
            统计信息字典
        """
        with self.lock:
            try:
                db_path = self.get_current_db_path()
                files = [f for f in os.listdir(db_path) if f.endswith('.json') and not f.startswith('__')]
                
                total_size = 0
                for file in files:
                    file_path = os.path.join(db_path, file)
                    total_size += os.path.getsize(file_path)
                
                cache_stats = self.cache.stats()
                
                stats = {
                    'database_name': self.databases[self.current_db_index],
                    'database_count': len(self.databases),
                    'key_count': len(files),
                    'total_size': total_size,
                    'total_size_human': self._human_size(total_size),
                    'cache_size': cache_stats['size'],
                    'cache_capacity': cache_stats['capacity'],
                    'cache_hits': cache_stats['hits'],
                    'cache_misses': cache_stats['misses'],
                    'cache_hit_rate': f"{cache_stats['hit_rate']:.2%}",
                    'last_modified': self.metadata.get("modified", "未知"),
                    'created': self.metadata.get("created", "未知"),
                    'operations': self.metadata.get("operations", 0)
                }
                
                self.logger.info(f"获取统计信息: {stats}")
                return stats
                
            except Exception as e:
                self.logger.error(f"获取统计信息失败: {str(e)}")
                return {}
    
    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """转换字节数为人类可读格式"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    # ==================== 备份和恢复 ====================
    def backup(self, backup_name: Optional[str] = None) -> str:
        """
        备份数据库
        
        Args:
            backup_name: 备份名称，None则使用时间戳
        
        Returns:
            备份文件路径
        """
        with self.lock:
            try:
                self.logger.info(f"备份数据库: {self.databases[self.current_db_index]}")
                
                if backup_name is None:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_name = f"backup_{self.databases[self.current_db_index]}_{timestamp}"
                
                # 确保备份目录存在
                backup_dir = os.path.join(self.base_dir, self.config.backup_dir)
                os.makedirs(backup_dir, exist_ok=True)
                
                backup_path = os.path.join(backup_dir, f"{backup_name}.zip")
                db_path = self.get_current_db_path()
                
                # 创建ZIP备份
                with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(db_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, self.base_dir)
                            zipf.write(file_path, arcname)
                
                self.logger.info(f"备份完成: {backup_path}")
                return backup_path
                
            except Exception as e:
                self.logger.error(f"备份失败: {str(e)}")
                raise
    
    def restore(self, backup_file: str, overwrite: bool = False) -> None:
        """
        从备份恢复数据库
        
        Args:
            backup_file: 备份文件路径
            overwrite: 是否覆盖现有数据库
        """
        with self.lock:
            try:
                self.logger.info(f"从备份恢复: {backup_file} (覆盖: {overwrite})")
                
                if not os.path.exists(backup_file):
                    raise DatabaseError(f"备份文件不存在: {backup_file}")
                
                db_path = self.get_current_db_path()
                
                # 如果不覆盖，确保数据库为空
                if not overwrite and os.listdir(db_path):
                    raise DatabaseError("数据库不为空，请设置overwrite=True或清空数据库")
                
                # 解压备份
                with zipfile.ZipFile(backup_file, 'r') as zipf:
                    # 首先提取到临时目录
                    temp_dir = os.path.join(self.base_dir, "temp_restore")
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)
                    
                    zipf.extractall(temp_dir)
                    
                    # 然后复制到目标目录
                    for item in os.listdir(temp_dir):
                        src = os.path.join(temp_dir, item)
                        dst = os.path.join(db_path, item)
                        
                        if os.path.isdir(src):
                            if os.path.exists(dst):
                                shutil.rmtree(dst)
                            shutil.copytree(src, dst)
                        else:
                            if os.path.exists(dst):
                                os.remove(dst)
                            shutil.copy2(src, dst)
                    
                    # 清理临时目录
                    shutil.rmtree(temp_dir)
                
                # 重新加载元数据和索引
                self._load_metadata()
                self.indices = IndexManager(db_path)
                
                # 清空缓存
                self.cache.clear()
                
                self.logger.info(f"恢复完成")
                
            except Exception as e:
                self.logger.error(f"恢复失败: {str(e)}")
                raise
    
    # ==================== 导入导出 ====================
    def export_to_csv(self, csv_path: str) -> int:
        """
        导出为CSV文件
        
        Args:
            csv_path: CSV文件路径
        
        Returns:
            导出的记录数
        """
        with self.lock:
            try:
                self.logger.info(f"导出为CSV: {csv_path}")
                
                count = 0
                
                with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Key', 'Value', 'Created', 'Modified', 'Expires'])
                    
                    for key in self.keys():
                        try:
                            data = self._read_json(self._get_file_path(key))
                            
                            # 将值转换为字符串
                            value_str = json.dumps(data.get('value', ''))
                            
                            writer.writerow([
                                key,
                                value_str,
                                data.get('created', ''),
                                data.get('modified', ''),
                                data.get('expires', '')
                            ])
                            
                            count += 1
                        except Exception as e:
                            self.logger.warning(f"导出键 {key} 失败: {str(e)}")
                            continue
                
                self.logger.info(f"CSV导出完成，导出了 {count} 条记录")
                return count
                
            except Exception as e:
                self.logger.error(f"CSV导出失败: {str(e)}")
                raise
    
    def import_from_csv(self, csv_path: str, clear_existing: bool = False) -> int:
        """
        从CSV文件导入
        
        Args:
            csv_path: CSV文件路径
            clear_existing: 是否清空现有数据
        
        Returns:
            导入的记录数
        """
        with self.lock:
            try:
                self.logger.info(f"从CSV导入: {csv_path} (清空现有: {clear_existing})")
                
                if clear_existing:
                    self.clear()
                
                count = 0
                
                with open(csv_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    
                    for row in reader:
                        key = row['Key']
                        
                        try:
                            value = json.loads(row['Value'])
                        except:
                            value = row['Value']
                        
                        self.put(key, value)
                        count += 1
                
                self.logger.info(f"CSV导入完成，导入了 {count} 条记录")
                return count
                
            except Exception as e:
                self.logger.error(f"CSV导入失败: {str(e)}")
                raise
    
    def export_to_json(self, json_path: str) -> int:
        """
        导出为JSON文件
        
        Args:
            json_path: JSON文件路径
        
        Returns:
            导出的记录数
        """
        with self.lock:
            try:
                self.logger.info(f"导出为JSON: {json_path}")
                
                data = {}
                
                for key in self.keys():
                    try:
                        value = self.get(key)
                        if value is not None:
                            data[key] = value
                    except Exception as e:
                        self.logger.warning(f"导出键 {key} 失败: {str(e)}")
                        continue
                
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                self.logger.info(f"JSON导出完成，导出了 {len(data)} 条记录")
                return len(data)
                
            except Exception as e:
                self.logger.error(f"JSON导出失败: {str(e)}")
                raise
    
    def import_from_json(self, json_path: str, clear_existing: bool = False) -> int:
        """
        从JSON文件导入
        
        Args:
            json_path: JSON文件路径
            clear_existing: 是否清空现有数据
        
        Returns:
            导入的记录数
        """
        with self.lock:
            try:
                self.logger.info(f"从JSON导入: {json_path} (清空现有: {clear_existing})")
                
                if clear_existing:
                    self.clear()
                
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                count = 0
                for key, value in data.items():
                    self.put(key, value)
                    count += 1
                
                self.logger.info(f"JSON导入完成，导入了 {count} 条记录")
                return count
                
            except Exception as e:
                self.logger.error(f"JSON导入失败: {str(e)}")
                raise
    
    # ==================== 维护功能 ====================
    def clear(self) -> int:
        """
        清空当前数据库
        
        Returns:
            删除的记录数
        """
        with self.lock:
            try:
                self.logger.warning("清空数据库")
                
                count = 0
                keys_to_delete = self.keys()
                
                for key in keys_to_delete:
                    if self.delete(key):
                        count += 1
                
                # 清空缓存
                self.cache.clear()
                
                # 重置元数据
                self.metadata = {
                    "created": datetime.now().isoformat(),
                    "modified": datetime.now().isoformat(),
                    "key_count": 0,
                    "total_size": 0,
                    "operations": 0
                }
                self._save_metadata()
                
                # 重新加载索引
                self.indices = IndexManager(self.get_current_db_path())
                
                self.logger.warning(f"数据库已清空，删除了 {count} 条记录")
                return count
                
            except Exception as e:
                self.logger.error(f"清空数据库失败: {str(e)}")
                return 0
    
    def compact(self) -> None:
        """压缩数据库（删除过期数据）"""
        with self.lock:
            try:
                self.logger.info("压缩数据库（删除过期数据）")
                
                expired_keys = []
                
                for key in self.keys():
                    try:
                        data = self._read_json(self._get_file_path(key))
                        if "expires" in data and data["expires"] < time.time():
                            expired_keys.append(key)
                    except Exception as e:
                        self.logger.warning(f"检查键 {key} 过期状态失败: {str(e)}")
                        continue
                
                if expired_keys:
                    deleted = self.batch_delete(expired_keys)
                    self.logger.info(f"压缩完成，删除了 {deleted} 个过期键")
                else:
                    self.logger.info("压缩完成，没有过期键")
                    
            except Exception as e:
                self.logger.error(f"压缩数据库失败: {str(e)}")
    
    def _start_cleanup_thread(self) -> None:
        """启动自动清理线程"""
        def cleanup_worker():
            while True:
                time.sleep(self.config.cleanup_interval)
                try:
                    self.compact()
                except Exception as e:
                    self.logger.error(f"自动清理失败: {str(e)}")
        
        thread = threading.Thread(target=cleanup_worker, daemon=True, name="DB-Cleanup-Thread")
        thread.start()
        self.logger.info(f"启动自动清理线程，间隔: {self.config.cleanup_interval}秒")
    
    # ==================== 魔法方法 ====================
    def __getitem__(self, key: str) -> Any:
        """支持字典式访问: db['key']"""
        value = self.get(key)
        if value is None:
            raise KeyNotFoundError(f"键 '{key}' 不存在", key)
        return value
    
    def __setitem__(self, key: str, value: Any) -> None:
        """支持字典式赋值: db['key'] = value"""
        self.put(key, value)
    
    def __delitem__(self, key: str) -> None:
        """支持字典式删除: del db['key']"""
        if not self.delete(key):
            raise KeyNotFoundError(f"键 '{key}' 不存在", key)
    
    def __contains__(self, key: str) -> bool:
        """支持in操作符: 'key' in db"""
        return self.exists(key)
    
    def __len__(self) -> int:
        """支持len()函数: len(db)"""
        return len(self.keys())
    
    def __iter__(self):
        """支持迭代: for key in db"""
        return iter(self.keys())
    
    def __enter__(self):
        """支持上下文管理器"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器"""
        # 确保事务已提交或回滚
        if self.in_transaction:
            if exc_type is not None:
                self.logger.warning(f"上下文管理器退出时发生异常，回滚事务: {exc_val}")
                self.rollback()
            else:
                self.commit()
        return False  # 不捕获异常
    
    # ==================== 高级功能 ====================
    def put_with_expiry(self, key: str, value: Any, ttl: int) -> None:
        """存储带过期时间的键值对（put的别名）"""
        self.put(key, value, ttl)
    
    def get_with_ttl(self, key: str) -> Tuple[Any, Optional[float]]:
        """
        获取值及其剩余生存时间
        
        Returns:
            (value, ttl_seconds) - ttl为None表示永不过期
        """
        with self.lock:
            try:
                file_path = self._get_file_path(key)
                
                data = self._read_json(file_path)
                
                if "expires" in data:
                    ttl = data["expires"] - time.time()
                    if ttl <= 0:
                        self.delete(key)
                        raise KeyNotFoundError(f"键 '{key}' 已过期", key)
                    return data["value"], ttl
                else:
                    return data["value"], None
                    
            except KeyNotFoundError:
                raise
            except Exception as e:
                self.logger.error(f"获取带TTL的值失败: {key} - {str(e)}")
                raise
    
    def increment(self, key: str, amount: int = 1) -> int:
        """
        对整数值进行递增
        
        Args:
            key: 键名
            amount: 递增幅度
        
        Returns:
            递增后的值
        """
        with self.lock:
            try:
                self.logger.debug(f"递增键: {key} (+{amount})")
                
                current = self.get(key, 0)
                
                if not isinstance(current, (int, float)):
                    raise DatabaseError(f"键 '{key}' 的值不是数字")
                
                new_value = current + amount
                self.put(key, new_value)
                
                self.logger.debug(f"递增完成: {key} = {new_value}")
                return new_value
                
            except Exception as e:
                self.logger.error(f"递增失败: {key} - {str(e)}")
                raise
    
    def decrement(self, key: str, amount: int = 1) -> int:
        """对整数值进行递减"""
        return self.increment(key, -amount)


# ==================== 高级数据库类（扩展功能） ====================
class AdvancedFileDatabase(FileDatabase):
    """高级数据库类，添加历史记录功能"""
    
    def __init__(self, db_name: str, config: Optional[DatabaseConfig] = None, max_history: int = 10):
        super().__init__(db_name, config)
        self.max_history = max_history
        self.history = {}  # 用于存储键的历史记录
        self.history_file = os.path.join(self.get_current_db_path(), "__history.json")
        self._load_history()
        self.logger = logging.getLogger(__name__ + ".AdvancedFileDatabase")
        self.logger.info(f"高级数据库初始化完成，最大历史记录: {max_history}")
    
    def _load_history(self) -> None:
        """加载历史记录"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.history = json.load(f)
                self.logger.debug(f"从 {self.history_file} 加载了历史记录")
            else:
                self.history = {}
        except Exception as e:
            self.logger.error(f"加载历史记录失败: {str(e)}")
            self.history = {}
    
    def _save_history(self) -> None:
        """保存历史记录"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
            self.logger.debug("保存历史记录")
        except Exception as e:
            self.logger.error(f"保存历史记录失败: {str(e)}")
    
    def put_with_history(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        存储键值对并保存历史记录
        
        Args:
            key: 键名
            value: 值
            ttl: 过期时间
        """
        with self.lock:
            try:
                self.logger.debug(f"带历史记录存储: {key}")
                
                # 保存当前值到历史记录
                current = self.get(key)
                if current is not None:
                    if key not in self.history:
                        self.history[key] = []
                    
                    self.history[key].append({
                        "value": current,
                        "timestamp": datetime.now().isoformat(),
                        "operation": "update"
                    })
                    
                    # 限制历史记录长度
                    if len(self.history[key]) > self.max_history:
                        self.history[key] = self.history[key][-self.max_history:]
                    
                    self._save_history()
                
                # 调用父类的put方法
                super().put(key, value, ttl)
                
                self.logger.debug(f"带历史记录存储完成: {key}")
                
            except Exception as e:
                self.logger.error(f"带历史记录存储失败: {key} - {str(e)}")
                raise
    
    def get_history(self, key: str) -> List[Dict]:
        """
        获取键的历史记录
        
        Args:
            key: 键名
        
        Returns:
            历史记录列表
        """
        with self.lock:
            try:
                history = self.history.get(key, [])
                self.logger.debug(f"获取历史记录: {key}，数量: {len(history)}")
                return history.copy()
            except Exception as e:
                self.logger.error(f"获取历史记录失败: {key} - {str(e)}")
                return []
    
    def restore_from_history(self, key: str, history_index: int = -1) -> bool:
        """
        从历史记录恢复值
        
        Args:
            key: 键名
            history_index: 历史记录索引（-1表示上一个）
        
        Returns:
            是否成功恢复
        """
        with self.lock:
            try:
                self.logger.info(f"从历史记录恢复: {key}，索引: {history_index}")
                
                if key not in self.history or not self.history[key]:
                    self.logger.warning(f"键 {key} 没有历史记录")
                    return False
                
                if history_index < 0:
                    history_index = len(self.history[key]) + history_index
                
                if 0 <= history_index < len(self.history[key]):
                    old_value = self.history[key][history_index]["value"]
                    
                    # 保存当前值到历史记录
                    current = self.get(key)
                    if current is not None:
                        self.history[key].append({
                            "value": current,
                            "timestamp": datetime.now().isoformat(),
                            "operation": "restore_from_history"
                        })
                        
                        # 限制历史记录长度
                        if len(self.history[key]) > self.max_history:
                            self.history[key] = self.history[key][-self.max_history:]
                        
                        self._save_history()
                    
                    # 调用父类的put方法（不是put_with_history，避免重复记录历史）
                    super().put(key, old_value)
                    
                    self.logger.info(f"从历史记录恢复成功: {key}，索引: {history_index}")
                    return True
                else:
                    self.logger.warning(f"历史记录索引无效: {history_index}")
                    return False
                    
            except Exception as e:
                self.logger.error(f"从历史记录恢复失败: {key} - {str(e)}")
                return False
    
    def clear_history(self, key: Optional[str] = None) -> int:
        """
        清除历史记录
        
        Args:
            key: 键名，如果为None则清除所有历史记录
        
        Returns:
            清除的历史记录数量
        """
        with self.lock:
            try:
                if key is None:
                    count = sum(len(history) for history in self.history.values())
                    self.history.clear()
                    self._save_history()
                    self.logger.info(f"清除所有历史记录，数量: {count}")
                    return count
                elif key in self.history:
                    count = len(self.history[key])
                    del self.history[key]
                    self._save_history()
                    self.logger.info(f"清除键 {key} 的历史记录，数量: {count}")
                    return count
                else:
                    self.logger.warning(f"键 {key} 没有历史记录")
                    return 0
            except Exception as e:
                self.logger.error(f"清除历史记录失败: {key} - {str(e)}")
                return 0


# ==================== 使用示例 ====================
def example_basic():
    """基本使用示例"""
    print("=== 基本示例 ===")
    
    # 1. 创建数据库
    db = FileDatabase("MyDatabase")
    
    # 2. 基本CRUD操作
    db.put("user:1", {"name": "Alice", "age": 30})
    db.put("user:2", {"name": "Bob", "age": 25}, ttl=3600)  # 1小时后过期
    
    print("user:1:", db.get("user:1"))
    print("Exists user:2:", db.exists("user:2"))
    
    # 3. 字典式访问
    db["config:app"] = {"version": "1.0", "theme": "dark"}
    print("config:app:", db["config:app"])
    
    # 4. 批量操作
    items = [
        ("product:1", {"name": "Laptop", "price": 999}),
        ("product:2", {"name": "Phone", "price": 599}),
    ]
    db.batch_put(items)
    
    # 5. 搜索
    results = db.search("Laptop")
    print("Search results:", results)
    
    # 6. 创建索引
    try:
        db.create_index("name_index", "name")
        matches = db.search_by_index("name_index", "Phone")
        print("Index search:", matches)
    except DatabaseError as e:
        logging.error(f"索引操作失败: {e}")
        print(f"Index operation failed: {e}")
    
    # 7. 事务处理
    try:
        db.begin_transaction()
        db.put("temp:1", "value1")
        db.put("temp:2", "value2")
        db.commit()
        print("Transaction committed")
    except Exception as e:
        db.rollback()
        print(f"Transaction failed: {e}")
    
    # 8. 统计信息
    stats = db.stats()
    print("Database stats:", stats)
    
    # 9. 备份
    backup_path = db.backup()
    print(f"Backup created: {backup_path}")
    
    # 10. 导出为JSON
    db.export_to_json("export.json")
    print("Exported to JSON")
    
    # 清理
    db.delete("user:1")
    db.delete("user:2")
    print("Cleaned up")


def example_advanced():
    """高级功能示例"""
    print("\n=== 高级示例 ===")
    
    # 使用高级数据库
    config = DatabaseConfig(
        encryption_key="my_secret_key",
        auto_backup=True,
        cache_size=500,
        log_level="INFO"
    )
    
    db = AdvancedFileDatabase("SecureDatabase", config, max_history=5)
    
    # 带历史记录的存储
    db.put_with_history("document:1", "Version 1")
    db.put_with_history("document:1", "Version 2")
    db.put_with_history("document:1", "Version 3")
    
    # 获取历史记录
    history = db.get_history("document:1")
    print(f"Document history length: {len(history)}")
    
    # 恢复旧版本
    success = db.restore_from_history("document:1", 0)  # 恢复到版本1
    print(f"Restore successful: {success}")
    print(f"Restored to: {db.get('document:1')}")
    
    # 使用带TTL的获取
    try:
        value, ttl = db.get_with_ttl("document:1")
        print(f"Value: {value}, TTL: {ttl}")
    except Exception as e:
        print(f"Get with TTL error: {e}")
    
    # 递增操作
    db.put("counter", 0)
    for _ in range(5):
        db.increment("counter")
    print("Counter:", db.get("counter"))


def example_with_logging():
    """带详细日志的示例"""
    print("\n=== 带日志的示例 ===")
    
    # 配置数据库
    config = DatabaseConfig(
        log_level="DEBUG",
        log_file="database.log",
        cache_size=100,
        auto_backup=False
    )
    
    # 创建数据库
    db = FileDatabase("TestDB", config)
    
    # 执行一些操作
    db.put("test:1", "Hello")
    db.put("test:2", {"nested": "data"})
    db.put("test:3", [1, 2, 3], ttl=10)  # 10秒后过期
    
    print(f"test:1 = {db.get('test:1')}")
    print(f"test:2 = {db.get('test:2')}")
    print(f"Keys: {list(db.keys())}")
    
    # 查看统计
    stats = db.stats()
    print(f"Stats: {stats}")
    
    # 清理
    db.clear()
    print("Database cleared")


if __name__ == "__main__":
    try:
        # 运行示例
        example_basic()
        #example_advanced()
        #example_with_logging()
        
        print("\n所有示例运行完成！")
        print("查看 database.log 文件获取详细日志")
        
    except Exception as e:
        print(f"运行示例时出错: {e}")
        import traceback
        traceback.print_exc()