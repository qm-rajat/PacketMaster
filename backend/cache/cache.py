"""
Simple Caching System - Result caching and memoization
"""
import json
import hashlib
import os
from typing import Any, Optional, Callable
from datetime import datetime, timedelta

CACHE_DIR = '.cache'


class ResultCache:
    """Simple file-based cache for analysis results"""
    
    def __init__(self, ttl_hours: int = 24):
        self.ttl = timedelta(hours=ttl_hours)
        os.makedirs(CACHE_DIR, exist_ok=True)
    
    def _get_cache_key(self, file_path: str) -> str:
        """Generate cache key from file path and modification time"""
        if not os.path.exists(file_path):
            return None
        
        stat = os.stat(file_path)
        file_info = f"{file_path}_{stat.st_size}_{stat.st_mtime}"
        return hashlib.md5(file_info.encode()).hexdigest()
    
    def _get_cache_file(self, cache_key: str) -> str:
        """Get cache file path"""
        return os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    def get(self, file_path: str) -> Optional[dict]:
        """Get cached results if available and not expired"""
        cache_key = self._get_cache_key(file_path)
        if not cache_key:
            return None
        
        cache_file = self._get_cache_file(cache_key)
        if not os.path.exists(cache_file):
            return None
        
        # Check if cache is expired
        mod_time = os.path.getmtime(cache_file)
        if datetime.now() - datetime.fromtimestamp(mod_time) > self.ttl:
            os.remove(cache_file)
            return None
        
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except:
            return None
    
    def set(self, file_path: str, data: dict) -> bool:
        """Cache results"""
        cache_key = self._get_cache_key(file_path)
        if not cache_key:
            return False
        
        cache_file = self._get_cache_file(cache_key)
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            return True
        except:
            return False
    
    def clear(self):
        """Clear all cache"""
        import shutil
        if os.path.exists(CACHE_DIR):
            shutil.rmtree(CACHE_DIR)
            os.makedirs(CACHE_DIR, exist_ok=True)


class CachedFunction:
    """Decorator for caching function results"""
    
    def __init__(self, ttl_hours: int = 24):
        self.cache = ResultCache(ttl_hours)
    
    def __call__(self, func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Simple cache key from function name and args
            cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
            
            # Try to get from cache
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except:
                    pass
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Cache result
            try:
                with open(cache_file, 'w') as f:
                    json.dump(result, f, default=str)
            except:
                pass
            
            return result
        
        return wrapper


# Global cache instance
default_cache = ResultCache()
