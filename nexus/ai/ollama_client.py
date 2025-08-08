"""
Ollama Client for Nexus

Handles communication with Ollama API for AI model inference,
including model management, request handling, and response processing.
"""

import json
import time
import asyncio
import aiohttp
import requests
from typing import Dict, Any, Optional, List, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ModelInfo:
    """Information about an available model"""
    name: str
    size: int
    digest: str
    modified_at: datetime
    details: Dict[str, Any]


@dataclass
class GenerationRequest:
    """Request for text generation"""
    model: str
    prompt: str
    system: Optional[str] = None
    template: Optional[str] = None
    context: Optional[List[int]] = None
    stream: bool = False
    raw: bool = False
    format: Optional[str] = None
    keep_alive: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


@dataclass
class GenerationResponse:
    """Response from text generation"""
    model: str
    created_at: datetime
    response: str
    done: bool
    context: Optional[List[int]] = None
    total_duration: Optional[int] = None
    load_duration: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    prompt_eval_duration: Optional[int] = None
    eval_count: Optional[int] = None
    eval_duration: Optional[int] = None


class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434", timeout: int = 300):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = None
        self._models_cache: Optional[List[ModelInfo]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_ttl = 300  # 5 minutes
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_session(self) -> requests.Session:
        """Get or create requests session for sync operations"""
        if not hasattr(self, '_sync_session'):
            self._sync_session = requests.Session()
            self._sync_session.timeout = self.timeout
        return self._sync_session
    
    async def health_check(self) -> bool:
        """Check if Ollama service is healthy"""
        try:
            if not self.session:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.base_url}/api/tags") as response:
                        return response.status == 200
            else:
                async with self.session.get(f"{self.base_url}/api/tags") as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    def health_check_sync(self) -> bool:
        """Synchronous health check"""
        try:
            session = self._get_session()
            response = session.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def list_models(self, force_refresh: bool = False) -> List[ModelInfo]:
        """List available models"""
        # Check cache
        if (not force_refresh and self._models_cache and self._cache_timestamp and 
            (datetime.now() - self._cache_timestamp).seconds < self._cache_ttl):
            return self._models_cache
        
        try:
            if not self.session:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.base_url}/api/tags") as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}: {await response.text()}")
                        data = await response.json()
            else:
                async with self.session.get(f"{self.base_url}/api/tags") as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}: {await response.text()}")
                    data = await response.json()
            
            models = []
            for model_data in data.get('models', []):
                models.append(ModelInfo(
                    name=model_data['name'],
                    size=model_data['size'],
                    digest=model_data['digest'],
                    modified_at=datetime.fromisoformat(model_data['modified_at'].replace('Z', '+00:00')),
                    details=model_data.get('details', {})
                ))
            
            # Update cache
            self._models_cache = models
            self._cache_timestamp = datetime.now()
            
            return models
            
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            raise
    
    def list_models_sync(self, force_refresh: bool = False) -> List[ModelInfo]:
        """Synchronous version of list_models"""
        # Check cache
        if (not force_refresh and self._models_cache and self._cache_timestamp and 
            (datetime.now() - self._cache_timestamp).seconds < self._cache_ttl):
            return self._models_cache
        
        try:
            session = self._get_session()
            response = session.get(f"{self.base_url}/api/tags")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            models = []
            
            for model_data in data.get('models', []):
                models.append(ModelInfo(
                    name=model_data['name'],
                    size=model_data['size'],
                    digest=model_data['digest'],
                    modified_at=datetime.fromisoformat(model_data['modified_at'].replace('Z', '+00:00')),
                    details=model_data.get('details', {})
                ))
            
            # Update cache
            self._models_cache = models
            self._cache_timestamp = datetime.now()
            
            return models
            
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            raise
    
    async def pull_model(self, model_name: str) -> AsyncGenerator[Dict[str, Any], None]:
        """Pull a model from the registry"""
        payload = {"name": model_name}
        
        try:
            if not self.session:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/api/pull",
                        json=payload
                    ) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}: {await response.text()}")
                        
                        async for line in response.content:
                            if line:
                                try:
                                    yield json.loads(line.decode('utf-8'))
                                except json.JSONDecodeError:
                                    continue
            else:
                async with self.session.post(
                    f"{self.base_url}/api/pull",
                    json=payload
                ) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}: {await response.text()}")
                    
                    async for line in response.content:
                        if line:
                            try:
                                yield json.loads(line.decode('utf-8'))
                            except json.JSONDecodeError:
                                continue
                                
        except Exception as e:
            logger.error(f"Failed to pull model {model_name}: {e}")
            raise
    
    async def delete_model(self, model_name: str) -> bool:
        """Delete a model"""
        payload = {"name": model_name}
        
        try:
            if not self.session:
                async with aiohttp.ClientSession() as session:
                    async with session.delete(
                        f"{self.base_url}/api/delete",
                        json=payload
                    ) as response:
                        success = response.status == 200
            else:
                async with self.session.delete(
                    f"{self.base_url}/api/delete",
                    json=payload
                ) as response:
                    success = response.status == 200
            
            if success:
                # Clear cache
                self._models_cache = None
                self._cache_timestamp = None
                logger.info(f"Model {model_name} deleted successfully")
            else:
                logger.error(f"Failed to delete model {model_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to delete model {model_name}: {e}")
            return False
    
    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        """Generate text using the specified model"""
        payload = {
            "model": request.model,
            "prompt": request.prompt,
            "stream": request.stream,
            "raw": request.raw
        }
        
        # Add optional parameters
        if request.system:
            payload["system"] = request.system
        if request.template:
            payload["template"] = request.template
        if request.context:
            payload["context"] = request.context
        if request.format:
            payload["format"] = request.format
        if request.keep_alive:
            payload["keep_alive"] = request.keep_alive
        if request.options:
            payload["options"] = request.options
        
        try:
            if not self.session:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/api/generate",
                        json=payload
                    ) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}: {await response.text()}")
                        
                        data = await response.json()
            else:
                async with self.session.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                ) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}: {await response.text()}")
                    
                    data = await response.json()
            
            return GenerationResponse(
                model=data['model'],
                created_at=datetime.fromisoformat(data['created_at'].replace('Z', '+00:00')),
                response=data['response'],
                done=data['done'],
                context=data.get('context'),
                total_duration=data.get('total_duration'),
                load_duration=data.get('load_duration'),
                prompt_eval_count=data.get('prompt_eval_count'),
                prompt_eval_duration=data.get('prompt_eval_duration'),
                eval_count=data.get('eval_count'),
                eval_duration=data.get('eval_duration')
            )
            
        except Exception as e:
            logger.error(f"Failed to generate text: {e}")
            raise
    
    def generate_sync(self, request: GenerationRequest) -> GenerationResponse:
        """Synchronous version of generate"""
        payload = {
            "model": request.model,
            "prompt": request.prompt,
            "stream": request.stream,
            "raw": request.raw
        }
        
        # Add optional parameters
        if request.system:
            payload["system"] = request.system
        if request.template:
            payload["template"] = request.template
        if request.context:
            payload["context"] = request.context
        if request.format:
            payload["format"] = request.format
        if request.keep_alive:
            payload["keep_alive"] = request.keep_alive
        if request.options:
            payload["options"] = request.options
        
        try:
            session = self._get_session()
            response = session.post(
                f"{self.base_url}/api/generate",
                json=payload
            )
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            
            return GenerationResponse(
                model=data['model'],
                created_at=datetime.fromisoformat(data['created_at'].replace('Z', '+00:00')),
                response=data['response'],
                done=data['done'],
                context=data.get('context'),
                total_duration=data.get('total_duration'),
                load_duration=data.get('load_duration'),
                prompt_eval_count=data.get('prompt_eval_count'),
                prompt_eval_duration=data.get('prompt_eval_duration'),
                eval_count=data.get('eval_count'),
                eval_duration=data.get('eval_duration')
            )
            
        except Exception as e:
            logger.error(f"Failed to generate text: {e}")
            raise
    
    async def generate_stream(self, request: GenerationRequest) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate text with streaming response"""
        request.stream = True
        payload = {
            "model": request.model,
            "prompt": request.prompt,
            "stream": True,
            "raw": request.raw
        }
        
        # Add optional parameters
        if request.system:
            payload["system"] = request.system
        if request.template:
            payload["template"] = request.template
        if request.context:
            payload["context"] = request.context
        if request.format:
            payload["format"] = request.format
        if request.keep_alive:
            payload["keep_alive"] = request.keep_alive
        if request.options:
            payload["options"] = request.options
        
        try:
            if not self.session:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/api/generate",
                        json=payload
                    ) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}: {await response.text()}")
                        
                        async for line in response.content:
                            if line:
                                try:
                                    yield json.loads(line.decode('utf-8'))
                                except json.JSONDecodeError:
                                    continue
            else:
                async with self.session.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                ) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}: {await response.text()}")
                    
                    async for line in response.content:
                        if line:
                            try:
                                yield json.loads(line.decode('utf-8'))
                            except json.JSONDecodeError:
                                continue
                                
        except Exception as e:
            logger.error(f"Failed to generate streaming text: {e}")
            raise
    
    def is_model_available(self, model_name: str) -> bool:
        """Check if a model is available locally"""
        try:
            models = self.list_models_sync()
            return any(model.name == model_name for model in models)
        except Exception:
            return False
    
    async def ensure_model_available(self, model_name: str) -> bool:
        """Ensure a model is available, pull if necessary"""
        if self.is_model_available(model_name):
            return True
        
        logger.info(f"Model {model_name} not found locally, pulling...")
        
        try:
            async for progress in self.pull_model(model_name):
                if progress.get('status') == 'success':
                    logger.info(f"Model {model_name} pulled successfully")
                    return True
                elif 'error' in progress:
                    logger.error(f"Failed to pull model: {progress['error']}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to pull model {model_name}: {e}")
            return False
    
    def close(self):
        """Close the client and cleanup resources"""
        if hasattr(self, '_sync_session'):
            self._sync_session.close()