"""
Nexus Evasion System

Comprehensive evasion capabilities for avoiding detection during penetration testing operations.
Includes traffic obfuscation, timing manipulation, payload encoding, and behavioral analysis.
"""

import random
import time
import base64
import hashlib
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta

from nexus.ai.ollama_client import OllamaClient
from nexus.core.config import NexusConfig


class EvasionTechnique(Enum):
    """Available evasion techniques"""
    TIMING_RANDOMIZATION = "timing_randomization"
    TRAFFIC_FRAGMENTATION = "traffic_fragmentation"
    PAYLOAD_ENCODING = "payload_encoding"
    USER_AGENT_ROTATION = "user_agent_rotation"
    SOURCE_IP_SPOOFING = "source_ip_spoofing"
    PROTOCOL_TUNNELING = "protocol_tunneling"
    DECOY_TRAFFIC = "decoy_traffic"
    BEHAVIORAL_MIMICRY = "behavioral_mimicry"
    ENCRYPTION_OBFUSCATION = "encryption_obfuscation"
    STEGANOGRAPHY = "steganography"


class DetectionRisk(Enum):
    """Detection risk levels"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class EvasionProfile:
    """Evasion profile configuration"""
    name: str
    description: str
    techniques: List[EvasionTechnique]
    detection_risk: DetectionRisk
    performance_impact: float  # 0.0 to 1.0
    stealth_rating: float      # 0.0 to 1.0
    complexity: str           # trivial, easy, medium, hard, expert


@dataclass
class TrafficPattern:
    """Traffic pattern for behavioral mimicry"""
    name: str
    description: str
    request_intervals: List[float]  # Seconds between requests
    burst_patterns: List[int]       # Number of requests in bursts
    idle_periods: List[float]       # Idle time between bursts
    user_agents: List[str]          # User agents to rotate
    headers: Dict[str, List[str]]   # HTTP headers to vary


class EvasionManager:
    """Main evasion management system"""
    
    def __init__(self, ollama_client: OllamaClient, config: NexusConfig):
        self.ollama_client = ollama_client
        self.config = config
        self.active_profile: Optional[EvasionProfile] = None
        self.traffic_patterns: Dict[str, TrafficPattern] = {}
        self.detection_history: List[Dict[str, Any]] = []
        
        # Initialize built-in evasion profiles
        self._initialize_profiles()
        self._initialize_traffic_patterns()
    
    def _initialize_profiles(self):
        """Initialize built-in evasion profiles"""
        self.profiles = {
            "stealth_maximum": EvasionProfile(
                name="Maximum Stealth",
                description="Highest stealth with significant performance impact",
                techniques=[
                    EvasionTechnique.TIMING_RANDOMIZATION,
                    EvasionTechnique.TRAFFIC_FRAGMENTATION,
                    EvasionTechnique.PAYLOAD_ENCODING,
                    EvasionTechnique.USER_AGENT_ROTATION,
                    EvasionTechnique.PROTOCOL_TUNNELING,
                    EvasionTechnique.DECOY_TRAFFIC,
                    EvasionTechnique.BEHAVIORAL_MIMICRY,
                    EvasionTechnique.ENCRYPTION_OBFUSCATION
                ],
                detection_risk=DetectionRisk.VERY_LOW,
                performance_impact=0.8,
                stealth_rating=0.95,
                complexity="expert"
            ),
            
            "stealth_balanced": EvasionProfile(
                name="Balanced Stealth",
                description="Good stealth with moderate performance impact",
                techniques=[
                    EvasionTechnique.TIMING_RANDOMIZATION,
                    EvasionTechnique.PAYLOAD_ENCODING,
                    EvasionTechnique.USER_AGENT_ROTATION,
                    EvasionTechnique.BEHAVIORAL_MIMICRY
                ],
                detection_risk=DetectionRisk.LOW,
                performance_impact=0.4,
                stealth_rating=0.75,
                complexity="medium"
            ),
            
            "stealth_minimal": EvasionProfile(
                name="Minimal Stealth",
                description="Basic evasion with minimal performance impact",
                techniques=[
                    EvasionTechnique.TIMING_RANDOMIZATION,
                    EvasionTechnique.USER_AGENT_ROTATION
                ],
                detection_risk=DetectionRisk.MEDIUM,
                performance_impact=0.1,
                stealth_rating=0.5,
                complexity="easy"
            ),
            
            "red_team": EvasionProfile(
                name="Red Team Operations",
                description="Advanced evasion for red team exercises",
                techniques=[
                    EvasionTechnique.TIMING_RANDOMIZATION,
                    EvasionTechnique.TRAFFIC_FRAGMENTATION,
                    EvasionTechnique.PAYLOAD_ENCODING,
                    EvasionTechnique.USER_AGENT_ROTATION,
                    EvasionTechnique.DECOY_TRAFFIC,
                    EvasionTechnique.BEHAVIORAL_MIMICRY,
                    EvasionTechnique.STEGANOGRAPHY
                ],
                detection_risk=DetectionRisk.VERY_LOW,
                performance_impact=0.6,
                stealth_rating=0.9,
                complexity="hard"
            ),
            
            "apt_simulation": EvasionProfile(
                name="APT Simulation",
                description="Mimics advanced persistent threat behavior",
                techniques=[
                    EvasionTechnique.TIMING_RANDOMIZATION,
                    EvasionTechnique.BEHAVIORAL_MIMICRY,
                    EvasionTechnique.ENCRYPTION_OBFUSCATION,
                    EvasionTechnique.PROTOCOL_TUNNELING,
                    EvasionTechnique.STEGANOGRAPHY
                ],
                detection_risk=DetectionRisk.VERY_LOW,
                performance_impact=0.7,
                stealth_rating=0.92,
                complexity="expert"
            )
        }
    
    def _initialize_traffic_patterns(self):
        """Initialize traffic patterns for behavioral mimicry"""
        self.traffic_patterns = {
            "normal_browsing": TrafficPattern(
                name="Normal Web Browsing",
                description="Mimics typical user web browsing behavior",
                request_intervals=[2.5, 5.0, 8.0, 12.0, 15.0, 20.0],
                burst_patterns=[1, 2, 3, 5],
                idle_periods=[30.0, 60.0, 120.0, 300.0],
                user_agents=[
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                ],
                headers={
                    "Accept": [
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
                    ],
                    "Accept-Language": ["en-US,en;q=0.5", "en-GB,en;q=0.5"],
                    "Accept-Encoding": ["gzip, deflate", "gzip, deflate, br"]
                }
            ),
            
            "api_client": TrafficPattern(
                name="API Client",
                description="Mimics automated API client behavior",
                request_intervals=[1.0, 2.0, 3.0, 5.0],
                burst_patterns=[5, 10, 15, 20],
                idle_periods=[10.0, 30.0, 60.0],
                user_agents=[
                    "curl/7.68.0",
                    "python-requests/2.25.1",
                    "PostmanRuntime/7.28.0"
                ],
                headers={
                    "Content-Type": ["application/json", "application/x-www-form-urlencoded"],
                    "Accept": ["application/json", "*/*"]
                }
            ),
            
            "mobile_app": TrafficPattern(
                name="Mobile Application",
                description="Mimics mobile application traffic",
                request_intervals=[3.0, 7.0, 15.0, 30.0],
                burst_patterns=[2, 4, 6],
                idle_periods=[60.0, 300.0, 600.0],
                user_agents=[
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
                    "Mozilla/5.0 (Linux; Android 11; SM-G991B)"
                ],
                headers={
                    "Accept": ["application/json", "text/html"],
                    "X-Requested-With": ["XMLHttpRequest"]
                }
            )
        }
    
    def set_evasion_profile(self, profile_name: str) -> bool:
        """Set active evasion profile"""
        if profile_name in self.profiles:
            self.active_profile = self.profiles[profile_name]
            return True
        return False
    
    def get_available_profiles(self) -> Dict[str, EvasionProfile]:
        """Get all available evasion profiles"""
        return self.profiles.copy()
    
    async def apply_timing_randomization(self, base_delay: float) -> float:
        """Apply timing randomization to avoid pattern detection"""
        if not self.active_profile or EvasionTechnique.TIMING_RANDOMIZATION not in self.active_profile.techniques:
            return base_delay
        
        # Apply jitter based on stealth rating
        jitter_factor = self.active_profile.stealth_rating * 2.0
        min_delay = base_delay * (1.0 - jitter_factor * 0.5)
        max_delay = base_delay * (1.0 + jitter_factor * 1.5)
        
        randomized_delay = random.uniform(min_delay, max_delay)
        
        # Add occasional longer pauses to mimic human behavior
        if random.random() < 0.1:  # 10% chance
            randomized_delay += random.uniform(5.0, 30.0)
        
        return max(0.1, randomized_delay)  # Minimum 0.1 second delay
    
    def apply_payload_encoding(self, payload: str, encoding_type: str = "auto") -> str:
        """Apply payload encoding for evasion"""
        if not self.active_profile or EvasionTechnique.PAYLOAD_ENCODING not in self.active_profile.techniques:
            return payload
        
        if encoding_type == "auto":
            encoding_type = random.choice(["base64", "url", "hex", "unicode", "double_url"])
        
        encoded_payload = payload
        
        if encoding_type == "base64":
            encoded_payload = base64.b64encode(payload.encode()).decode()
        
        elif encoding_type == "url":
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload)
        
        elif encoding_type == "double_url":
            import urllib.parse
            encoded_payload = urllib.parse.quote(urllib.parse.quote(payload))
        
        elif encoding_type == "hex":
            encoded_payload = payload.encode().hex()
        
        elif encoding_type == "unicode":
            encoded_payload = ''.join(f'\\u{ord(c):04x}' for c in payload)
        
        return encoded_payload
    
    def get_random_user_agent(self, pattern: str = "normal_browsing") -> str:
        """Get random user agent for rotation"""
        if not self.active_profile or EvasionTechnique.USER_AGENT_ROTATION not in self.active_profile.techniques:
            return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        
        if pattern in self.traffic_patterns:
            return random.choice(self.traffic_patterns[pattern].user_agents)
        
        # Default user agents
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        
        return random.choice(user_agents)
    
    def generate_decoy_requests(self, target_url: str, num_decoys: int = 5) -> List[Dict[str, Any]]:
        """Generate decoy requests to mask real attacks"""
        if not self.active_profile or EvasionTechnique.DECOY_TRAFFIC not in self.active_profile.techniques:
            return []
        
        decoy_requests = []
        
        # Common legitimate paths
        decoy_paths = [
            "/", "/index.html", "/about", "/contact", "/login", "/search",
            "/favicon.ico", "/robots.txt", "/sitemap.xml", "/css/style.css",
            "/js/main.js", "/images/logo.png", "/api/status", "/health"
        ]
        
        for _ in range(num_decoys):
            decoy_request = {
                "url": target_url.rstrip('/') + random.choice(decoy_paths),
                "method": "GET",
                "headers": {
                    "User-Agent": self.get_random_user_agent(),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive"
                },
                "delay": random.uniform(1.0, 10.0)
            }
            decoy_requests.append(decoy_request)
        
        return decoy_requests
    
    async def apply_behavioral_mimicry(self, operation_type: str) -> Dict[str, Any]:
        """Apply behavioral mimicry based on operation type"""
        if not self.active_profile or EvasionTechnique.BEHAVIORAL_MIMICRY not in self.active_profile.techniques:
            return {}
        
        # Select appropriate traffic pattern
        if operation_type in ["web_scan", "directory_enum"]:
            pattern_name = "normal_browsing"
        elif operation_type in ["api_test", "injection_test"]:
            pattern_name = "api_client"
        elif operation_type in ["mobile_test"]:
            pattern_name = "mobile_app"
        else:
            pattern_name = "normal_browsing"
        
        if pattern_name not in self.traffic_patterns:
            return {}
        
        pattern = self.traffic_patterns[pattern_name]
        
        behavior = {
            "request_interval": random.choice(pattern.request_intervals),
            "burst_size": random.choice(pattern.burst_patterns),
            "idle_period": random.choice(pattern.idle_periods),
            "user_agent": random.choice(pattern.user_agents),
            "headers": {}
        }
        
        # Add randomized headers
        for header_name, header_values in pattern.headers.items():
            behavior["headers"][header_name] = random.choice(header_values)
        
        return behavior
    
    def fragment_payload(self, payload: str, fragment_size: int = 8) -> List[str]:
        """Fragment payload to avoid signature detection"""
        if not self.active_profile or EvasionTechnique.TRAFFIC_FRAGMENTATION not in self.active_profile.techniques:
            return [payload]
        
        fragments = []
        for i in range(0, len(payload), fragment_size):
            fragments.append(payload[i:i + fragment_size])
        
        return fragments
    
    async def generate_ai_evasion_strategy(self, target_info: Dict[str, Any], 
                                         operation_type: str) -> Dict[str, Any]:
        """Generate AI-powered evasion strategy based on target analysis"""
        
        prompt = f"""
        Analyze the target environment and generate an optimal evasion strategy:
        
        Target Information:
        - Host: {target_info.get('host', 'unknown')}
        - Services: {target_info.get('services', [])}
        - OS: {target_info.get('os', 'unknown')}
        - Security Controls: {target_info.get('security_controls', [])}
        
        Operation Type: {operation_type}
        Current Profile: {self.active_profile.name if self.active_profile else 'None'}
        
        Provide recommendations for:
        1. Optimal timing patterns
        2. Payload encoding methods
        3. Traffic obfuscation techniques
        4. Behavioral mimicry approach
        5. Detection avoidance strategies
        
        Format as JSON with specific recommendations and rationale.
        """
        
        try:
            from nexus.ai.ollama_client import GenerationRequest
            request = GenerationRequest(
                model=self.config.ai.model,
                prompt=prompt,
                system="You are a cybersecurity expert specializing in evasion techniques.",
                temperature=0.4
            )
            response = await self.ollama_client.generate(request)
            import json
            strategy = json.loads(response.response)
            return strategy
        except Exception as e:
            # Fallback to default strategy
            return {
                "timing_pattern": "randomized_intervals",
                "encoding_method": "base64",
                "obfuscation": "user_agent_rotation",
                "mimicry": "normal_browsing",
                "rationale": f"AI analysis failed ({e}), using default strategy"
            }
    
    def calculate_detection_probability(self, operation_params: Dict[str, Any]) -> float:
        """Calculate detection probability for current operation"""
        base_probability = 0.5  # 50% base detection probability
        
        if not self.active_profile:
            return base_probability
        
        # Reduce probability based on active evasion techniques
        reduction_factor = 0.0
        
        for technique in self.active_profile.techniques:
            if technique == EvasionTechnique.TIMING_RANDOMIZATION:
                reduction_factor += 0.15
            elif technique == EvasionTechnique.PAYLOAD_ENCODING:
                reduction_factor += 0.10
            elif technique == EvasionTechnique.USER_AGENT_ROTATION:
                reduction_factor += 0.08
            elif technique == EvasionTechnique.BEHAVIORAL_MIMICRY:
                reduction_factor += 0.20
            elif technique == EvasionTechnique.TRAFFIC_FRAGMENTATION:
                reduction_factor += 0.12
            elif technique == EvasionTechnique.DECOY_TRAFFIC:
                reduction_factor += 0.18
            elif technique == EvasionTechnique.ENCRYPTION_OBFUSCATION:
                reduction_factor += 0.15
            elif technique == EvasionTechnique.PROTOCOL_TUNNELING:
                reduction_factor += 0.25
            elif technique == EvasionTechnique.STEGANOGRAPHY:
                reduction_factor += 0.30
        
        # Apply stealth rating multiplier
        reduction_factor *= self.active_profile.stealth_rating
        
        # Consider operation parameters
        if operation_params.get('request_rate', 1) > 10:
            reduction_factor *= 0.8  # High request rate increases detection risk
        
        if operation_params.get('payload_size', 0) > 1000:
            reduction_factor *= 0.9  # Large payloads increase detection risk
        
        final_probability = max(0.01, base_probability - reduction_factor)
        return min(0.99, final_probability)
    
    def log_detection_event(self, event_type: str, details: Dict[str, Any]):
        """Log potential detection events for analysis"""
        detection_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "active_profile": self.active_profile.name if self.active_profile else None,
            "detection_probability": self.calculate_detection_probability(details)
        }
        
        self.detection_history.append(detection_event)
        
        # Keep only last 1000 events
        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-1000:]
    
    def get_evasion_report(self) -> Dict[str, Any]:
        """Generate comprehensive evasion report"""
        if not self.active_profile:
            return {"error": "No active evasion profile"}
        
        recent_events = [e for e in self.detection_history 
                        if datetime.fromisoformat(e["timestamp"]) > datetime.now() - timedelta(hours=24)]
        
        avg_detection_prob = sum(e["detection_probability"] for e in recent_events) / len(recent_events) if recent_events else 0.0
        
        return {
            "active_profile": {
                "name": self.active_profile.name,
                "description": self.active_profile.description,
                "techniques": [t.value for t in self.active_profile.techniques],
                "detection_risk": self.active_profile.detection_risk.value,
                "stealth_rating": self.active_profile.stealth_rating,
                "performance_impact": self.active_profile.performance_impact
            },
            "statistics": {
                "total_events": len(self.detection_history),
                "recent_events_24h": len(recent_events),
                "average_detection_probability": avg_detection_prob,
                "techniques_active": len(self.active_profile.techniques)
            },
            "recommendations": self._generate_evasion_recommendations()
        }
    
    def _generate_evasion_recommendations(self) -> List[str]:
        """Generate evasion recommendations based on current state"""
        recommendations = []
        
        if not self.active_profile:
            recommendations.append("Set an evasion profile appropriate for your operation")
            return recommendations
        
        if self.active_profile.detection_risk.value in ["high", "very_high"]:
            recommendations.append("Consider switching to a higher stealth profile")
        
        if len(self.detection_history) > 100:
            recent_high_risk = sum(1 for e in self.detection_history[-50:] 
                                 if e["detection_probability"] > 0.7)
            if recent_high_risk > 10:
                recommendations.append("High detection probability detected - consider pausing operations")
        
        if EvasionTechnique.BEHAVIORAL_MIMICRY not in self.active_profile.techniques:
            recommendations.append("Enable behavioral mimicry for better stealth")
        
        if EvasionTechnique.TIMING_RANDOMIZATION not in self.active_profile.techniques:
            recommendations.append("Enable timing randomization to avoid pattern detection")
        
        return recommendations


class EvasionIntegration:
    """Integration layer for evasion with other Nexus components"""
    
    def __init__(self, evasion_manager: EvasionManager):
        self.evasion_manager = evasion_manager
    
    async def prepare_tool_execution(self, tool_name: str, target: str, 
                                   params: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare tool execution with evasion techniques"""
        
        # Apply timing randomization
        if 'delay' in params:
            params['delay'] = await self.evasion_manager.apply_timing_randomization(params['delay'])
        else:
            params['delay'] = await self.evasion_manager.apply_timing_randomization(1.0)
        
        # Apply behavioral mimicry
        behavior = await self.evasion_manager.apply_behavioral_mimicry(tool_name)
        if behavior:
            params.update(behavior)
        
        # Generate decoy requests for web tools
        if tool_name in ['nikto', 'gobuster', 'dirb']:
            params['decoy_requests'] = self.evasion_manager.generate_decoy_requests(target)
        
        # Apply payload encoding for injection tools
        if tool_name in ['sqlmap'] and 'payload' in params:
            params['payload'] = self.evasion_manager.apply_payload_encoding(params['payload'])
        
        return params
    
    def get_stealth_headers(self, operation_type: str = "web_scan") -> Dict[str, str]:
        """Get stealth-optimized HTTP headers"""
        headers = {
            "User-Agent": self.evasion_manager.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0"
        }
        
        # Add operation-specific headers
        if operation_type == "api_test":
            headers["Content-Type"] = "application/json"
            headers["Accept"] = "application/json"
        
        return headers