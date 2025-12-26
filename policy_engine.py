#!/usr/bin/env python3
"""
Anti-Ransomware Policy Engine
YAML/JSON parsing, per-path rules, quotas, and admin interface
"""

import os
import json
import yaml
import re
import fnmatch
import time
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import hashlib
import psutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

@dataclass
class ProcessRule:
    """Process-specific rules"""
    name: str
    signer_hash: Optional[str] = None
    publisher_cn: Optional[str] = None
    team_id: Optional[str] = None  # macOS
    cdhash: Optional[str] = None  # macOS
    ima_hash: Optional[str] = None  # Linux
    selinux_label: Optional[str] = None  # Linux
    deny_if_parent: Optional[str] = None
    allow: bool = True

@dataclass
class TimeWindow:
    """Time window for access control"""
    start_time: str  # HH:MM format
    end_time: str    # HH:MM format
    days: List[str]  # ['monday', 'tuesday', etc.]
    timezone: str = 'UTC'

@dataclass
class Quota:
    """Quota limits"""
    files_per_min: int = 10
    bytes_per_min: int = 1024 * 1024  # 1MB
    entropy_bypass: bool = False
    interactive_consent: bool = True

@dataclass
class PathRule:
    """Path-specific access rule"""
    path_pattern: str
    quota: Quota
    process_rules: List[ProcessRule]
    time_windows: List[TimeWindow]
    recursive: bool = True
    case_sensitive: bool = False

@dataclass
class Policy:
    """Complete policy configuration"""
    version: str = "1.0"
    rules: List[PathRule] = None
    global_settings: Dict[str, Any] = None
    signature: Optional[str] = None
    
    def __post_init__(self):
        if self.rules is None:
            self.rules = []
        if self.global_settings is None:
            self.global_settings = {
                'default_quota': {'files_per_min': 10, 'bytes_per_min': 1048576},
                'token_lifetime': 300,
                'require_dongle': True,
                'audit_level': 'full'
            }

class PolicyEngine:
    """Policy engine with YAML/JSON parsing and evaluation"""
    
    def __init__(self, policy_file: str = "policy.yaml"):
        self.policy_file = policy_file
        self.policy: Policy = Policy()
        self.quota_tracker: Dict[str, List[float]] = {}
        self.process_cache: Dict[int, Dict[str, str]] = {}
        self.load_policy()
    
    def load_policy(self) -> bool:
        """Load policy from YAML or JSON file"""
        try:
            if not os.path.exists(self.policy_file):
                self.create_default_policy()
                return True
                
            with open(self.policy_file, 'r', encoding='utf-8') as f:
                if self.policy_file.endswith('.yaml') or self.policy_file.endswith('.yml'):
                    policy_data = yaml.safe_load(f)
                else:
                    policy_data = json.load(f)
            
            # Parse policy data
            self.policy = self._parse_policy(policy_data)
            
            # Verify policy signature if present
            if self.policy.signature and not self._verify_policy_signature(policy_data):
                raise ValueError("Policy signature verification failed")
            
            print(f"Loaded policy with {len(self.policy.rules)} rules")
            return True
            
        except Exception as e:
            print(f"Failed to load policy: {e}")
            self.create_default_policy()
            return False
    
    def create_default_policy(self):
        """Create default policy if none exists"""
        default_quota = Quota(files_per_min=10, bytes_per_min=1024*1024)
        default_rule = PathRule(
            path_pattern="/protected/*",
            quota=default_quota,
            process_rules=[],
            time_windows=[]
        )
        
        self.policy = Policy(rules=[default_rule])
        self.save_policy()
    
    def save_policy(self):
        """Save policy to file"""
        try:
            policy_dict = asdict(self.policy)
            
            with open(self.policy_file, 'w', encoding='utf-8') as f:
                if self.policy_file.endswith('.yaml') or self.policy_file.endswith('.yml'):
                    yaml.dump(policy_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(policy_dict, f, indent=2)
                    
            print(f"Policy saved to {self.policy_file}")
            
        except Exception as e:
            print(f"Failed to save policy: {e}")
    
    def _parse_policy(self, policy_data: Dict) -> Policy:
        """Parse policy data into Policy object"""
        policy = Policy()
        policy.version = policy_data.get('version', '1.0')
        policy.global_settings = policy_data.get('global_settings', {})
        policy.signature = policy_data.get('signature')
        
        # Parse rules
        policy.rules = []
        for rule_data in policy_data.get('rules', []):
            rule = self._parse_path_rule(rule_data)
            policy.rules.append(rule)
        
        return policy
    
    def _parse_path_rule(self, rule_data: Dict) -> PathRule:
        """Parse path rule data"""
        quota_data = rule_data.get('quota', {})
        quota = Quota(
            files_per_min=quota_data.get('files_per_min', 10),
            bytes_per_min=quota_data.get('bytes_per_min', 1048576),
            entropy_bypass=quota_data.get('entropy_bypass', False),
            interactive_consent=quota_data.get('interactive_consent', True)
        )
        
        # Parse process rules
        process_rules = []
        for proc_data in rule_data.get('process_rules', []):
            proc_rule = ProcessRule(
                name=proc_data['name'],
                signer_hash=proc_data.get('signer_hash'),
                publisher_cn=proc_data.get('publisher_cn'),
                team_id=proc_data.get('team_id'),
                cdhash=proc_data.get('cdhash'),
                ima_hash=proc_data.get('ima_hash'),
                selinux_label=proc_data.get('selinux_label'),
                deny_if_parent=proc_data.get('deny_if_parent'),
                allow=proc_data.get('allow', True)
            )
            process_rules.append(proc_rule)
        
        # Parse time windows
        time_windows = []
        for tw_data in rule_data.get('time_windows', []):
            time_window = TimeWindow(
                start_time=tw_data['start_time'],
                end_time=tw_data['end_time'],
                days=tw_data.get('days', ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']),
                timezone=tw_data.get('timezone', 'UTC')
            )
            time_windows.append(time_window)
        
        return PathRule(
            path_pattern=rule_data['path_pattern'],
            quota=quota,
            process_rules=process_rules,
            time_windows=time_windows,
            recursive=rule_data.get('recursive', True),
            case_sensitive=rule_data.get('case_sensitive', False)
        )
    
    def check_access(self, file_path: str, process_id: int, user_id: str) -> Tuple[bool, Optional[PathRule], str]:
        """Check if access is allowed based on policy"""
        # Get process information
        process_info = self._get_process_info(process_id)
        
        # Find matching rule
        matching_rule = None
        for rule in self.policy.rules:
            if self._match_path(file_path, rule.path_pattern, rule.case_sensitive):
                matching_rule = rule
                break
        
        if not matching_rule:
            return False, None, "No matching policy rule"
        
        # Check process rules
        if not self._check_process_rules(process_info, matching_rule.process_rules):
            return False, matching_rule, "Process denied by policy"
        
        # Check time windows
        if not self._check_time_windows(matching_rule.time_windows):
            return False, matching_rule, "Access denied due to time restrictions"
        
        # Check quotas
        if not self._check_quota(user_id, matching_rule.quota):
            return False, matching_rule, "Quota exceeded"
        
        return True, matching_rule, "Access allowed"
    
    def _get_process_info(self, process_id: int) -> Dict[str, str]:
        """Get process information"""
        if process_id in self.process_cache:
            return self.process_cache[process_id]
        
        try:
            process = psutil.Process(process_id)
            info = {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()),
                'parent_name': process.parent().name() if process.parent() else '',
                'user': process.username(),
                'create_time': str(process.create_time())
            }
            
            # Add platform-specific info
            if hasattr(process, 'environ'):
                env = process.environ()
                info['selinux_label'] = env.get('SELINUX_LABEL', '')
            
            # Cache process info
            self.process_cache[process_id] = info
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'name': 'unknown', 'exe': '', 'cmdline': '', 'parent_name': '', 'user': '', 'create_time': ''}
    
    def _match_path(self, path: str, pattern: str, case_sensitive: bool = False) -> bool:
        """Match file path against pattern"""
        if not case_sensitive:
            path = path.lower()
            pattern = pattern.lower()
        
        # Support glob patterns
        if '*' in pattern or '?' in pattern:
            return fnmatch.fnmatch(path, pattern)
        
        # Support regex patterns (if pattern starts with 'regex:')
        if pattern.startswith('regex:'):
            regex_pattern = pattern[6:]
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                return bool(re.match(regex_pattern, path, flags))
            except re.error:
                return False
        
        # Simple prefix matching
        return path.startswith(pattern)
    
    def _check_process_rules(self, process_info: Dict[str, str], rules: List[ProcessRule]) -> bool:
        """Check process against rules"""
        if not rules:
            return True
        
        for rule in rules:
            if self._match_process_rule(process_info, rule):
                return rule.allow
        
        return True  # Default allow if no rules match
    
    def _match_process_rule(self, process_info: Dict[str, str], rule: ProcessRule) -> bool:
        """Check if process matches a specific rule"""
        # Check process name
        if rule.name and not fnmatch.fnmatch(process_info.get('name', ''), rule.name):
            return False
        
        # Check parent process
        if rule.deny_if_parent and process_info.get('parent_name', '') == rule.deny_if_parent:
            return True
        
        # Check signer hash (simplified - would need actual signature verification)
        if rule.signer_hash:
            exe_path = process_info.get('exe', '')
            if exe_path and os.path.exists(exe_path):
                with open(exe_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    if file_hash != rule.signer_hash:
                        return False
        
        # Check SELinux label (Linux)
        if rule.selinux_label and process_info.get('selinux_label', '') != rule.selinux_label:
            return False
        
        return True
    
    def _check_time_windows(self, time_windows: List[TimeWindow]) -> bool:
        """Check if current time is within allowed windows"""
        if not time_windows:
            return True
        
        current_time = datetime.now()
        current_day = current_time.strftime('%A').lower()
        current_hour_min = current_time.strftime('%H:%M')
        
        for window in time_windows:
            if current_day in [day.lower() for day in window.days]:
                if self._is_time_in_range(current_hour_min, window.start_time, window.end_time):
                    return True
        
        return False
    
    def _is_time_in_range(self, current_time: str, start_time: str, end_time: str) -> bool:
        """Check if current time is within range"""
        try:
            current = datetime.strptime(current_time, '%H:%M').time()
            start = datetime.strptime(start_time, '%H:%M').time()
            end = datetime.strptime(end_time, '%H:%M').time()
            
            if start <= end:
                return start <= current <= end
            else:  # Spans midnight
                return current >= start or current <= end
        except ValueError:
            return True  # Default allow if time parsing fails
    
    def _check_quota(self, user_id: str, quota: Quota) -> bool:
        """Check if user is within quota limits"""
        current_time = time.time()
        
        if user_id not in self.quota_tracker:
            self.quota_tracker[user_id] = []
        
        # Clean old entries (older than 1 minute)
        self.quota_tracker[user_id] = [
            t for t in self.quota_tracker[user_id]
            if current_time - t < 60
        ]
        
        # Check quota
        if len(self.quota_tracker[user_id]) >= quota.files_per_min:
            return False
        
        # Add current request
        self.quota_tracker[user_id].append(current_time)
        return True
    
    def _verify_policy_signature(self, policy_data: Dict) -> bool:
        """Verify policy signature (simplified implementation)"""
        try:
            signature_b64 = policy_data.get('signature')
            if not signature_b64:
                return True  # Nothing to verify

            # Remove signature field for canonical representation
            policy_copy = dict(policy_data)
            policy_copy.pop('signature', None)
            canonical = json.dumps(policy_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')

            # Load admin public key (PEM) from keys/admin_public_key.pem
            pub_path = os.path.join('keys', 'admin_public_key.pem')
            if not os.path.exists(pub_path):
                print("Admin public key not found; rejecting unsigned policy")
                return False

            with open(pub_path, 'rb') as f:
                pub_data = f.read()
            public_key = serialization.load_pem_public_key(pub_data)

            signature = base64.b64decode(signature_b64)

            if not isinstance(public_key, Ed25519PublicKey):
                print("Unsupported public key type for policy verification")
                return False

            public_key.verify(signature, canonical)
            return True

        except Exception as e:
            print(f"Policy signature verification failed: {e}")
            return False
    
    def add_rule(self, rule: PathRule):
        """Add a new rule to the policy"""
        self.policy.rules.append(rule)
        self.save_policy()
    
    def remove_rule(self, path_pattern: str):
        """Remove a rule by path pattern"""
        self.policy.rules = [r for r in self.policy.rules if r.path_pattern != path_pattern]
        self.save_policy()
    
    def update_rule(self, path_pattern: str, new_rule: PathRule):
        """Update an existing rule"""
        for i, rule in enumerate(self.policy.rules):
            if rule.path_pattern == path_pattern:
                self.policy.rules[i] = new_rule
                break
        self.save_policy()
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get policy summary for admin interface"""
        return {
            'version': self.policy.version,
            'total_rules': len(self.policy.rules),
            'global_settings': self.policy.global_settings,
            'rules': [
                {
                    'path_pattern': rule.path_pattern,
                    'quota_files_per_min': rule.quota.files_per_min,
                    'quota_bytes_per_min': rule.quota.bytes_per_min,
                    'process_rules_count': len(rule.process_rules),
                    'time_windows_count': len(rule.time_windows)
                }
                for rule in self.policy.rules
            ]
        }

# Example policy YAML generator
def generate_example_policy() -> str:
    """Generate example policy YAML"""
    example_policy = {
        'version': '1.0',
        'global_settings': {
            'default_quota': {'files_per_min': 10, 'bytes_per_min': 1048576},
            'token_lifetime': 300,
            'require_dongle': True,
            'audit_level': 'full'
        },
        'rules': [
            {
                'path_pattern': '/protected/*',
                'quota': {
                    'files_per_min': 10,
                    'bytes_per_min': 1048576,
                    'entropy_bypass': False,
                    'interactive_consent': True
                },
                'process_rules': [
                    {
                        'name': 'notepad.exe',
                        'allow': True
                    },
                    {
                        'name': 'powershell.exe',
                        'deny_if_parent': 'winword.exe',
                        'allow': False
                    }
                ],
                'time_windows': [
                    {
                        'start_time': '09:00',
                        'end_time': '17:00',
                        'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']
                    }
                ]
            }
        ]
    }
    
    return yaml.dump(example_policy, default_flow_style=False, indent=2)

if __name__ == "__main__":
    # Example usage
    print("Anti-Ransomware Policy Engine")
    
    # Generate example policy
    print("\nExample policy YAML:")
    print(generate_example_policy())
    
    # Create policy engine
    engine = PolicyEngine("example_policy.yaml")
    
    # Test access check
    allowed, rule, reason = engine.check_access(
        file_path="/protected/important.txt",
        process_id=os.getpid(),
        user_id="user123"
    )
    
    print(f"\nAccess check result: {'ALLOWED' if allowed else 'DENIED'}")
    print(f"Reason: {reason}")
    
    if rule:
        print(f"Matching rule: {rule.path_pattern}")
        print(f"Quota: {rule.quota.files_per_min} files/min, {rule.quota.bytes_per_min} bytes/min")
    
    # Print policy summary
    print("\nPolicy summary:")
    summary = engine.get_policy_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")
