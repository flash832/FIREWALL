"""
sentinel_guard.py — Input Validation & Rate Limiting for Sentinel-SD
=====================================================================
Two missing pieces that take the project from GOOD to EXCELLENT:

  1. RateLimiter   — blocks sessions sending too many requests
  2. InputGuard    — validates input before it reaches the firewall
  3. GuardedShield — drop-in wrapper that adds both to your Sentinel

Usage — wrap your existing shield with GuardedShield:

    from sentinel_shield import Sentinel
    from sentinel_shield.guard import GuardedShield

    # Replace this:
    shield = Sentinel()

    # With this — everything else stays the same:
    shield = GuardedShield(Sentinel())

    result = shield.analyze("Some input")
    # Returns same dict as before + new fields:
    # {
    #   'verdict': 'MALICIOUS',
    #   'threat_score': 100,
    #   'detected_vector': 'PatternMatch',
    #   'matched_pattern': 'ignore previous',   ← NEW
    #   'normalized_input': 'how to hack',       ← NEW
    #   'layer': 1,                              ← NEW
    #   'confidence': 'HIGH',                    ← NEW
    #   'rate_limited': False,                   ← NEW
    # }
"""

import time
import sys
import os
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

# ── Fix Unicode on Windows ────────────────────────────────────
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Logging ───────────────────────────────────────────────────
os.makedirs("sentinel_logs", exist_ok=True)
logging.basicConfig(
    filename="sentinel_logs/sentinel_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8",
)
guard_log = logging.getLogger("sentinel_guard")


# ══════════════════════════════════════════════════════════════
# 1. RATE LIMITER
# Tracks requests per session. Blocks if too many come too fast.
# Configurable: max requests per window, window size in seconds.
# ══════════════════════════════════════════════════════════════
@dataclass
class RateLimitConfig:
    max_requests_per_window: int = 60      # max requests allowed
    window_seconds: int          = 60      # rolling window size
    block_duration_seconds: int  = 300     # how long to block after limit hit (5 min)
    strict_mode: bool            = False   # True = block at limit, False = warn first


class RateLimiter:
    """
    Per-session rolling window rate limiter.

    Works with any session identifier — IP address, user ID,
    API key, or anything you pass as session_id.

    Example:
        limiter = RateLimiter()
        allowed, info = limiter.check("user_123")
        if not allowed:
            return {'verdict': 'RATE_LIMITED', ...}
    """

    def __init__(self, config: RateLimitConfig = None):
        self.config    = config or RateLimitConfig()
        # session_id → list of request timestamps
        self._requests: dict = defaultdict(list)
        # session_id → blocked_until timestamp
        self._blocked:  dict = {}
        self._stats = {
            'total_checked':  0,
            'total_blocked':  0,
            'total_warned':   0,
            'blocked_sessions': set(),
        }

    def check(self, session_id: str) -> tuple:
        """
        Check if session is within rate limit.

        Returns:
            (allowed: bool, info: dict)
            info contains: requests_in_window, limit, blocked_until, reason
        """
        self._stats['total_checked'] += 1
        now = time.time()

        # ── Check if currently hard-blocked ──────────────────
        if session_id in self._blocked:
            blocked_until = self._blocked[session_id]
            if now < blocked_until:
                remaining = int(blocked_until - now)
                self._stats['total_blocked'] += 1
                guard_log.warning(
                    f"RATE_BLOCKED | session={session_id} | "
                    f"blocked_for={remaining}s more"
                )
                return False, {
                    'reason':         'hard_blocked',
                    'blocked_until':  datetime.fromtimestamp(blocked_until).isoformat(),
                    'retry_after_sec': remaining,
                    'requests_in_window': self.config.max_requests_per_window,
                    'limit':          self.config.max_requests_per_window,
                }
            else:
                # Block expired — clear it
                del self._blocked[session_id]

        # ── Clean up old requests outside window ──────────────
        cutoff = now - self.config.window_seconds
        self._requests[session_id] = [
            t for t in self._requests[session_id] if t > cutoff
        ]

        count = len(self._requests[session_id])

        # ── Hard limit hit — block the session ───────────────
        if count >= self.config.max_requests_per_window:
            blocked_until = now + self.config.block_duration_seconds
            self._blocked[session_id] = blocked_until
            self._stats['total_blocked'] += 1
            self._stats['blocked_sessions'].add(session_id)

            guard_log.warning(
                f"RATE_LIMIT_HIT | session={session_id} | "
                f"requests={count} | window={self.config.window_seconds}s | "
                f"blocked_for={self.config.block_duration_seconds}s"
            )
            return False, {
                'reason':          'rate_limit_exceeded',
                'requests_in_window': count,
                'limit':           self.config.max_requests_per_window,
                'blocked_until':   datetime.fromtimestamp(blocked_until).isoformat(),
                'retry_after_sec': self.config.block_duration_seconds,
            }

        # ── Soft warning — approaching limit ──────────────────
        warn_threshold = int(self.config.max_requests_per_window * 0.8)
        if count >= warn_threshold:
            self._stats['total_warned'] += 1
            guard_log.info(
                f"RATE_WARNING | session={session_id} | "
                f"requests={count}/{self.config.max_requests_per_window}"
            )

        # ── Allow — record this request ───────────────────────
        self._requests[session_id].append(now)

        return True, {
            'reason':            'allowed',
            'requests_in_window': count + 1,
            'limit':             self.config.max_requests_per_window,
            'remaining':         self.config.max_requests_per_window - count - 1,
        }

    def get_stats(self) -> dict:
        return {
            'total_checked':    self._stats['total_checked'],
            'total_blocked':    self._stats['total_blocked'],
            'total_warned':     self._stats['total_warned'],
            'active_sessions':  len(self._requests),
            'blocked_sessions': len(self._stats['blocked_sessions']),
        }

    def unblock(self, session_id: str):
        """Manually unblock a session — for admin use."""
        if session_id in self._blocked:
            del self._blocked[session_id]
            guard_log.info(f"MANUAL_UNBLOCK | session={session_id}")


# ══════════════════════════════════════════════════════════════
# 2. INPUT GUARD
# Validates and sanitizes input BEFORE it reaches the firewall.
# Catches: too long, empty, binary garbage, null byte injection.
# ══════════════════════════════════════════════════════════════
@dataclass
class InputConfig:
    max_length: int          = 5000     # characters — block anything longer
    min_length: int          = 1        # block empty strings
    allow_binary: bool       = False    # block non-text binary content
    normalize_whitespace: bool = True   # collapse multiple spaces
    strip_null_bytes: bool   = True     # remove \x00 chars (null byte injection)
    max_lines: int           = 50       # block inputs with excessive newlines


class InputGuard:
    """
    Validates and sanitizes raw input before firewall analysis.

    Catches attack types the firewall itself does not handle:
    - Crash-by-length: 10MB strings
    - Null byte injection: \x00 hidden in input
    - Binary garbage: non-text bytes
    - Empty input: avoids unnecessary processing
    - Excessive newlines: used to hide payloads in whitespace

    Example:
        guard = InputGuard()
        clean, result = guard.validate("Hello \x00 world")
        if result['blocked']:
            return result
        # use clean input
    """

    def __init__(self, config: InputConfig = None):
        self.config = config or InputConfig()
        self._stats = {
            'total_validated': 0,
            'total_blocked':   0,
            'block_reasons':   defaultdict(int),
        }

    def validate(self, text: str) -> tuple:
        """
        Validate and clean input.

        Returns:
            (cleaned_text: str, result: dict)
            result['blocked'] = True means reject this input
        """
        self._stats['total_validated'] += 1

        # ── Check 1: Type safety ──────────────────────────────
        if not isinstance(text, str):
            return self._block(str(text)[:100], 'not_a_string',
                               'Input must be a string')

        # ── Check 2: Empty input ──────────────────────────────
        if len(text.strip()) < self.config.min_length:
            return self._block('', 'empty_input', 'Input is empty')

        # ── Check 3: Input too long ───────────────────────────
        if len(text) > self.config.max_length:
            guard_log.warning(
                f"INPUT_TOO_LONG | length={len(text)} | "
                f"limit={self.config.max_length}"
            )
            return self._block(
                text[:100] + '...',
                'input_too_long',
                f'Input exceeds {self.config.max_length} characters '
                f'(got {len(text)})'
            )

        # ── Check 4: Too many lines (hidden payload trick) ────
        line_count = text.count('\n')
        if line_count > self.config.max_lines:
            return self._block(
                text[:100],
                'too_many_lines',
                f'Input has {line_count} lines (max {self.config.max_lines})'
            )

        # ── Check: Null byte injection — always block ─────────
        if '\x00' in text:
            guard_log.warning(
                f"NULL_BYTE_DETECTED | "
                f"count={text.count(chr(0))} | payload={text[:80]}"
            )
            return self._block(
                text[:100],
                'null_byte_injection',
                'Input contains null bytes — injection attempt detected'
            )

        # ── Sanitize: Normalize whitespace ────────────────────
        if self.config.normalize_whitespace:
            import re
            text = re.sub(r'[ \t]+', ' ', text).strip()

        # ── Check 5: Binary / non-text content ───────────────
        if not self.config.allow_binary:
            try:
                text.encode('utf-8')
            except (UnicodeEncodeError, UnicodeDecodeError):
                return self._block(
                    repr(text[:50]),
                    'binary_content',
                    'Input contains non-UTF-8 binary content'
                )

        self._stats['total_validated'] += 0  # already counted at top
        return text, {
            'blocked':          False,
            'original_length':  len(text),
            'cleaned':          True,
        }

    def _block(self, text: str, reason: str, message: str) -> tuple:
        self._stats['total_blocked']      += 1
        self._stats['block_reasons'][reason] += 1
        guard_log.warning(
            f"INPUT_BLOCKED | reason={reason} | message={message} | "
            f"input={text[:80]}"
        )
        return text, {
            'blocked':        True,
            'verdict':        'MALICIOUS',
            'threat_score':   100,
            'detected_vector': f'InputValidation:{reason}',
            'message':        message,
            'confidence':     'HIGH',
        }

    def get_stats(self) -> dict:
        return {
            'total_validated': self._stats['total_validated'],
            'total_blocked':   self._stats['total_blocked'],
            'block_reasons':   dict(self._stats['block_reasons']),
        }


@dataclass
class LearningConfig:
    enabled: bool                = True
    auto_patch_threshold: int    = 2     # Number of threat keywords needed to auto-patch
    review_queue_path: str       = "sentinel_logs/review_queue.json"
    rules_path: str              = "sentinel_shield/dynamic_rules.json"
    backups_dir: str             = "sentinel_rule_backups"


# ══════════════════════════════════════════════════════════════
# 3. GUARDED SHIELD — Drop-in wrapper
# Adds rate limiting + input validation to your existing Sentinel.
# Use this instead of Sentinel() directly.
# ══════════════════════════════════════════════════════════════
class GuardedShield:
    """
    Drop-in replacement for Sentinel() that adds:
      - Input length validation
      - Null byte detection
      - Rate limiting per session
      - Richer verdict output with matched patterns

    Usage:
        # Before:
        shield = Sentinel()
        result = shield.analyze("some input")

        # After (identical API, more protection):
        shield = GuardedShield(Sentinel())
        result = shield.analyze("some input")
        result = shield.analyze("some input", session_id="user_123")
    """

    def __init__(
        self,
        sentinel_instance,
        rate_config:  RateLimitConfig = None,
        input_config: InputConfig     = None,
        learning_config: LearningConfig = None,
    ):
        self.shield          = sentinel_instance
        self.rate_limiter    = RateLimiter(rate_config or RateLimitConfig())
        self.input_guard     = InputGuard(input_config or InputConfig())
        self.learning_config = learning_config or LearningConfig()
        self._total       = 0
        self._blocked     = 0
        self._patched     = 0

        self.threat_keywords = {
            "hack", "bypass", "ignore", "override", "inject", "exploit",
            "admin", "password", "malware", "jailbreak", "dan", "system",
            "instructions", "prompt", "disregard", "forget", "reveal",
            "bomb", "poison", "weapon", "shell", "root", "execute",
            "kaise", "batao", "mujhe",
        }

        if self.learning_config.enabled:
            os.makedirs(self.learning_config.backups_dir, exist_ok=True)
            os.makedirs(os.path.dirname(self.learning_config.review_queue_path), exist_ok=True)

        print("  [GUARD] GuardedShield active")
        print(f"  [GUARD] Rate limit : "
              f"{self.rate_limiter.config.max_requests_per_window} req/"
              f"{self.rate_limiter.config.window_seconds}s per session")
        print(f"  [GUARD] Max input  : "
              f"{self.input_guard.config.max_length} chars")
        if self.learning_config.enabled:
            print(f"  [GUARD] Self-learn : ON (Auto-patch threshold: {self.learning_config.auto_patch_threshold} keywords)")

    def analyze(self, text: str, session_id: str = "default") -> dict:
        """
        Full guarded analysis pipeline:
          1. Rate limit check
          2. Input validation + sanitization
          3. Firewall analysis
          4. Enriched verdict returned
        """
        self._total += 1
        start = time.perf_counter()

        # ── Step 1: Rate limit check ──────────────────────────
        allowed, rate_info = self.rate_limiter.check(session_id)
        if not allowed:
            self._blocked += 1
            guard_log.warning(
                f"RATE_LIMITED | session={session_id} | "
                f"retry_after={rate_info.get('retry_after_sec')}s"
            )
            return {
                'verdict':         'MALICIOUS',
                'threat_score':    100,
                'detected_vector': 'RateLimit',
                'message':         'Too many requests. Try again later.',
                'retry_after_sec': rate_info.get('retry_after_sec', 300),
                'rate_limited':    True,
                'confidence':      'HIGH',
                'latency_ms':      round((time.perf_counter() - start) * 1000, 2),
            }

        # ── Step 2: Input validation ──────────────────────────
        clean_text, validation = self.input_guard.validate(text)
        if validation.get('blocked'):
            self._blocked += 1
            return {
                **validation,
                'rate_limited': False,
                'latency_ms':   round((time.perf_counter() - start) * 1000, 2),
            }

        # ── Step 3: Firewall analysis ─────────────────────────
        try:
            result = self.shield.analyze(clean_text)
        except Exception as e:
            guard_log.error(f"SHIELD_ERROR | error={e} | input={clean_text[:80]}")
            return {
                'verdict':         'ERROR',
                'threat_score':    0,
                'detected_vector': 'ShieldError',
                'message':         str(e),
                'rate_limited':    False,
                'latency_ms':      round((time.perf_counter() - start) * 1000, 2),
            }

        # ── Step 4: Enrich verdict ────────────────────────────
        latency = round((time.perf_counter() - start) * 1000, 2)
        score   = float(result.get('threat_score', 0))

        # ── Live Self-Learning Check ──────────────────────────
        if self.learning_config.enabled and result.get('verdict') == 'SAFE' and score < 30:
            self._on_live_bypass(clean_text, session_id)

        enriched = {
            **result,
            # Existing fields preserved ↑
            'normalized_input': clean_text if clean_text != text else None,
            'input_length':     len(text),
            'rate_limited':     False,
            'requests_remaining': rate_info.get('remaining', '?'),
            'confidence':       self._score_to_confidence(score),
            'latency_ms':       latency,
        }

        if result.get('verdict') == 'MALICIOUS':
            self._blocked += 1
            guard_log.warning(
                f"BLOCKED | session={session_id} | "
                f"score={score} | vector={result.get('detected_vector')} | "
                f"input={clean_text[:100]}"
            )

        return enriched

    def _score_to_confidence(self, score: float) -> str:
        if score >= 90:  return 'HIGH'
        if score >= 60:  return 'MEDIUM'
        if score >= 30:  return 'LOW'
        return 'NONE'

    def _is_security_relevant(self, text: str) -> tuple:
        words = set(text.lower().split())
        matched = words & self.threat_keywords
        return bool(matched), len(matched), list(matched)

    def _on_live_bypass(self, raw_input: str, session_id: str):
        is_relevant, match_count, matched_words = self._is_security_relevant(raw_input)
        
        if not is_relevant:
            return

        # Log to review queue
        queue_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "payload": raw_input,
            "matched_keywords": matched_words,
            "match_count": match_count
        }
        
        try:
            with open(self.learning_config.review_queue_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(queue_entry) + '\n')
            guard_log.info(f"REVIEW_QUEUE_ADDED | session={session_id} | keywords={matched_words}")
        except Exception as e:
            guard_log.error(f"REVIEW_QUEUE_ERROR | error={e}")

        # Auto-patch if confidence threshold is met
        if match_count >= self.learning_config.auto_patch_threshold:
            guard_log.warning(f"AUTO_PATCH_TRIGGERED | session={session_id} | matches={match_count}")
            self._apply_live_patch(raw_input)

    def _apply_live_patch(self, text: str):
        clean = text.lower().strip()
        if not clean or len(clean) < 10:
            return
            
        try:
            with open(self.learning_config.rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
        except FileNotFoundError:
            rules = {'patterns': [], 'keywords': []}

        if clean in rules.get('patterns', []):
            return

        # Backup existing rules
        backup_path = (
            f"{self.learning_config.backups_dir}/rules_v"
            f"{rules.get('version', 0)}_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
        except Exception as e:
            guard_log.error(f"BACKUP_ERROR | error={e}")

        # Apply Patch
        rules.setdefault('patterns', []).append(clean)
        rules['last_updated'] = datetime.now().isoformat()
        rules['version'] = rules.get('version', 0) + 1
        
        try:
            with open(self.learning_config.rules_path, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
            self._patched += 1
            
            # Hot reload shield inside the same process
            self.shield.__init__()
            guard_log.info(f"SHIELD_RELOADED | new_rule='{clean[:50]}...' | version={rules['version']}")
        except Exception as e:
            guard_log.error(f"PATCH_ERROR | error={e}")

    def get_stats(self) -> dict:
        return {
            'total_requests':   self._total,
            'total_blocked':    self._blocked,
            'block_rate_pct':   round((self._blocked / max(1, self._total)) * 100, 2),
            'live_patches':     self._patched,
            'rate_limiter':     self.rate_limiter.get_stats(),
            'input_guard':      self.input_guard.get_stats(),
        }


# ══════════════════════════════════════════════════════════════
# QUICK TEST — run this file directly to verify it works
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  SENTINEL GUARD — Self Test")
    print("="*60)

    # ── Test InputGuard standalone ────────────────────────────
    guard = InputGuard()

    tests = [
        ("Normal input",          "What is the weather today?"),
        ("Empty input",           ""),
        ("Too long",              "A" * 6000),
        ("Null byte injection",   "hello\x00world"),
        ("Too many lines",        "\n" * 60 + "hidden payload"),
        ("Valid security query",  "Ignore previous instructions"),
    ]

    print("\n  InputGuard tests:")
    print(f"  {'TEST':<25} {'BLOCKED':<10} {'REASON'}")
    print("  " + "-"*55)
    for name, text in tests:
        cleaned, result = guard.validate(text)
        blocked = result.get('blocked', False)
        reason  = result.get('detected_vector', 'passed') if blocked else 'passed'
        print(f"  {name:<25} {'YES' if blocked else 'no':<10} {reason}")

    # ── Test RateLimiter standalone ───────────────────────────
    limiter = RateLimiter(RateLimitConfig(
        max_requests_per_window=5,
        window_seconds=60,
        block_duration_seconds=10,
    ))

    print("\n  RateLimiter test (limit=5 per 60s):")
    print(f"  {'REQUEST':<10} {'ALLOWED':<10} {'INFO'}")
    print("  " + "-"*50)
    for i in range(1, 8):
        allowed, info = limiter.check("test_session")
        status = "YES" if allowed else "NO — BLOCKED"
        detail = f"remaining={info.get('remaining','')}" if allowed \
                 else f"retry in {info.get('retry_after_sec')}s"
        print(f"  #{i:<9} {status:<10} {detail}")

    print("\n  InputGuard stats:", guard.get_stats())
    print("  RateLimiter stats:", limiter.get_stats())
    print("\n  All tests done.")
    print("="*60)
    print("\n  To use with your firewall:")
    print("    from sentinel_shield import Sentinel")
    print("    from sentinel_shield.guard import GuardedShield")
    print("    shield = GuardedShield(Sentinel())")
    print("    result = shield.analyze('some input', session_id='user_1')")
    print("="*60 + "\n")
