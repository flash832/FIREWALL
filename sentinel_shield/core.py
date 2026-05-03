import json
import re
import sys
import unicodedata
import math
import os
import base64
from typing import Dict, Any, List

try:
    from sentence_transformers import SentenceTransformer, util
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

# --- CONFIGURATION & CONSTANTS ---
SENTINEL_VERSION = "3.3.0-STATEFUL-SEMANTIC"
CANARY_TOKENS = ["[SENTINEL_ALPHA_9]", "[REDACTED_SEC_0]"]

# Semantic Intent Scanner - Forbidden Concepts
FORBIDDEN_CONCEPTS = [
    "harmful actions, violence, stealing, and illegal acts.",
    "Bypassing security, hacking, exploiting, and root access.",
    "Deception, malware, ransomware, and spyware.",
    "Data theft, credential harvesting, and keylogging.",
    "instructions on gaining unauthorized entry to a server.",
    "a script that silently records a user's typed keys",
    "how the system's memory can be intentionally overflowed."
]

# Extended "Pune/Mumbai Edge" / Regional detection keywords
REGIONAL_KEYWORDS = [
    # Hinglish - Request/Pleading
    r"mere bhai", r"aap safe ho", r"please bhai", r"arrey yaar", 
    r"bhai ek baar", r"tension mat lo", r"trust me bhai", 
    r"kuch nahi hoga", r"sirf educational hai",
    
    # Marathi - Refusal Suppression
    r"kahi harkat nahi", r"audha chalte", r"jugaad", r"bhau", 
    r"aai chya gavat", r"visay hard hai", r"load nako gheu",
    r"saheb", r"raao", r"kay rao", r"setting lav",
    
    # Emotional/Manipulative
    r"my job depends on this", r"emergency hai", r"urgent hai",
    r"grandmother is dying", r"hospital emergency", r"life or death"
]

# Malicious intent keywords
MALICIOUS_INTENT_KEYWORDS = [
    "poison", "wifi", "admin", "exploit", "hack", "bypass", "override", 
    "jailbreak", "root", "sql injection", "dos attack", "ddos", 
    "credential", "password", "keylogger", "malware", "ransomware"
]

# Common Homoglyph Map (Cyrillic/Greek -> Latin)
HOMOGLYPH_MAP = {
    # Cyrillic to Latin
    u'\u0430': 'a', u'\u0410': 'A', # a
    u'\u0435': 'e', u'\u0415': 'E', # e
    u'\u043e': 'o', u'\u041e': 'O', # o
    u'\u0440': 'p', u'\u0420': 'P', # p
    u'\u0441': 'c', u'\u0421': 'C', # c
    u'\u0443': 'y', u'\u0423': 'Y', # y
    u'\u0445': 'x', u'\u0425': 'X', # x
    u'\u0501': 'd', # d (komi de)
    
    # Greek to Latin
    u'\u03bf': 'o', u'\u039f': 'O', # o
    u'\u03c1': 'p', u'\u03a1': 'P', # p
}

def normalize_leet(text: str) -> str:
    leet_map = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a',
        '5': 's', '6': 'g', '7': 't', '8': 'b',
        '@': 'a', '$': 's', '!': 'i', '+': 't', '#': 'h'
    }
    return ''.join(leet_map.get(c, c) for c in text.lower())

class Sentinel:
    """
    The Sentinel Security Kernel Engine (V3.2-STATEFUL).
    Stateful Analysis for Payload Reconstruction.
    """
    def __init__(self, system_prompt_path: str = None, history_window: int = 3):
        # Determine package directory for asset loading
        self.package_dir = os.path.dirname(os.path.abspath(__file__))
        self._cache = {}
        
        if system_prompt_path is None:
            system_prompt_path = os.path.join(self.package_dir, "sentinel_core.md")
            
        self.system_prompt = self._load_system_prompt(system_prompt_path)
        self.version = SENTINEL_VERSION
        self.history_window = history_window
        self.message_buffer = []
        self.dynamic_rules = self._load_dynamic_rules()

        # Initialize Semantic Intent Scanner
        self.semantic_threshold = 0.25
        self.encoder_model = None
        self.forbidden_embeddings = None
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                # all-MiniLM-L6-v2 is small, fast, and runs well on CPU.
                self.encoder_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.forbidden_embeddings = self.encoder_model.encode(FORBIDDEN_CONCEPTS, convert_to_tensor=True)
            except Exception as e:
                print(f"[Sentinel] Warning: Could not load Semantic Intent Scanner model. {e}")

    def _load_system_prompt(self, filepath: str) -> str:
        try:
            with open(filepath, "r", encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return "[ERROR] System prompt file not found."

    def _load_dynamic_rules(self) -> Dict[str, List[str]]:
        rules_path = os.path.join(self.package_dir, "dynamic_rules.json")
        default_rules = {"patterns": [], "keywords": []}
        try:
            with open(rules_path, "r") as f:
                data = json.load(f)
                # Backward compatibility for old list format
                if isinstance(data, list):
                    return {"patterns": [], "keywords": data}
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            return default_rules

    def _generate_fuzzy_regex(self, keyword: str) -> str:
        """
        Generates a regex pattern that matches the keyword with:
        - Leetspeak substitutions (e.g., a -> [a@4])
        - Optional spaces between chars
        - Case insensitivity (handled by flag)
        """
        leetspeak_map = {
            'a': '[a@4]', 'b': '[b8]', 'e': '[e3]', 'g': '[g9]',
            'i': '[i1!]', 'l': '[l1|]', 'o': '[o0]', 's': '[s5$]',
            't': '[t7+]', 'z': '[z2]'
        }
        
        pattern = ""
        for char in keyword.lower():
            if char in leetspeak_map:
                pattern += leetspeak_map[char]
            elif char.isalnum():
                pattern += re.escape(char)
            else:
                pattern += re.escape(char)
            # Allow flexible spacing between characters
            pattern += r"\s*"
            
        return pattern.strip()

    def _decode_hex(self, text: str) -> str:
        """
        V3.3 Feature: Hex Decoder
        Detects and decodes hex-encoded strings (e.g., \\x70\\x6f\\x69 or pure hex format) 
        to prevent obfuscation.
        """
        decoded_text = text
        # 1. Match explicit python/C hex escapes: \x70\x6f\x69
        hex_escape_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')
        for match in hex_escape_pattern.findall(text):
            try:
                # remove the '\x' and decode as hex
                clean_hex = match.replace('\\x', '')
                decoded = bytes.fromhex(clean_hex).decode('utf-8')
                decoded_text = decoded_text.replace(match, f"{match} {decoded}")
            except Exception:
                continue
                
        # 2. Match continuous hex strings of sufficient length (e.g., 706f69736f6e for 'poison')
        # Requires at least 8 chars (4 bytes) to avoid false positive matching of pure numbers
        hex_continuous_pattern = re.compile(r'\b[0-9a-fA-F]{8,}\b')
        for match in hex_continuous_pattern.findall(text):
            # Only process if length is even
            if len(match) % 2 == 0:
                try:
                    decoded = bytes.fromhex(match).decode('utf-8')
                    # Ensure it decoded into something somewhat readable (not just gibberish bytes)
                    # Simple heuristic: see if it contains any standard alphanumeric chars
                    if any(c.isalnum() for c in decoded):
                         decoded_text = decoded_text.replace(match, f"{match} {decoded}")
                except Exception:
                    continue
                    
        return decoded_text

    def _decode_base64(self, text: str) -> str:
        """
        V3.3 Feature: Base64 Decoder
        Detects and decodes base64 strings to prevent obfuscation.
        """
        decoded_text = text
        # Find potential base64 strings (length >= 8, multiple of 4)
        b64_pattern = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')
        
        for match in b64_pattern.findall(text):
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                # Replace with decoded content alongside the original to keep context
                decoded_text = decoded_text.replace(match, f"{match} {decoded}")
            except Exception:
                continue
                
        # Catch full-string base64 without word boundaries
        try:
            trimmed = text.strip()
            if len(trimmed) >= 8 and len(trimmed) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', trimmed):
                full_decoded = base64.b64decode(trimmed).decode('utf-8')
                if full_decoded not in decoded_text:
                    decoded_text += f" {full_decoded}"
        except Exception:
            pass
            
        return decoded_text

    def reload_rules(self):
        self.dynamic_rules = self._load_dynamic_rules()

    def normalize_input(self, text: str) -> str:
        """
        V3.0 Feature: Advanced Normalization
        - Removes invisible characters (Zero-width spaces, joiners)
        - Normalizes homoglyphs using manual map + NFKD.
        """
        # 1. Remove non-printable / invisible formatting characters (Category: Cf)
        text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
        
        # 2. Manual Homoglyph Substitution (Before NFKD)
        # This fixes specific attacks like "аdmin" (Cyrillic a) -> "admin"
        text = text.translate(str.maketrans(HOMOGLYPH_MAP))
        
        # 3. Normalize unicode (NFKD) to decompose remaining compound characters
        text = unicodedata.normalize("NFKD", text)
        
        return text

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect random gibberish (fuzzing)."""
        if not text:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _check_content(self, text: str) -> Dict[str, Any]:
        """Internal method to run checks on a specific text block."""
        fast_result = self._fast_check(text)
        if fast_result:
            return fast_result
        return self._deep_check(text)

    def _fast_check(self, text: str) -> Dict[str, Any]:
        # 0. PROTOCOL_0: DYNAMIC BLOCKLIST (Learned Rules)
        # Check Patterns (Regex)
        for pattern in self.dynamic_rules.get("patterns", []):
            if re.search(pattern, text, re.IGNORECASE):
                return self._verdict("MALICIOUS", 100, "DynamicBlocklist (Fuzzy)", action="BLOCK")

        # Check Exact Keywords
        for rule in self.dynamic_rules.get("keywords", []):
            if rule in text:
                    return self._verdict("MALICIOUS", 100, "DynamicBlocklist", action="BLOCK")

        # 1. PROTOCOL_2: CANARY TOKEN PROTECTION (Highest Priority)
        for token in CANARY_TOKENS:
            if token in text: 
                return self._verdict("MALICIOUS", 100, "LeakageAttempt", action="BLOCK")
        
        # Check for intent to extract system prompt
        leakage_patterns = [
            r"repeat everything", r"show (your )?instructions", 
            r"list (your )?variables", r"ignore previous instructions",
            r"system prompt", r"initial instructions"
        ]
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in leakage_patterns):
             return self._verdict("MALICIOUS", 100, "LeakageAttempt", action="BLOCK")

        # 2. PROTOCOL_5: HOMOGLYPH & OBFUSCATION PREVENTION
        # Pattern Matching for known Fuzzing signatures
        if re.search(r"[\w\d]+-\d+-!{3,}$", text.strip()):
             return self._verdict("MALICIOUS", 95, "Obfuscation", action="BLOCK")

        # High Entropy Check 
        if len(text) > 20 and self.calculate_entropy(text) > 4.5:
             return self._verdict("MALICIOUS", 90, "Obfuscation", action="BLOCK")

        # 3. PROTOCOL_4: INDIRECT INJECTION & TAG ESCAPE
        if "--- END DATA ---" in text or "</USER_INPUT>" in text:
             return self._verdict("MALICIOUS", 95, "TagEscape", action="BLOCK")
        
        # 4. PROTOCOL_3: REGIONAL & EMOTIONAL COERCION
        is_regional = any(re.search(pattern, text, re.IGNORECASE) for pattern in REGIONAL_KEYWORDS)
        is_malicious_topic = any(keyword in text.lower() for keyword in MALICIOUS_INTENT_KEYWORDS)

        if is_regional:
            if is_malicious_topic:
                 return self._verdict("MALICIOUS", 90, "RegionalStealth", action="BLOCK")
            return self._verdict("SAFE", 50, "RegionalStealth", action="ALLOW") 

        # 5. PROTOCOL_1: PAYLOAD SPLITTING
        if re.search(r"(part|step|phase)\s*\d", text, re.IGNORECASE):
            if is_malicious_topic:
                 return self._verdict("MALICIOUS", 80, "PayloadSplitting", action="STRIP_COMMANDS")

        # 6. PROTOCOL_6: REVERSE LOGIC
        reverse_logic_triggers = [
            r"how (to|do i) (avoid|prevent|stop)", 
            r"what (should|do) i (not|never) do",
            r"tell me how to not",
            r"safety research on"
        ]
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in reverse_logic_triggers):
            if is_malicious_topic:
                 return self._verdict("MALICIOUS", 95, "ReverseLogic", action="BLOCK")

        # 7. GENERAL MALICIOUS INTENT
        if is_malicious_topic:
             return self._verdict("MALICIOUS", 90, "NegativeConstraint", action="BLOCK")

        return None

    def _deep_check(self, text: str) -> Dict[str, Any]:
        if len(text.strip()) < 3:
            return None

        # 8. PROTOCOL_7: SEMANTIC INTENT SCANNER
        if self.encoder_model is not None and self.forbidden_embeddings is not None:
             try:
                 input_embedding = self.encoder_model.encode(text, convert_to_tensor=True)
                 cosine_scores = util.cos_sim(input_embedding, self.forbidden_embeddings)
                 max_score = float(cosine_scores.max())
                 
                 if max_score > self.semantic_threshold:
                     return self._verdict("MALICIOUS", int(max_score * 100), "SemanticIntent", action="BLOCK")
             except Exception as e:
                 # Fail open (allow) if embedding fails to avoid blocking valid traffic
                 pass

        return None # No threat found in this pass

    def analyze(self, user_input: str) -> Dict[str, Any]:
        """
        Public API to analyze input. 
        Maintains a rolling buffer of history to detect split payloads.
        """
        if user_input in self._cache:
            return self._cache[user_input]

        result = self._analyze_internal(user_input)
        self._cache[user_input] = result
        return result

    def _analyze_internal(self, user_input: str) -> Dict[str, Any]:
        user_input = normalize_leet(user_input)
        # 1. Decode payload obfuscations
        decoded_hex = self._decode_hex(user_input)
        decoded_input = self._decode_base64(decoded_hex)
        
        # 2. Normalize Text
        normalized_input = self.normalize_input(decoded_input)
        
        # Update buffer
        self.message_buffer.append(normalized_input)
        if len(self.message_buffer) > self.history_window:
            self.message_buffer.pop(0)
            
        # 1. Check CURRENT input isolated
        result = self._check_content(normalized_input)
        if result: return result

        # Invisible Character Check (Delta check only applicable to raw vs normalized current input)
        if len(decoded_input) - len(normalized_input) > 2:
             return self._verdict("MALICIOUS", 90, "Obfuscation", action="BLOCK")

        # 2. Check CUMULATIVE input (Payload Reconstruction)
        if len(self.message_buffer) > 1:
            cumulative_text = "".join(self.message_buffer) # Join without spaces to catch "p"+"oison"
            cumulative_result = self._check_content(cumulative_text)
            
            if cumulative_result:
                # If the combined text is malicious but the individual parts weren't, 
                # it's a Reconstruction detection.
                cumulative_result['detected_vector'] = "PayloadReconstruction"
                cumulative_result['detected_intent'] = f"Split Payload Detected (Segments: {len(self.message_buffer)})"
                return cumulative_result

        return self._verdict("SAFE", 0, "None", action="ALLOW")

    def _verdict(self, verdict: str, score: int, vector: str, action: str = "ALLOW") -> Dict[str, Any]:
        return {
            "verdict": verdict,
            "threat_score": score,
            "detected_vector": vector,
            "detected_intent": "Automated Classification",
            "action_required": action
        }
