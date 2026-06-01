import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EVENTS_FILE = os.path.join(BASE_DIR, "events.jsonl")
MODEL_PATH  = os.path.join(BASE_DIR, "model", "ddos_model_final.joblib")

# ── Detection tuning ──────────────────────────────────────────────────────────
ML_THRESHOLD          = 0.70   # overwritten at runtime via /api/config/threshold
WINDOW_SIZE           = 5      # seconds per detection window
MIN_PACKETS           = 20     # ignore windows below this packet count
ATTACK_SCORE_THRESHOLD = 6     # score needed before an IP is treated as attacker
BASE_BLOCK_TIME       = 60     # base seconds to block a confirmed attacker
SCORE_DECAY           = 1      # score points removed per window (cool-down)
STALE_IP_TIMEOUT      = 300    # seconds before an unseen IP is purged from table
SESSION_GAP           = 30     # seconds of silence before a session is closed