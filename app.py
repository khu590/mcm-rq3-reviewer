import streamlit as st
import json
import os
import glob
from datetime import datetime
import gspread
from google.oauth2.service_account import Credentials
from google.auth.exceptions import GoogleAuthError
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

st.set_page_config(
    page_title="VulnScan RQ3 Reviewer",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600;700&display=swap');

:root {
  --bg: #050b14;
  --surface: #0d1623;
  --surface2: #141f2e;
  --border: #1a2d42;
  --accent: #00e5ff;
  --accent2: #6c63ff;
  --safe: #00c896;
  --danger: #ff4b6e;
  --warn: #ffaa00;
  --text: #dde6f0;
  --muted: #5a7494;
  --code: #0a1628;
}

* { margin:0; padding:0; box-sizing:border-box; }
html, body, .stApp { background:var(--bg) !important; color:var(--text); font-family:'DM Sans',sans-serif; }

/* Hide Streamlit chrome */
#MainMenu, footer, header { visibility:hidden; }
.stDeployButton { display:none; }
.block-container { padding:0 !important; max-width:100% !important; }

/* Custom scrollbar */
::-webkit-scrollbar { width:4px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

/* Top bar */
.topbar {
  background:var(--surface);
  border-bottom:1px solid var(--border);
  padding:14px 32px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  position:sticky; top:0; z-index:100;
}
.brand { display:flex; align-items:center; gap:12px; }
.brand-icon {
  width:36px; height:36px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  border-radius:8px;
  display:flex; align-items:center; justify-content:center;
  font-size:16px; font-weight:700; color:#000;
}
.brand-name { font-family:'Space Mono',monospace; font-size:16px; font-weight:700; letter-spacing:-0.5px; }
.brand-name span { color:var(--accent); }
.top-meta { font-family:'Space Mono',monospace; font-size:10px; color:var(--muted); letter-spacing:1px; }

/* Page layout */
.page { padding:24px 32px; }

/* Hero section */
.hero {
  background:linear-gradient(135deg, var(--surface) 0%, #0a1628 100%);
  border:1px solid var(--border);
  border-radius:16px;
  padding:28px 32px;
  margin-bottom:24px;
  position:relative;
  overflow:hidden;
}
.hero::before {
  content:'';
  position:absolute; top:-50%; right:-10%;
  width:400px; height:400px;
  background:radial-gradient(circle, rgba(0,229,255,0.04) 0%, transparent 70%);
  pointer-events:none;
}
.hero-title { font-size:22px; font-weight:700; color:var(--text); margin-bottom:6px; }
.hero-sub { font-size:13px; color:var(--muted); line-height:1.6; }
.hero-tags { display:flex; gap:8px; margin-top:12px; flex-wrap:wrap; }
.tag {
  background:rgba(0,229,255,0.08);
  border:1px solid rgba(0,229,255,0.2);
  color:var(--accent);
  font-family:'Space Mono',monospace;
  font-size:10px; padding:4px 10px; border-radius:20px; letter-spacing:0.5px;
}

/* Cards */
.card {
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:12px;
  overflow:hidden;
  margin-bottom:16px;
}
.card-header {
  background:var(--surface2);
  border-bottom:1px solid var(--border);
  padding:10px 16px;
  display:flex; align-items:center; justify-content:space-between;
}
.card-title { font-family:'Space Mono',monospace; font-size:10px; font-weight:700; letter-spacing:1.5px; text-transform:uppercase; color:var(--muted); }
.card-body { padding:16px; }

/* Badges */
.badge-vuln { background:#ff4b6e18; border:1px solid #ff4b6e44; color:#ff4b6e; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; font-family:'Space Mono',monospace; }
.badge-safe { background:#00c89618; border:1px solid #00c89644; color:#00c896; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; font-family:'Space Mono',monospace; }
.badge-info { background:rgba(0,229,255,0.1); border:1px solid rgba(0,229,255,0.25); color:var(--accent); padding:3px 10px; border-radius:20px; font-size:11px; font-family:'Space Mono',monospace; }

/* Progress */
.progress-wrap { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:14px 20px; margin-bottom:20px; }
.progress-track { background:var(--border); border-radius:6px; height:6px; margin:8px 0; overflow:hidden; }
.progress-fill { background:linear-gradient(90deg,var(--accent),var(--accent2)); height:100%; border-radius:6px; transition:width 0.5s ease; }
.progress-label { display:flex; justify-content:space-between; font-size:12px; color:var(--muted); }

/* Sample grid */
.sample-grid { display:flex; gap:6px; flex-wrap:wrap; margin-top:10px; }
.sample-dot {
  width:28px; height:28px; border-radius:6px;
  border:1px solid var(--border);
  display:flex; align-items:center; justify-content:center;
  font-size:9px; font-family:'Space Mono',monospace;
  color:var(--muted); cursor:pointer; transition:all 0.2s;
}
.sample-dot.rated { background:#00c89618; border-color:#00c89644; color:#00c896; }
.sample-dot.current { background:rgba(0,229,255,0.15); border-color:var(--accent); color:var(--accent); }

/* Explanation sections */
.exp-section { border-radius:8px; padding:12px 14px; margin-bottom:10px; font-size:13px; line-height:1.7; }
.exp-main { background:rgba(0,229,255,0.05); border-left:3px solid var(--accent); }
.exp-risk { background:rgba(255,75,110,0.05); border-left:3px solid var(--danger); }
.exp-fix { background:rgba(0,200,150,0.05); border-left:3px solid var(--safe); }
.exp-label { font-size:9px; font-weight:700; letter-spacing:2px; text-transform:uppercase; opacity:0.5; margin-bottom:5px; font-family:'Space Mono',monospace; }

/* Token pills */
.token-row { display:flex; flex-wrap:wrap; gap:5px; margin-top:8px; }
.tok { background:rgba(108,99,255,0.12); border:1px solid rgba(108,99,255,0.25); color:#9990ff; font-family:'Space Mono',monospace; font-size:10px; padding:2px 8px; border-radius:4px; }

/* Rating section */
.rating-box { background:var(--surface2); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:12px; }
.rating-title { font-size:11px; font-weight:600; letter-spacing:0.5px; margin-bottom:10px; color:var(--text); }

/* Nav buttons */
.nav-row { display:flex; gap:10px; margin-top:16px; }

/* Info box */
.info-box { background:rgba(0,229,255,0.05); border:1px solid rgba(0,229,255,0.15); border-radius:8px; padding:12px 14px; font-size:12px; color:var(--text); line-height:1.6; margin-bottom:16px; }
.info-box strong { color:var(--accent); }

/* Rubric table */
.rubric { width:100%; border-collapse:collapse; font-size:12px; margin-top:8px; }
.rubric th { background:var(--surface2); padding:8px 10px; text-align:left; color:var(--muted); font-weight:600; font-size:10px; letter-spacing:1px; text-transform:uppercase; border-bottom:1px solid var(--border); }
.rubric td { padding:8px 10px; border-bottom:1px solid rgba(26,45,66,0.5); vertical-align:top; }
.rubric tr:last-child td { border-bottom:none; }

/* Code test area */
.code-test-wrap { background:var(--code); border:1px solid var(--border); border-radius:8px; overflow:hidden; }

/* Summary card */
.summary-stat { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:14px; text-align:center; }
.summary-num { font-size:28px; font-weight:700; font-family:'Space Mono',monospace; }
.summary-label { font-size:11px; color:var(--muted); margin-top:3px; }

/* Streamlit overrides */
div[data-testid="stNumberInput"] input { background:var(--code) !important; border:1px solid var(--border) !important; color:var(--text) !important; border-radius:8px !important; font-family:'Space Mono',monospace !important; }
div[data-testid="stTextInput"] input { background:var(--code) !important; border:1px solid var(--border) !important; color:var(--text) !important; border-radius:8px !important; }
div[data-testid="stSelectbox"] select { background:var(--code) !important; }
div[data-testid="stTextArea"] textarea { background:var(--code) !important; border:1px solid var(--border) !important; color:var(--text) !important; border-radius:8px !important; font-family:'Space Mono',monospace !important; font-size:12px !important; }
div[data-testid="stSlider"] { }
.stButton button {
  background:var(--surface2) !important;
  border:1px solid var(--border) !important;
  color:var(--text) !important;
  border-radius:8px !important;
  font-family:'DM Sans',sans-serif !important;
  font-weight:600 !important;
  transition:all 0.2s !important;
}
.stButton button:hover { border-color:var(--accent) !important; color:var(--accent) !important; }
div[data-testid="stExpander"] { background:var(--surface) !important; border:1px solid var(--border) !important; border-radius:10px !important; }

/* --- Visual polish (cosmetic only; rating controls stay neutral) --- */
@keyframes gradShift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
@keyframes dotPulse { 0%,100%{box-shadow:0 0 0 0 rgba(0,229,255,0.35)} 50%{box-shadow:0 0 0 6px rgba(0,229,255,0)} }
@keyframes barGlow { 0%,100%{box-shadow:0 0 6px rgba(0,229,255,0.35)} 50%{box-shadow:0 0 16px rgba(108,99,255,0.6)} }

.stApp {
  background-image:
    linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px) !important;
  background-size:38px 38px !important;
}
.hero-title {
  background:linear-gradient(90deg, var(--text) 0%, var(--accent) 35%, var(--accent2) 65%, var(--text) 100%);
  background-size:250% auto;
  -webkit-background-clip:text; background-clip:text;
  -webkit-text-fill-color:transparent;
  animation:gradShift 8s ease infinite;
}
.sample-dot.current { animation:dotPulse 1.6s ease-in-out infinite; }
.progress-fill { background-size:200% auto; animation:gradShift 4s linear infinite, barGlow 2.5s ease-in-out infinite; }
.tok { transition:all 0.15s ease; cursor:default; }
.tok:hover { transform:translateY(-2px) scale(1.08); background:rgba(108,99,255,0.3); color:#c9c4ff; border-color:#9990ff; }
.card { transition:border-color 0.25s ease; }
.card:hover { border-color:rgba(0,229,255,0.3); }
.term-dots { display:flex; gap:5px; }
.term-dots span { width:10px; height:10px; border-radius:50%; display:inline-block; }
.term-dots .r { background:#ff5f57; } .term-dots .y { background:#febc2e; } .term-dots .g { background:#28c840; }
</style>
""", unsafe_allow_html=True)

# ----------------------------------------------------------------
# Data
# ----------------------------------------------------------------

SAMPLES = [
    {"id":"CWE121_v1","cwe":"CWE-121","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void read_input(char *src) {\n    char dest[16];\n    strcpy(dest, src);\n    printf(\"%s\", dest);\n}",
     "pred_cwe":"CWE-120: Buffer Copy without Checking Size of Input",
     "explanation":"The `strcpy` function copies from `src` into `dest` (fixed 16 bytes) with no bounds checking. Any input longer than 15 characters overflows the buffer.",
     "risk":"Attacker provides a long string to overwrite adjacent stack memory, enabling control-flow manipulation or arbitrary code execution.",
     "fix":"Replace `strcpy` with `snprintf(dest, sizeof(dest), \"%s\", src)` to enforce bounds.",
     "tokens":["strcpy","dest","16","src","char"]},
    {"id":"CWE121_v2","cwe":"CWE-121","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void process(char *data) {\n    char buf[8];\n    gets(buf);\n    return;\n}",
     "pred_cwe":"CWE-120: Buffer Copy without Checking Size of Input",
     "explanation":"The `gets()` function reads into `buf` (8 bytes) with no limit. Any input longer than 7 characters overflows the buffer. `gets` is removed from C11 for this reason.",
     "risk":"Attacker provides input exceeding 7 chars to overwrite stack memory, enabling denial-of-service or arbitrary code execution.",
     "fix":"Replace `gets(buf)` with `fgets(buf, sizeof(buf), stdin)` which enforces the size limit.",
     "tokens":["gets","buf","8","char"]},
    {"id":"CWE121_v3","cwe":"CWE-121","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void concat(char *s1, char *s2) {\n    char result[20];\n    strcpy(result, s1);\n    strcat(result, s2);\n}",
     "pred_cwe":"CWE-120: Buffer Copy without Checking Size of Input",
     "explanation":"Both `strcpy` and `strcat` write into `result` (20 bytes) without bounds checking. If s1+s2 combined length exceeds 19 chars, the buffer overflows.",
     "risk":"Attacker controls s1 or s2 to overflow result, corrupting stack and potentially achieving code execution.",
     "fix":"Use `snprintf(result, sizeof(result), \"%s%s\", s1, s2)` to limit total output to buffer size.",
     "tokens":["strcpy","strcat","result","20","char"]},
    {"id":"CWE121_s1","cwe":"CWE-121","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void read_safe(char *src) {\n    char dest[16];\n    strncpy(dest, src, sizeof(dest)-1);\n    dest[sizeof(dest)-1] = '\\0';\n}",
     "pred_cwe":"CWE-476: NULL Pointer Dereference",
     "explanation":"strncpy is used with sizeof(dest)-1 to prevent overflow, and null-termination is explicitly set. The explanation notes src is not checked for NULL before use.",
     "risk":"Limited — if src is NULL, strncpy dereferences it causing a crash. Otherwise the buffer handling is correct.",
     "fix":"Add NULL check: `if (!src) return;` before strncpy.",
     "tokens":["strncpy","sizeof","dest","16","src"]},
    {"id":"CWE121_s2","cwe":"CWE-121","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void read_line(FILE *fp) {\n    char buf[64];\n    if (fgets(buf, sizeof(buf), fp) != NULL)\n        printf(\"%s\", buf);\n}",
     "pred_cwe":"CWE-120: Buffer Copy without Checking Size of Input",
     "explanation":"fgets with sizeof(buf) correctly limits reads to 63 chars + null terminator. The NULL check before printf is safe. This code has no buffer overflow vulnerability.",
     "risk":"N/A — code is safe.",
     "fix":"N/A — no fix required.",
     "tokens":["fgets","sizeof","buf","64","NULL"]},
    {"id":"CWE78_v1","cwe":"CWE-78","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void run_cmd(char *input) {\n    char cmd[256];\n    sprintf(cmd, \"ping %s\", input);\n    system(cmd);\n}",
     "pred_cwe":"CWE-78: OS Command Injection",
     "explanation":"User-controlled `input` is embedded directly into a shell command via sprintf, then executed by system(). Shell metacharacters in input execute as arbitrary commands.",
     "risk":"Attacker provides `; rm -rf /` or similar, executing arbitrary shell commands with the process's privileges.",
     "fix":"Use execl(\"/bin/ping\", \"ping\", input, NULL) instead of system(), or strictly whitelist input to contain only valid hostname characters.",
     "tokens":["system","sprintf","input","cmd","ping"]},
    {"id":"CWE78_v2","cwe":"CWE-78","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void execute(char *arg) {\n    char buf[128];\n    strcpy(buf, arg);\n    system(buf);\n}",
     "pred_cwe":"CWE-78: OS Command Injection",
     "explanation":"strcpy copies user input into buf (buffer overflow risk), then system() executes it. Both CWE-120 and CWE-78 are present simultaneously.",
     "risk":"Attacker can both overflow the buffer and inject shell commands, enabling stack corruption and arbitrary command execution.",
     "fix":"Use strncpy for safe copy and execve() instead of system() to prevent shell interpretation.",
     "tokens":["system","strcpy","buf","128","arg"]},
    {"id":"CWE78_v3","cwe":"CWE-78","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"int run(char *cmd) {\n    return system(cmd);\n}",
     "pred_cwe":"CWE-78: OS Command Injection",
     "explanation":"Directly passes user-controlled cmd to system() with no sanitization. Any shell metacharacter in cmd enables arbitrary command injection.",
     "risk":"Complete command injection — attacker executes arbitrary commands with process privileges.",
     "fix":"Replace with execvp() using explicit argument arrays, or rigorously validate and escape all shell metacharacters.",
     "tokens":["system","cmd","char","return"]},
    {"id":"CWE78_s1","cwe":"CWE-78","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void run_fixed(const char *file) {\n    const char *args[] = {\"/bin/ping\",\"-c\",\"1\",file,NULL};\n    execv(\"/bin/ping\",(char *const *)args);\n}",
     "pred_cwe":"CWE-78: OS Command Injection",
     "explanation":"execv() is used instead of system(), preventing shell interpretation. file is passed as a direct argument to ping, not through a shell. Classic injection is prevented.",
     "risk":"Only argument injection to ping itself is a concern (e.g., option injection via leading hyphens), not shell injection.",
     "fix":"Whitelist file to valid hostname/IP characters to prevent ping argument injection.",
     "tokens":["execv","args","file","ping","const"]},
    {"id":"CWE78_s2","cwe":"CWE-78","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void log_event(const char *type) {\n    const char *ok[] = {\"login\",\"logout\",\"error\"};\n    for (int i=0;i<3;i++)\n        if (!strcmp(type,ok[i])) { printf(\"%s\\n\",type); return; }\n}",
     "pred_cwe":"CWE-778: Insufficient Logging",
     "explanation":"Input is whitelisted against three allowed values before use. No shell command is executed. The explanation identifies insufficient logging (unrecognized types are silently ignored) rather than command injection.",
     "risk":"Unrecognized event types are not logged, hindering audit trails. No command injection risk.",
     "fix":"Add logging for unrecognized types after the loop.",
     "tokens":["strcmp","ok","return","log","type"]},
    {"id":"CWE190_v1","cwe":"CWE-190","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void alloc(int count) {\n    int size = count * sizeof(int);\n    int *data = malloc(size);\n    memset(data,0,size);\n}",
     "pred_cwe":"CWE-131: Incorrect Calculation of Buffer Size",
     "explanation":"count * sizeof(int) can overflow if count is large, producing a small size. malloc return is unchecked, so memset dereferences NULL on allocation failure.",
     "risk":"Attacker provides large count causing overflow → undersized allocation → heap overflow in subsequent write. Or NULL deref crash.",
     "fix":"Validate count, check overflow before multiply, check malloc return before memset.",
     "tokens":["malloc","count","sizeof","memset","int"]},
    {"id":"CWE190_v2","cwe":"CWE-190","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"short increment(short val) {\n    return val + 1;\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"When val equals SHRT_MAX (32767), adding 1 causes signed integer overflow, wrapping to -32768. This is undefined behavior in C.",
     "risk":"If result feeds into array indexing or allocation, negative value causes out-of-bounds access or logic errors.",
     "fix":"Check before increment: `if (val == SHRT_MAX) { handle_overflow(); }`",
     "tokens":["short","val","return","increment"]},
    {"id":"CWE190_v3","cwe":"CWE-190","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"int compute(unsigned int a, unsigned int b) {\n    return (int)(a + b);\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"unsigned int addition wraps modulo 2^32. Casting the wrapped result to int can produce a negative value if the sum exceeds INT_MAX.",
     "risk":"Negative result used in allocation or array indexing causes buffer overflow or out-of-bounds access.",
     "fix":"Check `if (a > (unsigned)INT_MAX - b)` before adding, or change return type to unsigned int.",
     "tokens":["unsigned","int","return","compute"]},
    {"id":"CWE190_s1","cwe":"CWE-190","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void alloc_safe(int count) {\n    if (count<=0||count>1000000) return;\n    size_t size=(size_t)count*sizeof(int);\n    int *data=malloc(size);\n    if (!data) return;\n    free(data);\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"Cast to size_t before multiplication prevents overflow. Input is validated. malloc return is checked. Memory is freed. This is a correct safe implementation.",
     "risk":"N/A — code is safe.",
     "fix":"N/A — no fix required.",
     "tokens":["size_t","count","malloc","free","if"]},
    {"id":"CWE190_s2","cwe":"CWE-190","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"int safe_add(int a, int b) {\n    if ((b>0&&a>INT_MAX-b)||(b<0&&a<INT_MIN-b)) return -1;\n    return a+b;\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"Explicit pre-condition checks prevent both overflow (b>0) and underflow (b<0) before addition. This is a standard safe integer addition pattern.",
     "risk":"N/A — code is safe.",
     "fix":"N/A — no fix required.",
     "tokens":["INT_MAX","INT_MIN","if","return","safe"]},
    {"id":"CWE191_v1","cwe":"CWE-191","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"unsigned int decrement(unsigned int val) {\n    return val - 1;\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"When val is 0, subtracting 1 from an unsigned int wraps to UINT_MAX. The explanation correctly identifies this as integer underflow.",
     "risk":"Wrapped value used in allocation or indexing causes oversized allocation or out-of-bounds memory access.",
     "fix":"`return (val == 0) ? 0 : val - 1;`",
     "tokens":["unsigned","val","return","decrement"]},
    {"id":"CWE191_v2","cwe":"CWE-191","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void process(unsigned int len) {\n    unsigned int adj = len - 10;\n    char *buf = malloc(adj);\n    memset(buf,0,adj);\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"If len < 10, adj underflows to a huge number. malloc likely fails and returns NULL. memset then crashes on the NULL pointer dereference.",
     "risk":"Attacker provides len < 10 to trigger crash (denial of service) or unexpected huge allocation.",
     "fix":"Add `if (len < 10) return;` and check malloc return before memset.",
     "tokens":["unsigned","len","10","malloc","memset"]},
    {"id":"CWE191_v3","cwe":"CWE-191","expected":"VULNERABLE","model_pred":"VULNERABLE","conf":99.99,
     "code":"int subtract(int a, int b) {\n    return a - b;\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"This function is not inherently vulnerable in isolation. The explanation notes that vulnerability depends on how inputs are supplied and result is used. No definitive issue can be confirmed without context.",
     "risk":"N/A in isolation — context-dependent.",
     "fix":"Validate inputs if extreme values are expected in the caller.",
     "tokens":["subtract","return","int","a","b"]},
    {"id":"CWE191_s1","cwe":"CWE-191","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"unsigned int safe_dec(unsigned int val) {\n    if (val==0) return 0;\n    return val-1;\n}",
     "pred_cwe":"CWE-190: Integer Overflow or Wraparound",
     "explanation":"Explicit zero check before decrement correctly prevents unsigned wraparound. This is the safe pattern for unsigned decrement.",
     "risk":"N/A — code is safe.",
     "fix":"N/A — no fix required.",
     "tokens":["if","val","0","return","unsigned"]},
    {"id":"CWE191_s2","cwe":"CWE-191","expected":"SAFE","model_pred":"VULNERABLE","conf":99.99,
     "code":"void process_safe(unsigned int len) {\n    if (len<10) return;\n    unsigned int adj=len-10;\n    char *buf=malloc(adj+1);\n    if (!buf) return;\n    free(buf);\n}",
     "pred_cwe":"CWE-191: Integer Underflow",
     "explanation":"Guard `if (len < 10) return` ensures len >= 10 before subtraction, preventing underflow. malloc return is checked, memory is freed. Safe implementation.",
     "risk":"N/A — code is safe.",
     "fix":"N/A — no fix required.",
     "tokens":["if","len","10","malloc","free"]},
]

# ----------------------------------------------------------------
# Persistence — Google Sheets (service account)
# ----------------------------------------------------------------

SPREADSHEET_ID = "11tq2jk4qRVbEih-8KmgkQvXy-S0dKp8izKdy0FMjGe0"
WORKSHEET_NAME = "ratings_v2"
SHEET_COLUMNS = ["key", "reviewer_id", "sample_id", "correctness", "usefulness",
                 "model_prediction_correct", "comments", "timestamp"]
CREDENTIALS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODEBERT_CHECKPOINT = os.path.join(REPO_ROOT, "experiments", "codebert-test", "checkpoint-1000")
CODEBERT_CHECKPOINT_HF_REPO = "Khushi81/codebert-juliet-rq3-demo"


@st.cache_resource(show_spinner="Loading CodeBERT checkpoint...")
def _load_codebert():
    """Loads the debug-scale CodeBERT checkpoint. This predates the paper's leakage fix and
    label fix (Section III-A7) -- it is the same checkpoint used for the out-of-distribution
    evaluation in Section V-C, not the final corrected model behind Table VII. Kept for
    live-demo purposes; results here should not be read as the paper's controlled numbers.

    experiments/ is gitignored (large training artefacts), so the checkpoint is not present
    on a fresh clone (e.g. Streamlit Cloud). Prefer the local copy if present (local dev,
    no network needed); otherwise pull the inference-only files (config.json,
    model.safetensors) from the mirrored Hugging Face Hub repo.
    """
    source = CODEBERT_CHECKPOINT if os.path.isdir(CODEBERT_CHECKPOINT) else CODEBERT_CHECKPOINT_HF_REPO
    try:
        tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        model = AutoModelForSequenceClassification.from_pretrained(source, output_attentions=True)
    except Exception:
        return None, None
    model.eval()
    return tokenizer, model


def run_codebert_inference(code_text):
    """Real CodeBERT inference + attention-based evidence tokens, same extraction as
    Section IV-A: final-layer CLS-attention row, averaged across heads, top-10 tokens."""
    tokenizer, model = _load_codebert()
    if tokenizer is None:
        return None
    inputs = tokenizer(code_text, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        out = model(**inputs)
    probs = torch.softmax(out.logits, dim=-1)[0]
    pred_idx = int(torch.argmax(probs))
    label = "VULNERABLE" if pred_idx == 1 else "SAFE"
    confidence = float(probs[pred_idx])

    attentions = out.attentions[-1][0]  # last layer, shape (heads, seq, seq)
    cls_attn = attentions[:, 0, :].mean(dim=0)  # average heads, CLS row
    tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])
    scored = [
        (tok.replace("Ġ", ""), score.item())
        for tok, score in zip(tokens, cls_attn)
        if tok not in ("<s>", "</s>", "<pad>") and len(tok.strip("Ġ")) > 1
    ]
    scored.sort(key=lambda x: -x[1])
    top_tokens = [t for t, _ in scored[:10]]

    return {"label": label, "confidence": confidence, "tokens": top_tokens}


def _load_credentials():
    """Prefer Streamlit Cloud secrets; fall back to a local credentials/*.json for dev."""
    try:
        if "gcp_service_account" in st.secrets:
            info = dict(st.secrets["gcp_service_account"])
            return Credentials.from_service_account_info(
                info, scopes=["https://www.googleapis.com/auth/spreadsheets"]
            )
    except (FileNotFoundError, KeyError):
        pass

    cred_files = glob.glob(os.path.join(CREDENTIALS_DIR, "*.json"))
    if not cred_files:
        raise FileNotFoundError(
            "No Google credentials found. Add a [gcp_service_account] entry to "
            "Streamlit secrets, or place a service-account JSON file in "
            f"{CREDENTIALS_DIR} for local development."
        )
    return Credentials.from_service_account_file(
        cred_files[0], scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )


@st.cache_resource(show_spinner=False)
def _get_worksheet():
    creds = _load_credentials()
    gc = gspread.authorize(creds)
    sheet_id = st.secrets.get("sheet_id", SPREADSHEET_ID) if hasattr(st, "secrets") else SPREADSHEET_ID
    sh = gc.open_by_key(sheet_id)
    try:
        ws = sh.worksheet(WORKSHEET_NAME)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=WORKSHEET_NAME, rows=2000, cols=len(SHEET_COLUMNS))
        ws.append_row(SHEET_COLUMNS)
    return ws


@st.cache_data(ttl=15, show_spinner=False)
def _load_ratings():
    try:
        ws = _get_worksheet()
        records = ws.get_all_records()
    except (FileNotFoundError, GoogleAuthError, gspread.exceptions.APIError) as e:
        st.error(f"Could not load ratings from Google Sheets: {e}")
        return {}
    ratings = {}
    for r in records:
        key = r.get("key")
        if not key:
            continue
        try:
            ratings[key] = {
                "reviewer_id": r["reviewer_id"],
                "sample_id": r["sample_id"],
                "correctness": int(r["correctness"]),
                "usefulness": int(r["usefulness"]),
                "model_prediction_correct": r["model_prediction_correct"],
                "comments": r["comments"],
                "timestamp": r["timestamp"],
            }
        except (KeyError, ValueError):
            continue
    return ratings


def save_rating(reviewer_id, sample_id, correctness, usefulness, pred_correct, comments):
    key = f"{reviewer_id}__{sample_id}"
    row = [key, reviewer_id, sample_id, correctness, usefulness, pred_correct,
           comments, datetime.now().isoformat()]
    try:
        ws = _get_worksheet()
        cell = ws.find(key, in_column=1)
        if cell:
            ws.update(f"A{cell.row}:H{cell.row}", [row])
        else:
            ws.append_row(row)
    except (FileNotFoundError, GoogleAuthError, gspread.exceptions.APIError) as e:
        st.error(f"Could not save rating to Google Sheets: {e}")
        return False
    _load_ratings.clear()
    return True

def get_all_ratings():
    return list(_load_ratings().values())

def get_reviewer_ratings(reviewer_id):
    return {k: v for k, v in _load_ratings().items() if k.startswith(reviewer_id + "__")}

def get_existing(reviewer_id, sample_id):
    return _load_ratings().get(f"{reviewer_id}__{sample_id}", {})

# ----------------------------------------------------------------
# Header
# ----------------------------------------------------------------

st.markdown("""
<div class="topbar">
  <div class="brand">
    <div class="brand-icon">VS</div>
    <div class="brand-name">Vuln<span>Scan</span> &nbsp;·&nbsp; RQ3 Reviewer</div>
  </div>
  <div class="top-meta">DCU MSc PRACTICUM 2026 &nbsp;·&nbsp; ACADEMIC USE ONLY</div>
</div>
<div class="page">
""", unsafe_allow_html=True)

# ----------------------------------------------------------------
# Tabs
# ----------------------------------------------------------------

tab1, tab2, tab3 = st.tabs(["📋 Rate Explanations", "🧪 Test Your Own Code", "📊 Results & Report"])


# ================================================================
# TAB 2 — TEST YOUR OWN CODE
# ================================================================
with tab2:
    st.markdown("""
    <div class="hero">
      <div class="hero-title">Test Your Own Code — Real CodeBERT Inference</div>
      <div class="hero-sub">
        Paste a C/C++ function below and it is run through the actual trained CodeBERT
        model, not a rule-based approximation. This is the same model class used
        throughout the paper, so it will reproduce the paper's own finding: it can
        misclassify safe code, and its attention tokens may not reflect what actually
        drove the prediction (Section V-D).
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box">
      <strong>Checkpoint used:</strong> <code>experiments/codebert-test/checkpoint-1000</code>
      (mirrored on the Hugging Face Hub at
      <a href="https://huggingface.co/Khushi81/codebert-juliet-rq3-demo" target="_blank">Khushi81/codebert-juliet-rq3-demo</a>
      for this live demo, since the original training artefacts aren't tracked in git)
      — a debug-scale checkpoint trained on 4,000 samples, predating the paper's label fix
      and leakage fix (Section III-A7). This is the <em>same</em> checkpoint used for the
      out-of-distribution evaluation in Section V-C. It is <strong>not</strong> the final,
      corrected model behind Table VII's controlled numbers — no such checkpoint is
      currently saved locally (Section VI's checkpoint corroboration gap). Predictions
      here demonstrate real model behaviour, not this paper's headline result.
    </div>
    """, unsafe_allow_html=True)

    lang_choice = st.selectbox(
        "Language",
        ["C / C++", "Java (no trained checkpoint available)"],
        key="user_code_lang",
    )

    code_input = st.text_area(
        "Paste your code here",
        height=200,
        placeholder="void example(char *input) {\n    char buf[32];\n    strcpy(buf, input);  // unsafe\n}",
        key="user_code"
    )

    if st.button("🔍 Run CodeBERT Inference", type="primary"):
        if lang_choice.startswith("Java"):
            st.warning(
                "No Java-trained checkpoint exists in this project yet (Section V-E "
                "reports Java/C# transformer results as pending checkpoint recovery). "
                "Running a C/C++-trained model on Java code would not be a meaningful "
                "test, so this is disabled rather than silently giving you a wrong answer."
            )
        elif code_input.strip():
            result = run_codebert_inference(code_input)
            if result is None:
                st.error(
                    f"Could not load the CodeBERT checkpoint from either the local path "
                    f"(`{CODEBERT_CHECKPOINT}`) or the mirrored Hugging Face Hub repo "
                    f"(`{CODEBERT_CHECKPOINT_HF_REPO}`). This is likely a transient network "
                    "issue fetching the Hub copy — try again in a moment."
                )
            else:
                is_vuln = result["label"] == "VULNERABLE"
                col1, col2 = st.columns(2)
                with col1:
                    badge = '<span class="badge-vuln">VULNERABLE</span>' if is_vuln else '<span class="badge-safe">SAFE</span>'
                    st.markdown(f"**Prediction:** {badge}", unsafe_allow_html=True)
                with col2:
                    st.markdown(f"**Confidence:** `{result['confidence']*100:.2f}%`")

                tokens_html = "".join([f'<span class="tok">{t}</span>' for t in result["tokens"]])
                st.markdown(f"""
                <div style="margin-top:12px;">
                  <div style="font-size:10px;color:var(--muted);margin-bottom:6px;letter-spacing:1px;">ATTENTION TOKENS (what the model focused on)</div>
                  <div class="token-row">{tokens_html}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("---")
                st.markdown("""
                **Reading this result:** a VULNERABLE prediction on safe-looking code, or
                attention tokens on punctuation/formatting rather than the risky API call,
                is not a bug in this demo — it reproduces the paper's own finding
                (Section V-C, Section V-D) that this model class relies on surface tokens
                rather than genuine code understanding.
                """)
        else:
            st.warning("Please paste some code first.")

# ================================================================
# TAB 3 — RESULTS & REPORT
# ================================================================
with tab3:
    st.markdown("""
    <div class="hero">
      <div class="hero-title">Results & Evaluation Report</div>
      <div class="hero-sub">
        Summary of all reviewer ratings collected so far.
        Download the full dataset for inter-rater agreement (Fleiss' kappa) analysis.
      </div>
    </div>
    """, unsafe_allow_html=True)

    all_ratings = get_all_ratings()

    if not all_ratings:
        st.info("No ratings collected yet. Reviewers need to complete their evaluations first.")
    else:
        reviewers = list(set(r['reviewer_id'] for r in all_ratings))
        total = len(all_ratings)
        avg_cor = sum(r['correctness'] for r in all_ratings) / total
        avg_use = sum(r['usefulness'] for r in all_ratings) / total

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f'<div class="summary-stat"><div class="summary-num" style="color:var(--accent)">{total}</div><div class="summary-label">Total Ratings</div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="summary-stat"><div class="summary-num" style="color:var(--accent2)">{len(reviewers)}</div><div class="summary-label">Reviewers</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="summary-stat"><div class="summary-num" style="color:var(--safe)">{avg_cor:.1f}/5</div><div class="summary-label">Avg Correctness</div></div>', unsafe_allow_html=True)
        with c4:
            st.markdown(f'<div class="summary-stat"><div class="summary-num" style="color:var(--warn)">{avg_use:.1f}/5</div><div class="summary-label">Avg Usefulness</div></div>', unsafe_allow_html=True)

        st.markdown("---")

        # Per reviewer
        st.markdown("### Per Reviewer Summary")
        for rev in reviewers:
            rev_ratings = [r for r in all_ratings if r['reviewer_id'] == rev]
            rc = sum(r['correctness'] for r in rev_ratings) / len(rev_ratings)
            ru = sum(r['usefulness'] for r in rev_ratings) / len(rev_ratings)
            st.markdown(f"**{rev}** — {len(rev_ratings)}/20 rated | Avg Correctness: {rc:.1f} | Avg Usefulness: {ru:.1f}")

        # Per sample
        st.markdown("### Per Sample Summary")
        sample_data = []
        for s in SAMPLES:
            s_ratings = [r for r in all_ratings if r['sample_id'] == s['id']]
            if s_ratings:
                ac = sum(r['correctness'] for r in s_ratings) / len(s_ratings)
                au = sum(r['usefulness'] for r in s_ratings) / len(s_ratings)
                sample_data.append({
                    "Sample": s['id'],
                    "Expected": s['expected'],
                    "Model": s['model_pred'],
                    "Ratings": len(s_ratings),
                    "Avg Correctness": round(ac, 1),
                    "Avg Usefulness": round(au, 1)
                })

        if sample_data:
            import pandas as pd
            df = pd.DataFrame(sample_data)
            st.dataframe(df, use_container_width=True)

        st.markdown("---")
        st.markdown("### Download Full Dataset")
        st.markdown("Download all ratings as JSON for Fleiss' kappa calculation and dissertation reporting.")

        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "📥 Download Ratings JSON",
                data=json.dumps(all_ratings, indent=2),
                file_name=f"rq3_ratings_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                use_container_width=True
            )
        with col2:
            if all_ratings:
                try:
                    import pandas as pd
                    df_full = pd.DataFrame(all_ratings)
                    st.download_button(
                        "📥 Download Ratings CSV",
                        data=df_full.to_csv(index=False),
                        file_name=f"rq3_ratings_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                except:
                    pass

st.markdown("</div>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align:center;padding:20px;color:#5a7494;font-size:11px;font-family:'Space Mono',monospace;">
DCU MSc PRACTICUM 2026 &nbsp;·&nbsp; ACADEMIC RESEARCH ONLY &nbsp;·&nbsp; ALL DATA ANONYMOUS
</div>
""", unsafe_allow_html=True)
# ================================================================
# TAB 1 — RATE EXPLANATIONS
# ================================================================
with tab1:
    st.markdown("""
    <div class="hero">
      <div class="hero-title">RQ3: Explanation Quality Evaluation</div>
      <div class="hero-sub">
        You are reviewing AI-generated vulnerability explanations produced by a CodeBERT transformer model.<br>
        For each sample, rate the explanation on <strong>Correctness</strong> and <strong>Usefulness</strong> using the rubric below.
      </div>
      <div class="hero-tags">
        <span class="tag">20 SAMPLES</span>
        <span class="tag">4 CWE TYPES</span>
        <span class="tag">ACADEMIC RESEARCH</span>
        <span class="tag">ANONYMOUS</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Reviewer info
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        reviewer_id = st.text_input("Your reviewer ID", placeholder="e.g. Prof_GH or Reviewer_1", key="rid").strip()
    with col2:
        expertise = st.selectbox("Security expertise", ["— select —", "Beginner (< 1 year)", "Intermediate (1-3 years)", "Expert (3+ years)"], key="exp")
    with col3:
        st.markdown("<br>", unsafe_allow_html=True)
        ready = bool(reviewer_id) and expertise != "— select —"
        if not ready:
            st.warning("Fill in both fields")

    if not ready:
        st.stop()

    # Rubric
    with st.expander("📏 Rating Rubric — expand to read before starting"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""
**Correctness (1–5)**
Does the explanation accurately describe the vulnerability?

| Score | Meaning |
|---|---|
| 5 | Perfectly identifies vulnerability type, mechanism, and affected code |
| 4 | Mostly correct with minor inaccuracies |
| 3 | Partially correct, missing key details |
| 2 | Mostly incorrect but some relevant elements |
| 1 | Completely wrong |
            """)
        with c2:
            st.markdown("""
**Usefulness (1–5)**
Would a developer benefit from this explanation?

| Score | Meaning |
|---|---|
| 5 | Clearly actionable, specific fix, immediately helpful |
| 4 | Mostly useful with minor gaps |
| 3 | Somewhat useful but vague |
| 2 | Minimal practical value |
| 1 | Not useful at all |

Rate explanation quality independently of model prediction correctness.
            """)

    st.divider()

    # Progress
    my_ratings = get_reviewer_ratings(reviewer_id)
    rated_ids = [v['sample_id'] for v in my_ratings.values()]
    progress = len(rated_ids)

    # Consume navigation state before rendering so the dot grid highlights
    # the sample actually about to be shown
    if 'current_sample' not in st.session_state:
        st.session_state.current_sample = 0
    if 'pending_nav' in st.session_state:
        st.session_state.current_sample = st.session_state.pending_nav
        del st.session_state.pending_nav

    milestone = st.session_state.pop('just_hit', None)
    if milestone == 20:
        st.balloons()
    elif milestone in (5, 10, 15):
        st.toast(f"🔥 {milestone}/20 rated — keep going!")

    st.markdown(f"""
    <div class="progress-wrap">
      <div class="progress-label">
        <span style="color:var(--text);font-weight:600">Your Progress</span>
        <span style="color:var(--accent);font-family:'Space Mono',monospace">{progress}/20 rated</span>
      </div>
      <div class="progress-track">
        <div class="progress-fill" style="width:{progress/20*100}%"></div>
      </div>
      <div class="sample-grid">
    """ + "".join([
        f'<div class="sample-dot {"rated" if s["id"] in rated_ids else ""} {"current" if i == st.session_state.current_sample else ""}">{i+1}</div>'
        for i, s in enumerate(SAMPLES)
    ]) + """
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Navigation (state consumed above, before the dot grid renders)
    nav1, nav2, nav3 = st.columns([2, 3, 2])
    with nav1:
        prev_disabled = st.session_state.current_sample == 0
        if st.button("◀ Previous", disabled=prev_disabled, use_container_width=True, key="btn_prev"):
            st.session_state.pending_nav = max(0, st.session_state.current_sample - 1)
            st.rerun()
    with nav2:
        st.markdown(
            f"<div style='text-align:center;padding:10px 0;font-family:Space Mono,monospace;"
            f"font-size:14px;color:#00e5ff;font-weight:700;letter-spacing:1px;'>"
            f"SAMPLE {st.session_state.current_sample+1} / 20</div>",
            unsafe_allow_html=True
        )
        jump_options = [f"{i+1} — {s['id']} {'✅' if s['id'] in rated_ids else '○'}" for i, s in enumerate(SAMPLES)]
        jumped = st.selectbox("Go to", jump_options,
            index=st.session_state.current_sample,
            key=f"jump_{st.session_state.current_sample}",
            label_visibility="collapsed")
        jumped_idx = int(jumped.split(" ")[0]) - 1
        if jumped_idx != st.session_state.current_sample:
            st.session_state.pending_nav = jumped_idx
            st.rerun()
    with nav3:
        next_disabled = st.session_state.current_sample == 19
        if st.button("Next ▶", disabled=next_disabled, use_container_width=True, key="btn_next"):
            st.session_state.pending_nav = min(19, st.session_state.current_sample + 1)
            st.rerun()

    sample = SAMPLES[st.session_state.current_sample]
    existing = get_existing(reviewer_id, sample['id'])

    st.markdown(f"### Sample {st.session_state.current_sample + 1} of 20 — `{sample['id']}`")

    # Left / right columns
    left, right = st.columns([1, 1])

    with left:
        # Prediction info
        is_vuln = sample['model_pred'] == 'VULNERABLE'
        is_expected_vuln = sample['expected'] == 'VULNERABLE'
        model_correct = sample['model_pred'] == sample['expected']

        pred_badge = '<span class="badge-vuln">VULNERABLE</span>' if is_vuln else '<span class="badge-safe">SAFE</span>'
        exp_badge = '<span class="badge-vuln">VULNERABLE</span>' if is_expected_vuln else '<span class="badge-safe">SAFE</span>'
        correct_badge = '✅ Correct' if model_correct else '❌ Wrong prediction'

        st.markdown(f"""
        <div class="card">
          <div class="card-header">
            <span class="card-title">Model Output</span>
            <span class="badge-info">{sample['cwe']}</span>
          </div>
          <div class="card-body">
            <div style="display:flex;gap:20px;margin-bottom:12px;">
              <div><div style="font-size:10px;color:var(--muted);margin-bottom:4px;">MODEL PREDICTED</div>{pred_badge}</div>
              <div><div style="font-size:10px;color:var(--muted);margin-bottom:4px;">ACTUAL LABEL</div>{exp_badge}</div>
              <div><div style="font-size:10px;color:var(--muted);margin-bottom:4px;">VERDICT</div><div style="font-size:13px;font-weight:600">{correct_badge}</div></div>
            </div>
            <div style="font-size:10px;color:var(--muted);margin-bottom:5px;">CONFIDENCE</div>
            <div style="font-family:'Space Mono',monospace;font-size:20px;font-weight:700;color:{'var(--danger)' if is_vuln else 'var(--safe)'}">
              {sample['conf']}%
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Code
        st.markdown(f'<div class="card"><div class="card-header"><span class="card-title">Source Code — {sample["id"].lower()}.c</span><span class="term-dots"><span class="r"></span><span class="y"></span><span class="g"></span></span></div></div>', unsafe_allow_html=True)
        st.code(sample['code'], language='c')

        # Attention tokens
        tokens_html = "".join([f'<span class="tok">{t}</span>' for t in sample['tokens']])
        st.markdown(f"""
        <div style="margin-top:8px;">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px;letter-spacing:1px;">ATTENTION TOKENS (what model focused on)</div>
          <div class="token-row">{tokens_html}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:8px;">
            Note: Faithfulness experiment showed delta=0.000005 — masking these tokens does not change the prediction.
          </div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        # Explanation
        st.markdown(f"""
        <div class="card">
          <div class="card-header">
            <span class="card-title">AI-Generated Explanation</span>
            <span class="badge-info">{sample['pred_cwe'][:30]}...</span>
          </div>
          <div class="card-body">
            <div class="exp-section exp-main">
              <div class="exp-label">Explanation</div>
              {sample['explanation']}
            </div>
            <div class="exp-section exp-risk">
              <div class="exp-label">Exploitation Risk</div>
              {sample['risk']}
            </div>
            <div class="exp-section exp-fix">
              <div class="exp-label">Suggested Fix</div>
              {sample['fix']}
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Rating form
        st.markdown("#### ⭐ Your Rating")

        st.markdown("**Correctness** — how accurately does this explain the vulnerability?")
        cor_options = ["1 — Completely wrong", "2 — Mostly wrong", "3 — Partially correct", "4 — Mostly correct", "5 — Perfect"]
        cor_default = existing.get('correctness', 3) - 1
        cor_choice = st.radio("Correctness", cor_options, index=cor_default,
            key=f"cor_{sample['id']}", horizontal=True, label_visibility="collapsed")
        correctness = int(cor_choice[0])

        st.markdown("**Usefulness** — how helpful is this for a developer trying to fix the issue?")
        use_options = ["1 — Not useful", "2 — Minimal value", "3 — Somewhat useful", "4 — Mostly useful", "5 — Very useful"]
        use_default = existing.get('usefulness', 3) - 1
        use_choice = st.radio("Usefulness", use_options, index=use_default,
            key=f"use_{sample['id']}", horizontal=True, label_visibility="collapsed")
        usefulness = int(use_choice[0])

        pred_correct = st.radio(
            "Was the model's prediction correct?",
            ["Yes", "No", "Partially"],
            index=["Yes","No","Partially"].index(existing.get('model_prediction_correct', 'Yes')),
            horizontal=True,
            key=f"pc_{sample['id']}"
        )

        comments = st.text_area(
            "Comments (optional) — what was good or missing?",
            value=existing.get('comments', ''),
            height=70,
            key=f"com_{sample['id']}"
        )

        saved = sample['id'] in rated_ids
        btn_label = "✅ Update Rating" if saved else "💾 Save Rating"

        if st.button(btn_label, type="primary", use_container_width=True, key=f"save_{sample['id']}"):
            if save_rating(reviewer_id, sample['id'], correctness, usefulness, pred_correct, comments):
                if sample['id'] not in rated_ids:
                    st.session_state.just_hit = progress + 1
                st.success(f"Rating saved for {sample['id']}!")
                if st.session_state.current_sample < 19:
                    st.session_state.current_sample += 1
                st.rerun()

    # Completion check
    if progress == 20:
        st.markdown("""
        <div style="background:rgba(0,200,150,0.08);border:1px solid rgba(0,200,150,0.3);border-radius:10px;padding:16px;margin-top:16px;text-align:center;">
          <div style="font-size:24px;margin-bottom:6px;">🎉</div>
          <div style="font-size:16px;font-weight:700;color:var(--safe);">All 20 samples rated!</div>
          <div style="font-size:13px;color:var(--muted);margin-top:4px;">Thank you for contributing to this academic research. Please go to the Results tab to see your summary.</div>
        </div>
        """, unsafe_allow_html=True)
