import sys
import pandas as pd
import apache_log_parser


if len(sys.argv) != 3:
    print(f"Usage: python3 {sys.argv[0]} <logfile> <key>", file=sys.stderr)
    sys.exit(1)
def vigenere_decrypt(text, key):
    key = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    out, i = [], 0
    for ch in text:
        if ch == "\n":
            i = 0
            out.append(ch)
        elif ch.isalpha():
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - key[i % len(key)]) % 26 + base))
            i += 1
        else:
            out.append(ch)
    return "".join(out)

with open(sys.argv[1]) as f:
    log_text = (vigenere_decrypt(f.read(), sys.argv[2]))





rows = []
format_string = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
line_parser = apache_log_parser.make_parser(format_string)
analysis = pd.DataFrame()
for line in log_text.splitlines():
    try:
        rows.append(line_parser(line))
    except ValueError:
        pass
df = pd.DataFrame(rows)
df = df[["remote_host", "time_received_datetimeobj","request_first_line", "request_method",
         "request_url_query_simple_dict", "status",
         "response_bytes_clf", "request_header_user_agent"]]

attack_detected = False

d401 = df[df["status"].astype(str) == "401"]
for ip, n in d401["remote_host"].value_counts().items():
    if n >= 5:
        print(f"[ALERT] Brute force from {ip} ({n} failed logins)")
        attack_detected = True

print("\n")

## DIR
mask = df["request_first_line"].astype(str).str.contains(r"(?:\.\.|%2e%2e)(?:/|%2f)", regex=True, case=False)

for ip, r in df[mask]["remote_host"].value_counts().items():
    print(f"[ALERT] Directory traversal from {ip} ({r} attempts)")
    attack_detected = True


print("\n")

patterns = ["DROP TABLE", "OR 1=1", "OR '1'='1'"]
req = df["request_first_line"].astype(str)

mask_sqli = False
for p in patterns:
    mask_sqli |= req.str.contains(p, regex=False)

for ip, n in df.loc[mask_sqli, "remote_host"].value_counts().items():
    print(f"[ALERT] SQL injection from {ip} ({n} attempts)")
    attack_detected = True

sys.exit(1 if attack_detected else 0)


  
