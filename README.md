# GhostLink



/ | | ___ __| |() | ___
| | | ' \ / _ / | | | |/ _
| || | | | | / (| || | | /
_|| |_|_|_|_||_|___|
There is No Place to Hide
by Inayat Hussain – Pakistani Security Researcher


**GhostLink** is a powerful OSINT (Open Source Intelligence) tool for **username enumeration and footprinting** across 100+ platforms.  
It also generates **Google & Bing dorks** to help investigators dig deeper.

> ⚠ **Ethics:** GhostLink is intended **only** for lawful and authorized research, security testing, and investigation.  
> Do not use for stalking, harassment, or violating privacy, ToS, or laws.  

---

## ✨ Features
- Search a username across **100+ platforms** (social media, dev sites, forums, etc.)
- **Multi-threaded & asynchronous** scanning for speed
- Supports **quick mode** (top 25 sites) or **deep mode** (all platforms)
- Saves results in **JSON, CSV, and HTML** formats
- Generates **search engine dorks** for deeper investigation
- Optional **stealth mode** with random delays to reduce detection
- CLI-based – works on **Linux, macOS, and Windows**

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOURUSERNAME/ghostlink.git
cd ghostlink

2. Install dependencies

pip install -r requirements.txt

🚀 Usage
Basic scan (Quick Mode – 25 sites)

python3 ghostLink.py johndoe

Recommended full scan (Deep Mode – 100+ sites)

python3 ghostLink.py johndoe --deep --workers 24 --stealth --delay-min 0.5 --delay-max 1.5 --verbose

Options:
Option	Description
--deep	Scan all 100+ platforms
--workers N	Number of concurrent threads (default: 8)
--stealth	Enable random delays between requests
--delay-min	Minimum delay in seconds
--delay-max	Maximum delay in seconds
--verbose	Show all output including errors
--proxy	Use a proxy (e.g., http://127.0.0.1:8080)
📂 Output Files

GhostLink saves results automatically in the current directory:

    JSON: username_ghostlink_<timestamp>.json

    CSV: username_ghostlink_<timestamp>.csv

    HTML: username_ghostlink_<timestamp>.html

    Dorks: username_ghostlink_dorks_<timestamp>.txt

🔍 Example Output

[Reddit] FOUND -> https://www.reddit.com/user/johndoe/
[GitHub] FOUND -> https://github.com/johndoe
[GitLab] FOUND -> https://gitlab.com/johndoe
[Medium] FOUND -> https://medium.com/@johndoe
[+] Scan complete. FOUND: 4 | POSSIBLE: 0 | PROTECTED: 0 | TOTAL: 110

⚖ Legal & Ethical Notice

This tool is provided for educational and ethical research purposes only.
The author takes no responsibility for misuse. Always ensure you have permission before scanning or gathering data.
👤 Author

Inayat Hussain – Pakistani Security Researcher
"There is No Place to Hide"
