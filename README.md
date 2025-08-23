<h1 align="center">DorkMe</h1>

**DorkMe** is a high-performance Google dork automation tool designed for OSINT, reconnaissance, and large-scale information discovery.  
With support for proxy chaining, SerpAPI integration, configurable request pacing, and powerful CSV/HTML reporting, DorkMe makes it simple to perform deep reconnaissance while keeping resource usage efficient and controlled.

![alt text](https://i.postimg.cc/TYChLNd3/temp-Image2-ILu-Zr.avif)

Define your dorks in a text file with simple headers (`##`) and let DorkMe handle the rest — mass querying, result collection, deduplication, and professional report generation. You can create as many custom scan lists as you would like, DorkMe will read which list would like to scan for in config.ini. 

---

## Why Use DorkMe?

- 🔎 **Automated Reconnaissance**  
  Input a structured dorks file and let DorkMe execute dozens or hundreds of targeted Google searches automatically.

- ⚡ **Networking Engineered for Scale**  
  - Token-bucket request limiter (precise global RPS control)  
  - Per-host concurrency caps to prevent overloads or bans  
  - Proxy chaining (datacenter, ISP, or mobile) for stealth & distribution  
  - Optional SerpAPI backend to bypass captchas entirely  

- 🖥️ **Resource-Friendly**  
  Designed to run efficiently on everything from a high-end workstation to a modest VPS. Adaptive limits keep CPU and memory usage sane.

- 📊 **Dual Reporting**  
  Generate clean **HTML** reports for easy browsing or **CSV** datasets for deeper analysis, automation, or import into other tools.

- 🔒 **Configurable & Persistent**  
  All runtime options — sockets, rate limits, proxies, API keys, and report formats — can be adjusted interactively or saved in a config file.

---

## Getting Started

### Prerequisites

Requirements to run DorkMe:
- Python 3.8+
- [requests](https://pypi.org/project/requests/)
- [beautifulsoup4](https://pypi.org/project/beautifulsoup4/)
- (optional) [lxml](https://pypi.org/project/lxml/) for faster parsing
- (optional) [psutil](https://pypi.org/project/psutil/) for hardware-aware recommendations

Install dependencies:

```bash
pip install requests beautifulsoup4
# Optional performance extras
pip install lxml psutil
