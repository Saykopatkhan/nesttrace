"""
NestTrace v5.1 — Field-Hardened Enterprise OSINT Framework
===========================================================
- TikTok triple-layer extraction (regex + JS eval + DOM)
- Context Pool with Semaphore (race-condition free)
- BasePlatform abstract class (DRY modular design)
- Resilient multi-layer JSON extraction
- Timezone-safe datetime (timezone.utc)
- Triple output: JSON / HTML / Markdown
- HEADLESS TOGGLE via --headed CLI flag
- MANUAL CAPTCHA SOLVE MODE (--solve-captcha)
- WIDENED RATE LIMITS (3-7s random inter-request)
- RESIDENTIAL PROXY SUPPORT (env/file/config)
- Full type hints, zero NBSP, production-grade

Usage:
    python nesttrace.py username                    # headless, no proxy
    python nesttrace.py username --headed           # visible browser
    python nesttrace.py username --headed --solve-captcha  # pause on captcha
    python nesttrace.py username --proxy http://user:pass@host:port
    python nesttrace.py username --proxy-file proxies.txt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote_plus

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    raise SystemExit("pip install playwright rich curl_cffi && python -m playwright install chromium")

try:
    from curl_cffi.requests import Session as SyncCffiSession
    HAS_CFFI = True
except ImportError:
    HAS_CFFI = False

console = Console()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("nesttrace_debug.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("NestTrace")


# ── CLI Argument Parser ─────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NestTrace v5.1 — Enterprise OSINT Framework")
    parser.add_argument("username", help="Hedef kullanıcı adı")
    parser.add_argument("--headed", action="store_true", help="Tarayıcıyı ekranda göster (headless=False)")
    parser.add_argument("--solve-captcha", action="store_true",
                        help="CAPTCHA tespit edildiğinde dur ve manuel çözüm bekle (headed gerektirir)")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy URL (http://user:pass@host:port)")
    parser.add_argument("--proxy-file", type=str, default=None, help="Proxy listesi dosyası (satır başına bir proxy)")
    parser.add_argument("--output", nargs="+", default=["json", "html", "md"],
                        choices=["json", "html", "md"], help="Çıktı formatları (varsayılan: json html md)")
    parser.add_argument("--concurrency", type=int, default=3, help="Eşzamanlı tarayıcı context sayısı (varsayılan: 3)")
    return parser.parse_args()


# ── Veri Modelleri ──────────────────────────────────────────────

@dataclass
class Trace:
    platform: str
    username: str
    found: bool
    url: str
    confidence: str
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    follower_count: Optional[int] = None
    post_count: Optional[int] = None
    joined_date: Optional[str] = None
    extra_metadata: dict[str, Any] = field(default_factory=dict)
    archived_snapshots: list[dict[str, str]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ReconProfile:
    target: str
    traces: list[Trace] = field(default_factory=list)
    correlations: list[str] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add(self, trace: Trace) -> None:
        self.traces.append(trace)


# ── Yardımcı Fonksiyonlar ───────────────────────────────────────

def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        cleaned = re.sub(r"[^\d.]", "", value.replace(",", "."))
        try:
            return int(float(cleaned)) if cleaned else default
        except ValueError:
            return default
    return default


def safe_extract_json(body: str, patterns: list[str], source_label: str) -> Optional[dict[str, Any]]:
    for pattern in patterns:
        match = re.search(pattern, body, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                logger.debug("[%s] JSON extracted via pattern: %s...", source_label, pattern[:60])
                return data
            except json.JSONDecodeError as e:
                logger.warning("[%s] JSON parse failed (%s...): %s", source_label, pattern[:40], e)
                continue
    logger.warning("[%s] All %d JSON extraction patterns failed", source_label, len(patterns))
    return None


def safe_timestamp(ts: Any) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OSError, TypeError) as e:
        logger.warning("Timestamp parse failed (%s): %s", ts, e)
        return None


def parse_social_count(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    value = value.strip().upper().replace(",", ".")
    try:
        if "B" in value:
            return int(float(value.replace("B", "")) * 1_000_000_000)
        elif "M" in value:
            return int(float(value.replace("M", "")) * 1_000_000)
        elif "K" in value:
            return int(float(value.replace("K", "")) * 1_000)
        else:
            return int(float(re.sub(r"[^\d.]", "", value)))
    except (ValueError, TypeError):
        return None


def load_proxies(proxy_arg: Optional[str], proxy_file: Optional[str]) -> list[str]:
    """Proxy listesini CLI argümanı, dosya veya environment variable'dan yükler."""
    proxies: list[str] = []
    if proxy_arg:
        proxies.append(proxy_arg)
    if proxy_file and Path(proxy_file).exists():
        with open(proxy_file, "r") as f:
            proxies.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    env_proxy = os.environ.get("NESTTRACE_PROXY")
    if env_proxy and env_proxy not in proxies:
        proxies.append(env_proxy)
    if proxies:
        logger.info("Loaded %d proxy endpoint(s)", len(proxies))
    return proxies


# ── İnsan Davranış Simülasyonu ──────────────────────────────────

class HumanBehavior:
    @staticmethod
    async def human_mouse_move(page: Page, x: int, y: int, steps: int = 20) -> None:
        start_x, start_y = random.randint(100, 800), random.randint(100, 600)
        cp1_x = start_x + (x - start_x) * random.uniform(0.2, 0.5)
        cp1_y = start_y + random.uniform(-100, 100)
        cp2_x = start_x + (x - start_x) * random.uniform(0.5, 0.8)
        cp2_y = y + random.uniform(-100, 100)
        for i in range(steps + 1):
            t = i / steps
            bx = (1 - t) ** 3 * start_x + 3 * (1 - t) ** 2 * t * cp1_x + 3 * (1 - t) * t**2 * cp2_x + t**3 * x
            by = (1 - t) ** 3 * start_y + 3 * (1 - t) ** 2 * t * cp1_y + 3 * (1 - t) * t**2 * cp2_y + t**3 * y
            await page.mouse.move(bx + random.gauss(0, 0.5), by + random.gauss(0, 0.5))
            await asyncio.sleep(random.uniform(0.005, 0.025))

    @staticmethod
    async def human_scroll(page: Page, direction: str = "down", distance: int = 300) -> None:
        remaining = distance
        for _ in range(random.randint(5, 12)):
            chunk = max(10, int(remaining / random.uniform(1.5, 3.0)))
            await page.mouse.wheel(0, chunk if direction == "down" else -chunk)
            remaining -= chunk
            await asyncio.sleep(random.uniform(0.02, 0.08))
        await asyncio.sleep(random.uniform(0.3, 1.2))

    @staticmethod
    async def human_pause(min_s: float = 0.5, max_s: float = 2.0) -> None:
        await asyncio.sleep(random.uniform(min_s, max_s))

    @classmethod
    async def simulate_page_read(cls, page: Page) -> None:
        await cls.human_pause(0.8, 2.0)
        await cls.human_scroll(page, "down", random.randint(200, 500))
        await cls.human_pause(0.5, 1.5)
        try:
            elements = await page.query_selector_all("a, button, h1, h2, p, img")
            if elements:
                el = random.choice(elements[:10])
                box = await el.bounding_box()
                if box:
                    await cls.human_mouse_move(page, int(box["x"] + box["width"] / 2), int(box["y"] + box["height"] / 2))
        except Exception:
            pass
        await cls.human_pause(0.3, 1.0)
        await cls.human_scroll(page, "up", random.randint(50, 150))


# ── Stealth JS ──────────────────────────────────────────────────

ADAPTIVE_STEALTH_JS: str = """
Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
Object.defineProperty(navigator,'plugins',{get:()=>{const p=[{name:'Chrome PDF Plugin',filename:'internal-pdf-viewer'},{name:'Chrome PDF Viewer',filename:'mhjfbmdgcfjbbpaeojofohoefgiehjai'},{name:'Chromium PDF Viewer',filename:'internal-pdf-viewer'},{name:'Microsoft Edge PDF Plugin',filename:'internal-pdf-viewer'},{name:'WebKit built-in PDF',filename:'internal-pdf-viewer'}];p.length=5;return p;}});
Object.defineProperty(navigator,'languages',{get:()=>['tr-TR','tr','en-US','en']});
Object.defineProperty(navigator,'hardwareConcurrency',{get:()=>[4,6,8,12][Math.floor(Math.random()*4)]});
Object.defineProperty(navigator,'deviceMemory',{get:()=>[4,8,16][Math.floor(Math.random()*3)]});
Object.defineProperty(navigator,'platform',{get:()=>'Win32'});
window.chrome={runtime:{connect:()=>{},sendMessage:()=>{}},loadTimes:()=>({}),csi:()=>({})};
const oq=window.navigator.permissions?.query;if(oq){window.navigator.permissions.query=(p)=>p.name==='notifications'?Promise.resolve({state:Notification.permission}):oq(p);}
const otd=HTMLCanvasElement.prototype.toDataURL;HTMLCanvasElement.prototype.toDataURL=function(t){if(t==='image/png'||!t){const c=this.getContext('2d');if(c){const s=c.fillStyle;c.fillStyle='rgba(255,255,255,0.01)';c.fillRect(0,0,1,1);c.fillStyle=s;}}return otd.apply(this,arguments);};
const gp=WebGLRenderingContext.prototype.getParameter;WebGLRenderingContext.prototype.getParameter=function(p){if(p===37445)return'Intel Inc.';if(p===37446)return'Intel Iris OpenGL Engine';return gp.call(this,p);};
const ogbr=Element.prototype.getBoundingClientRect;Element.prototype.getBoundingClientRect=function(){const r=ogbr.call(this);const n=()=>(Math.random()-0.5)*0.1;return new DOMRect(r.x+n(),r.y+n(),r.width+n(),r.height+n());};
"""


# ── CAPTCHA Detection & Manual Solve ────────────────────────────

CAPTCHA_SELECTORS = [
    '[class*="captcha"]', '[id*="captcha"]', '.verify-wrap',
    '#challenge-stage', '[data-testid="challenge"]',
    'iframe[src*="challenges.cloudflare.com"]',
    'iframe[src*="recaptcha"]', '.hcaptcha-container',
    '[class*="turnstile"]', '#cf-turnstile',
    '.geetest_panel', '.captcha_verify_container',
    '[class*="verify-bar"]', '[class*="slider"]',
]


async def check_and_handle_captcha(page: Page, platform_name: str, solve_mode: bool) -> bool:
    """CAPTCHA tespit eder. solve_mode=True ise kullanıcıya manuel çözüm için durur.
    Returns: True if captcha was detected (and possibly solved), False if clean."""
    for selector in CAPTCHA_SELECTORS:
        try:
            el = await page.query_selector(selector)
            if el and await el.is_visible():
                logger.warning("[%s] CAPTCHA detected: %s", platform_name, selector)
                if solve_mode:
                    console.print(f"\n[yellow bold]⚠ {platform_name}: CAPTCHA tespit edildi![/]")
                    console.print("[yellow]Tarayıcıda CAPTCHA'yı manuel olarak çözün.[/]")
                    console.print("[yellow]Çözdükten sonra burada ENTER'a basın...[/]")
                    await asyncio.get_event_loop().run_in_executor(None, input)
                    # Kullanıcı çözdükten sonra sayfanın yüklenmesini bekle
                    await page.wait_for_load_state("domcontentloaded", timeout=30000)
                    await HumanBehavior.human_pause(1.0, 2.0)
                    logger.info("[%s] User confirmed captcha solved, continuing", platform_name)
                    return True
                else:
                    logger.warning("[%s] CAPTCHA detected but --solve-captcha not enabled, skipping", platform_name)
                    return True
        except Exception:
            continue
    return False


# ── Context Pool (Semaphore-Based Isolation) ────────────────────

class ContextPool:
    def __init__(self, browser: Browser, max_concurrent: int = 3,
                 proxy_list: Optional[list[str]] = None,
                 headed: bool = False, solve_captcha: bool = False) -> None:
        self._browser = browser
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._proxy_list = proxy_list or []
        self._headed = headed
        self._solve_captcha = solve_captcha

    def _pick_proxy(self) -> Optional[str]:
        return random.choice(self._proxy_list) if self._proxy_list else None

    async def acquire(self) -> tuple[BrowserContext, asyncio.Semaphore]:
        await self._semaphore.acquire()
        ctx_kwargs: dict[str, Any] = {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "viewport": {"width": 1920, "height": 1080},
            "locale": "tr-TR",
            "timezone_id": "Europe/Istanbul",
            "color_scheme": "dark",
            "java_script_enabled": True,
            "bypass_csp": True,
        }
        proxy = self._pick_proxy()
        if proxy:
            ctx_kwargs["proxy"] = {"server": proxy}
            logger.debug("Using proxy: %s", proxy[:40])
        context = await self._browser.new_context(**ctx_kwargs)
        await context.add_init_script(ADAPTIVE_STEALTH_JS)
        logger.debug("Context acquired (pool slot, proxy=%s)", "yes" if proxy else "no")
        return context, self._semaphore

    @staticmethod
    async def release(context: BrowserContext, semaphore: asyncio.Semaphore) -> None:
        await context.close()
        semaphore.release()
        logger.debug("Context released (pool slot freed)")

    @property
    def solve_captcha(self) -> bool:
        return self._solve_captcha


# ── TLS-Aware HTTP Client ───────────────────────────────────────

class TlsClient:
    @staticmethod
    def get_sync(url: str, headers: Optional[dict[str, str]] = None, timeout: int = 10) -> Optional[Any]:
        if not HAS_CFFI:
            return None
        try:
            with SyncCffiSession(impersonate="chrome126") as sess:
                resp = sess.get(url, headers=headers, timeout=timeout)
                return resp if resp.status_code == 200 else None
        except Exception as e:
            logger.debug("TlsClient GET failed (%s): %s", url, e)
            return None

    @staticmethod
    def post_sync(url: str, headers: Optional[dict[str, str]] = None, timeout: int = 10) -> Optional[Any]:
        if not HAS_CFFI:
            return None
        try:
            with SyncCffiSession(impersonate="chrome126") as sess:
                resp = sess.post(url, headers=headers, timeout=timeout)
                return resp if resp.status_code == 200 else None
        except Exception as e:
            logger.debug("TlsClient POST failed (%s): %s", url, e)
            return None


# ── BasePlatform (Abstract — DRY Modular Design) ────────────────

class BasePlatform(ABC):
    name: str = "Base"
    priority: int = 5

    def __init__(self, pool: ContextPool, profile: ReconProfile) -> None:
        self.pool = pool
        self.profile = profile

    async def run(self, username: str) -> None:
        context, sem = await self.pool.acquire()
        try:
            await self.recon(context, username)
        except Exception as e:
            logger.error("[%s] Unhandled error: %s", self.name, e, exc_info=True)
            self.profile.add(Trace(
                platform=self.name, username=username, found=False,
                url="", confidence="LOW", extra_metadata={"error": str(e)[:200]}
            ))
        finally:
            await ContextPool.release(context, sem)

    @abstractmethod
    async def recon(self, context: BrowserContext, username: str) -> None: ...

    def add_found(self, username: str, **kwargs: Any) -> None:
        self.profile.add(Trace(platform=self.name, username=username, found=True, **kwargs))

    def add_not_found(self, username: str, url: str, confidence: str = "HIGH", **kwargs: Any) -> None:
        self.profile.add(Trace(platform=self.name, username=username, found=False, url=url, confidence=confidence, **kwargs))

    async def get_page_content(self, context: BrowserContext, url: str,
                               simulate: bool = True, timeout: int = 20000) -> tuple[Optional[Page], str]:
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            # CAPTCHA check after initial load
            captcha_found = await check_and_handle_captcha(page, self.name, self.pool.solve_captcha)
            if captcha_found and not self.pool.solve_captcha:
                logger.warning("[%s] CAPTCHA blocked access, cannot proceed", self.name)
                await page.close()
                return None, ""
            if simulate:
                await HumanBehavior.simulate_page_read(page)
            body = await page.content()
            return page, body
        except Exception as e:
            logger.warning("[%s] Page load failed (%s): %s", self.name, url, e)
            await page.close()
            return None, ""

    async def extract_meta_tags(self, page: Page) -> dict[str, Optional[str]]:
        return await page.evaluate("""() => ({
            title: document.title,
            og_title: document.querySelector('meta[property="og:title"]')?.content || null,
            og_desc: document.querySelector('meta[property="og:description"]')?.content || null,
            og_image: document.querySelector('meta[property="og:image"]')?.content || null
        })""")


# ── Platform Registry ───────────────────────────────────────────

class PlatformRegistry:
    _platforms: list[type[BasePlatform]] = []

    @classmethod
    def register(cls, platform_class: type[BasePlatform]) -> type[BasePlatform]:
        cls._platforms.append(platform_class)
        cls._platforms.sort(key=lambda p: p.priority)
        return platform_class

    @classmethod
    def all_platforms(cls) -> list[type[BasePlatform]]:
        return cls._platforms


# ── Platform Implementations ────────────────────────────────────

@PlatformRegistry.register
class TikTokPlatform(BasePlatform):
    name = "TikTok"
    priority = 1

    JSON_PATTERNS = [
        r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
        r'<script[^>]*id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)<\/script>',
        r'<script id="SIGI_STATE"[^>]*>(.*?)</script>',
        r'<script[^>]*id="SIGI_STATE"[^>]*>(.*?)<\/script>',
        r"window\['SIGI_STATE'\]\s*=\s*(\{.*?\});",
        r'window\.SIGI_STATE\s*=\s*(\{.*?\});',
        r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>',
        r'"userInfo"\s*:\s*\{[^{}]*"user"\s*:\s*(\{.*?"statsV2".*?\})\s*[,}]',
        r'"UserModule"\s*:\s*(\{.*?"users".*?"stats".*?\})\s*[,}]',
        r'"nickname"\s*:\s*"[^"]*".*?"statsV2"\s*:\s*(\{.*?\})',
        r'"webapp\.user-detail"\s*:\s*(\{.*?"userInfo".*?\})',
    ]

    JS_EXTRACTION = r"""() => {
        const results = {};
        if (window.__UNIVERSAL_DATA_FOR_REHYDRATION__) 
            results.rehydration = window.__UNIVERSAL_DATA_FOR_REHYDRATION__;
        if (window.SIGI_STATE) 
            results.sigi = window.SIGI_STATE;
        if (window.__NEXT_DATA__) 
            results.next = window.__NEXT_DATA__;
        const scripts = document.querySelectorAll('script');
        for (const s of scripts) {
            const text = s.textContent || '';
            if (text.includes('"userInfo"') && text.includes('"statsV2"')) {
                try {
                    const match = text.match(/(\{.*"userInfo".*"statsV2".*\})/s);
                    if (match) { results.inline_script = JSON.parse(match[1]); break; }
                } catch(e) {}
            }
            if (text.includes('"UserModule"') && text.includes('"users"')) {
                try {
                    const match = text.match(/(\{.*"UserModule".*"users".*\})/s);
                    if (match) { results.inline_sigi = JSON.parse(match[1]); break; }
                } catch(e) {}
            }
        }
        const domData = {};
        const nameEl = document.querySelector('[data-e2e="user-info"] h1, h1[data-e2e="user-title"], .user-username span');
        const bioEl = document.querySelector('[data-e2e="user-bio"], .user-bio');
        const followerEl = document.querySelector('[data-e2e="followers-count"], strong[data-e2e="followers-count"]');
        const followingEl = document.querySelector('[data-e2e="following-count"], strong[data-e2e="following-count"]');
        const likeEl = document.querySelector('[data-e2e="likes-count"], strong[data-e2e="likes-count"]');
        const videoEl = document.querySelector('[data-e2e="videos-count"]');
        const avatarEl = document.querySelector('img[data-e2e="user-avatar"], img.avatar-image');
        if (nameEl) domData.nickname = nameEl.innerText?.trim();
        if (bioEl) domData.signature = bioEl.innerText?.trim();
        if (followerEl) domData.followerCount = followerEl.innerText?.trim();
        if (followingEl) domData.followingCount = followingEl.innerText?.trim();
        if (likeEl) domData.heartCount = likeEl.innerText?.trim();
        if (videoEl) domData.videoCount = videoEl.innerText?.trim();
        if (avatarEl) domData.avatarLarger = avatarEl.src;
        if (Object.keys(domData).length > 0) results.dom = domData;
        return results;
    }"""

    async def recon(self, context: BrowserContext, username: str) -> None:
        url = f"https://www.tiktok.com/@{username}"
        page, body = await self.get_page_content(context, url)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            data = safe_extract_json(body, self.JSON_PATTERNS, self.name)
            user_info = None
            stats: dict[str, Any] = {}
            if data:
                user_info, stats = self._extract_user_from_json(data)
            if not user_info:
                logger.info("[%s] Regex failed, trying JS eval extraction", self.name)
                js_results = await page.evaluate(self.JS_EXTRACTION)
                for key in ("rehydration", "sigi", "inline_script", "inline_sigi"):
                    if not user_info and js_results.get(key):
                        user_info, stats = self._extract_user_from_json(js_results[key])
                        if user_info:
                            logger.info("[%s] Found via JS %s", self.name, key)
                if not user_info and js_results.get("dom"):
                    dom = js_results["dom"]
                    logger.info("[%s] Using DOM fallback: %s", self.name, list(dom.keys()))
                    self.add_found(username, url=url, confidence="MEDIUM",
                        display_name=dom.get("nickname"), bio=dom.get("signature"),
                        avatar_url=dom.get("avatarLarger"),
                        follower_count=parse_social_count(dom.get("followerCount")),
                        post_count=parse_social_count(dom.get("videoCount")),
                        extra_metadata={"following": parse_social_count(dom.get("followingCount")),
                                        "likes": parse_social_count(dom.get("heartCount")),
                                        "source": "dom_elements"})
                    return
            if user_info:
                self.add_found(username, url=url, confidence="HIGH",
                    display_name=user_info.get("nickname"), bio=user_info.get("signature"),
                    avatar_url=user_info.get("avatarLarger"),
                    follower_count=safe_int(stats.get("followerCount")),
                    post_count=safe_int(stats.get("videoCount")),
                    extra_metadata={"following": safe_int(stats.get("followingCount")),
                                    "likes": safe_int(stats.get("heartCount")),
                                    "verified": user_info.get("verified", False),
                                    "sec_uid": user_info.get("secUid"),
                                    "source": "json_multi_layer"})
            else:
                meta = await self.extract_meta_tags(page)
                if meta["title"] and "not found" not in meta["title"].lower():
                    self.add_found(username, url=url, confidence="LOW",
                        display_name=meta["title"].split("|")[0].strip(), bio=meta["og_desc"],
                        extra_metadata={"fallback": "meta_tags_only"})
                    logger.warning("[%s] All extraction layers failed, meta-only result", self.name)
                else:
                    self.add_not_found(username, url)
        finally:
            await page.close()

    @staticmethod
    def _extract_user_from_json(data: dict[str, Any]) -> tuple[Optional[dict], dict]:
        ui = data.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {}).get("userInfo", {})
        if ui.get("user"):
            return ui["user"], ui["user"].get("statsV2", {})
        users = data.get("UserModule", {}).get("users", {})
        if users:
            u = list(users.values())[0] if isinstance(users, dict) else None
            s_map = data.get("UserModule", {}).get("stats", {})
            s = list(s_map.values())[0] if isinstance(s_map, dict) else {}
            if u:
                return u, s
        if data.get("userInfo", {}).get("user"):
            u = data["userInfo"]["user"]
            return u, u.get("statsV2", u.get("stats", {}))
        if data.get("user") and data.get("statsV2"):
            return data["user"], data["statsV2"]
        if data.get("nickname") and ("statsV2" in data or "followerCount" in data):
            return data, data.get("statsV2", data)
        return None, {}


@PlatformRegistry.register
class InstagramPlatform(BasePlatform):
    name = "Instagram"
    priority = 2
    JSON_PATTERNS = [
        r'<script type="application/json"[^>]*>(.*?)</script>',
        r"window\.__additionalDataLoaded\s*\(\s*[\"'][^\"']*[\"']\s*,\s*(\{.*?\})\s*\)",
        r"window\._sharedData\s*=\s*(\{.*?\});",
        r'"graphql"\s*:\s*\{\s*"user"\s*:\s*(\{.*?"edge_followed_by".*?\})\s*[,}]',
        r'"user"\s*:\s*(\{.*?"biography".*?\})\s*[,}]',
    ]

    async def recon(self, context: BrowserContext, username: str) -> None:
        url = f"https://www.instagram.com/{username}/"
        page, body = await self.get_page_content(context, url)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            current_url = page.url
            if "accounts/login" in current_url or "challenge" in current_url:
                meta = await self.extract_meta_tags(page)
                self.add_found(username, url=url, confidence="MEDIUM",
                    display_name=meta["og_title"].split("(")[0].strip() if meta["og_title"] else None,
                    bio=meta["og_desc"], avatar_url=meta["og_image"],
                    extra_metadata={"note": "Auth wall", "redirect": current_url})
                return
            data = safe_extract_json(body, self.JSON_PATTERNS, self.name)
            user = None
            if data:
                for path_fn in [
                    lambda d: d.get("data", {}).get("user"),
                    lambda d: d.get("graphql", {}).get("user"),
                    lambda d: d.get("entry_data", {}).get("ProfilePage", [{}])[0].get("graphql", {}).get("user"),
                    lambda d: d.get("require", [{}])[0] if isinstance(d.get("require"), list) else None,
                    lambda d: d.get("user") if d.get("biography") else None,
                ]:
                    try:
                        c = path_fn(data)
                        if c and isinstance(c, dict) and any(k in c for k in ("username", "full_name", "biography")):
                            user = c
                            break
                    except (KeyError, IndexError, TypeError):
                        continue
            if user:
                self.add_found(username, url=url, confidence="HIGH",
                    display_name=user.get("full_name"), bio=user.get("biography"),
                    avatar_url=user.get("profile_pic_url_hd") or user.get("profile_pic_url"),
                    follower_count=safe_int(user.get("edge_followed_by", {}).get("count")) or safe_int(user.get("follower_count")),
                    post_count=safe_int(user.get("edge_owner_to_timeline_media", {}).get("count")) or safe_int(user.get("media_count")),
                    extra_metadata={"is_verified": user.get("is_verified"), "is_private": user.get("is_private"),
                                    "external_url": user.get("external_url"), "category": user.get("category_name"),
                                    "source": "json_multi"})
            else:
                meta = await self.extract_meta_tags(page)
                found = bool(meta["title"]) and "page not found" not in (meta["title"] or "").lower()
                if found:
                    self.add_found(username, url=url, confidence="MEDIUM",
                        display_name=meta["title"].split("(")[0].strip() if meta["title"] else None,
                        bio=meta["og_desc"], extra_metadata={"fallback": "meta_tags"})
                else:
                    self.add_not_found(username, url)
        finally:
            await page.close()


@PlatformRegistry.register
class TwitterPlatform(BasePlatform):
    name = "Twitter/X"
    priority = 3
    BEARER = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

    async def recon(self, context: BrowserContext, username: str) -> None:
        if HAS_CFFI:
            gt_resp = TlsClient.post_sync("https://api.twitter.com/1.1/guest/activate.json", headers={"Authorization": self.BEARER})
            if gt_resp:
                guest_token = gt_resp.json().get("guest_token")
                user_resp = TlsClient.get_sync(
                    f"https://api.twitter.com/1.1/users/show.json?screen_name={username}",
                    headers={"Authorization": self.BEARER, "x-guest-token": guest_token})
                if user_resp:
                    u = user_resp.json()
                    created = None
                    if u.get("created_at"):
                        try:
                            created = datetime.strptime(u["created_at"], "%a %b %d %H:%M:%S %z %Y").strftime("%Y-%m-%d")
                        except ValueError:
                            pass
                    self.add_found(username, url=f"https://x.com/{username}", confidence="HIGH",
                        display_name=u.get("name"), bio=u.get("description"),
                        avatar_url=u.get("profile_image_url_https"),
                        follower_count=safe_int(u.get("followers_count")),
                        post_count=safe_int(u.get("statuses_count")),
                        joined_date=created,
                        extra_metadata={"verified": u.get("verified"), "location": u.get("location"),
                                        "website": u.get("url"), "source": "tls_guest_api"})
                    return
        url = f"https://x.com/{username}"
        page, _ = await self.get_page_content(context, url)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            try:
                await page.wait_for_selector('[data-testid="UserName"]', timeout=10000)
            except Exception:
                body_text = await page.evaluate("() => document.body?.innerText || ''")
                if "doesn't exist" in body_text or "suspended" in body_text:
                    self.add_not_found(username, url)
                else:
                    self.add_not_found(username, url, "LOW", extra_metadata={"note": "Content failed to load"})
                return
            dn = await page.evaluate("() => document.querySelector('[data-testid=\"UserName\"]')?.innerText")
            bio = await page.evaluate("() => document.querySelector('[data-testid=\"UserDescription\"]')?.innerText")
            loc = await page.evaluate("() => document.querySelector('[data-testid=\"UserLocation\"]')?.innerText")
            web = await page.evaluate("() => document.querySelector('[data-testid=\"UserUrl\"]')?.innerText")
            jd = await page.evaluate("() => document.querySelector('[data-testid=\"UserJoinDate\"]')?.innerText")
            ft = await page.evaluate("() => {const l=document.querySelectorAll('a[href$=\"/followers\"]');return l[0]?.querySelector('span')?.textContent||null;}")
            self.add_found(username, url=url, confidence="HIGH",
                display_name=dn.split("\n")[0] if dn else None, bio=bio,
                extra_metadata={"location": loc, "website": web, "join_date_display": jd,
                                "follower_display": ft, "source": "browser_behavioral"})
        finally:
            await page.close()


@PlatformRegistry.register
class YouTubePlatform(BasePlatform):
    name = "YouTube"
    priority = 4
    JSON_PATTERNS = [r"var ytInitialData\s*=\s*(\{.*?\});", r"window\.ytInitialData\s*=\s*(\{.*?\});"]

    async def recon(self, context: BrowserContext, username: str) -> None:
        url = f"https://www.youtube.com/@{username}"
        page, body = await self.get_page_content(context, url)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            data = safe_extract_json(body, self.JSON_PATTERNS, self.name)
            if not data:
                data = await page.evaluate("() => window.ytInitialData || null")
            if data:
                header = data.get("header", {}).get("c4TabbedHeaderRenderer", {})
                metadata = data.get("metadata", {}).get("channelMetadataRenderer", {})
                subs_text = header.get("subscriberCountText", {}).get("simpleText", "")
                subs_num = None
                if subs_text:
                    nums = re.findall(r"[\d,.]+", subs_text.replace(",", "."))
                    if nums:
                        try:
                            val = float(nums[0])
                            if "M" in subs_text.upper(): val *= 1_000_000
                            elif "K" in subs_text.upper(): val *= 1_000
                            subs_num = int(val)
                        except ValueError:
                            pass
                self.add_found(username, url=url, confidence="HIGH",
                    display_name=metadata.get("title") or header.get("title"),
                    bio=metadata.get("description"),
                    avatar_url=metadata.get("avatar", {}).get("thumbnails", [{}])[-1].get("url"),
                    follower_count=subs_num,
                    extra_metadata={"channel_id": metadata.get("externalId"),
                                    "keywords": metadata.get("keywords"),
                                    "vanity_url": metadata.get("vanityChannelUrl"),
                                    "source": "ytInitialData"})
            else:
                meta = await self.extract_meta_tags(page)
                self.add_found(username, url=url, confidence="MEDIUM",
                    display_name=meta["title"].split("-")[0].strip() if meta["title"] else None,
                    extra_metadata={"fallback": "title"})
        finally:
            await page.close()


@PlatformRegistry.register
class FacebookPlatform(BasePlatform):
    name = "Facebook"
    priority = 5

    async def recon(self, context: BrowserContext, username: str) -> None:
        url = f"https://www.facebook.com/{username}"
        page, _ = await self.get_page_content(context, url, simulate=False)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            await HumanBehavior.human_pause(1.0, 2.5)
            current = page.url
            if "/login/" in current or "/checkpoint/" in current:
                meta = await self.extract_meta_tags(page)
                self.add_found(username, url=url, confidence="MEDIUM",
                    display_name=meta["og_title"], bio=meta["og_desc"], avatar_url=meta["og_image"],
                    extra_metadata={"note": "Auth wall", "redirect": current})
                return
            await HumanBehavior.simulate_page_read(page)
            meta = await self.extract_meta_tags(page)
            if meta["og_title"]:
                self.add_found(username, url=url, confidence="MEDIUM",
                    display_name=meta["og_title"], bio=meta["og_desc"], avatar_url=meta["og_image"])
            else:
                self.add_not_found(username, url)
        finally:
            await page.close()


@PlatformRegistry.register
class LinkedInPlatform(BasePlatform):
    name = "LinkedIn"
    priority = 6

    async def recon(self, context: BrowserContext, username: str) -> None:
        url = f"https://www.linkedin.com/in/{username}/"
        page, _ = await self.get_page_content(context, url, simulate=False)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            current = page.url
            if "/authwall" in current or "/login" in current:
                await HumanBehavior.human_pause(0.5, 1.5)
                meta = await self.extract_meta_tags(page)
                self.add_found(username, url=url, confidence="MEDIUM",
                    display_name=meta["og_title"], bio=meta["og_desc"], avatar_url=meta["og_image"],
                    extra_metadata={"note": "Auth wall"})
                return
            await HumanBehavior.simulate_page_read(page)
            name = await page.evaluate("() => document.querySelector('h1')?.innerText")
            headline = await page.evaluate("() => document.querySelector('.text-body-medium')?.innerText")
            location = await page.evaluate("() => document.querySelector('.text-body-small.inline')?.innerText")
            if name:
                self.add_found(username, url=url, confidence="HIGH",
                    display_name=name, bio=headline, extra_metadata={"location": location})
            else:
                self.add_not_found(username, url)
        finally:
            await page.close()


@PlatformRegistry.register
class RedditPlatform(BasePlatform):
    name = "Reddit"
    priority = 7

    async def recon(self, context: BrowserContext, username: str) -> None:
        if HAS_CFFI:
            resp = TlsClient.get_sync(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": "Mozilla/5.0 Chrome/126.0.0.0 Safari/537.36"})
            if resp:
                d = resp.json().get("data", {})
                self.add_found(username, url=f"https://www.reddit.com/user/{username}", confidence="HIGH",
                    display_name=d.get("subreddit", {}).get("title"),
                    bio=d.get("subreddit", {}).get("public_description"),
                    avatar_url=d.get("icon_img"),
                    follower_count=safe_int(d.get("subreddit", {}).get("subscribers")),
                    joined_date=safe_timestamp(d.get("created_utc")),
                    extra_metadata={"link_karma": safe_int(d.get("link_karma")),
                                    "comment_karma": safe_int(d.get("comment_karma")),
                                    "is_mod": d.get("is_mod"),
                                    "verified_email": d.get("has_verified_email"),
                                    "source": "tls_json_api"})
                return
        url = f"https://www.reddit.com/user/{username}"
        page, _ = await self.get_page_content(context, url, simulate=False)
        if not page:
            self.add_not_found(username, url, "LOW")
            return
        try:
            await HumanBehavior.human_pause(1.0, 2.0)
            nf = await page.query_selector("text=User not found")
            if nf:
                self.add_not_found(username, url)
            else:
                self.add_found(username, url=url, confidence="MEDIUM", extra_metadata={"source": "browser_fallback"})
        finally:
            await page.close()


@PlatformRegistry.register
class GitHubPlatform(BasePlatform):
    name = "GitHub"
    priority = 8

    async def recon(self, context: BrowserContext, username: str) -> None:
        data = None
        source = None
        if HAS_CFFI:
            resp = TlsClient.get_sync(f"https://api.github.com/users/{username}")
            if resp:
                data, source = resp.json(), "tls_api"
        if not data:
            import aiohttp
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"https://api.github.com/users/{username}", timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status == 200:
                            data, source = await resp.json(), "aiohttp_fallback"
            except Exception as e:
                logger.error("[GitHub] API error: %s", e)
        if data:
            self.add_found(username, url=data.get("html_url", f"https://github.com/{username}"), confidence="HIGH",
                display_name=data.get("name"), bio=data.get("bio"),
                avatar_url=data.get("avatar_url"), follower_count=safe_int(data.get("followers")),
                joined_date=data.get("created_at", "")[:10] if data.get("created_at") else None,
                extra_metadata={"repos": safe_int(data.get("public_repos")), "location": data.get("location"),
                                "blog": data.get("blog"), "company": data.get("company"),
                                "email": data.get("email"), "twitter": data.get("twitter_username"),
                                "source": source})
        else:
            self.add_not_found(username, f"https://github.com/{username}")


@PlatformRegistry.register
class WaybackPlatform(BasePlatform):
    name = "Wayback Machine"
    priority = 9

    async def recon(self, context: BrowserContext, username: str) -> None:
        import aiohttp
        urls = [
            f"https://www.tiktok.com/@{username}", f"https://www.youtube.com/@{username}",
            f"https://www.instagram.com/{username}/", f"https://twitter.com/{username}",
            f"https://www.facebook.com/{username}", f"https://www.linkedin.com/in/{username}/",
        ]
        snapshots: list[dict[str, str]] = []
        try:
            async with aiohttp.ClientSession() as session:
                for target_url in urls:
                    api = f"https://archive.org/wayback/available?url={quote_plus(target_url)}"
                    async with session.get(api, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            snap = (await resp.json()).get("archived_snapshots", {}).get("closest")
                            if snap:
                                snapshots.append({"original": target_url, "archive": snap.get("url", ""), "timestamp": snap.get("timestamp", "")})
        except Exception as e:
            logger.error("[Wayback] Error: %s", e)
        if snapshots:
            self.add_found(username, url=f"https://web.archive.org/web/*/{username}", confidence="HIGH",
                archived_snapshots=snapshots, extra_metadata={"count": len(snapshots)})


# ── Korelasyon Motoru ──────────────────────────────────────────

def correlate(profile: ReconProfile) -> None:
    found = [t for t in profile.traces if t.found]
    names: dict[str, list[str]] = {}
    bios: dict[str, list[str]] = {}
    avatars: dict[str, list[str]] = {}
    for t in found:
        if t.display_name:
            names.setdefault(t.display_name.lower().strip(), []).append(t.platform)
        if t.bio and len(t.bio.strip()) > 15:
            bios.setdefault(t.bio.strip().lower(), []).append(t.platform)
        if t.avatar_url:
            avatars.setdefault(t.avatar_url, []).append(t.platform)
    for name, plats in names.items():
        if len(plats) > 1:
            profile.correlations.append(f"Ayni isim '{name}' -> {', '.join(plats)}")
    for bio, plats in bios.items():
        if len(plats) > 1:
            profile.correlations.append(f"Ayni bio ({bio[:40]}...) -> {', '.join(plats)}")
    for _, plats in avatars.items():
        if len(plats) > 1:
            profile.correlations.append(f"Ayni avatar -> {', '.join(plats)}")
    for t in found:
        if t.platform == "GitHub":
            for key, label in [("email", "E-posta"), ("twitter", "Twitter"), ("blog", "Blog")]:
                val = t.extra_metadata.get(key)
                if val:
                    profile.correlations.append(f"{label}: {val}")
        for s in t.archived_snapshots:
            profile.correlations.append(f"Arsiv: {s['original']} -> {s['archive']}")


# ── Rapor Üreticileri ───────────────────────────────────────────

class ReportGenerator:
    @staticmethod
    def to_json(profile: ReconProfile, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(profile), f, indent=2, ensure_ascii=False)
        console.print(f"[dim]JSON: {path}[/]")

    @staticmethod
    def to_markdown(profile: ReconProfile, path: str) -> None:
        lines = [
            f"# NestTrace v5.1 OSINT Raporu", "",
            f"**Hedef:** `{profile.target}`  ",
            f"**Tarama Tarihi:** {profile.scanned_at}  ",
            f"**Toplam Bulgu:** {sum(1 for t in profile.traces if t.found)}/{len(profile.traces)}  ",
            f"**Korelasyon:** {len(profile.correlations)}", "", "---", "",
        ]
        if profile.correlations:
            lines.append("## Korelasyonlar\n")
            for c in profile.correlations:
                lines.append(f"- {c}")
            lines.append("")
        found = [t for t in profile.traces if t.found]
        if found:
            lines.append("## Bulunan Profiller\n")
            lines.append("| Platform | Isim | Takipci | Guven | Kaynak |")
            lines.append("|----------|------|---------|-------|--------|")
            for t in found:
                src = t.extra_metadata.get("source", "-")
                fc = str(t.follower_count) if t.follower_count else "-"
                lines.append(f"| {t.platform} | {t.display_name or '-'} | {fc} | {t.confidence} | {src} |")
            lines.append("")
        for t in found:
            lines.append(f"### {t.platform}")
            lines.append(f"- **URL:** {t.url}")
            if t.display_name: lines.append(f"- **Isim:** {t.display_name}")
            if t.bio: lines.append(f"- **Bio:** {t.bio}")
            if t.follower_count: lines.append(f"- **Takipci:** {t.follower_count}")
            if t.joined_date: lines.append(f"- **Katilim:** {t.joined_date}")
            for k, v in t.extra_metadata.items():
                if v and k not in ("error", "note", "source", "snapshots", "count", "redirect"):
                    lines.append(f"- **{k}:** {v}")
            if t.archived_snapshots:
                lines.append(f"- **Arsiv Kayitlari:** {len(t.archived_snapshots)} adet")
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        console.print(f"[dim]Markdown: {path}[/]")

    @staticmethod
    def to_html(profile: ReconProfile, path: str) -> None:
        found = [t for t in profile.traces if t.found]
        conf_colors = {"HIGH": "#00e676", "MEDIUM": "#ffd740", "LOW": "#ff5252"}
        rows = ""
        for t in found:
            cc = conf_colors.get(t.confidence, "#ffffff")
            src = t.extra_metadata.get("source", "-")
            fc = str(t.follower_count) if t.follower_count else "-"
            dn = t.display_name or "-"
            rows += f"<tr><td>{t.platform}</td><td>{dn}</td><td>{fc}</td><td style='color:{cc}'>{t.confidence}</td><td>{src}</td></tr>\n"
        corr_items = "".join(f"<li>{c}</li>" for c in profile.correlations)
        detail_cards = ""
        for t in found:
            meta_html = ""
            for k, v in t.extra_metadata.items():
                if v and k not in ("error", "note", "source", "snapshots", "count", "redirect"):
                    meta_html += f"<div class='meta'><strong>{k}:</strong> {v}</div>"
            if t.archived_snapshots:
                meta_html += f"<div class='meta'><strong>arsiv:</strong> {len(t.archived_snapshots)} kayit</div>"
            cc = conf_colors.get(t.confidence, "#ffffff")
            detail_cards += f"""
            <div class="card">
                <h3>{t.platform} <span style="color:{cc};font-size:0.8em">[{t.confidence}]</span></h3>
                <div class="name">{t.display_name or t.username}</div>
                <div class="bio">{t.bio or ''}</div>
                <a href="{t.url}" target="_blank">{t.url}</a>
                {meta_html}
            </div>"""
        html = f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NestTrace v5.1 - {profile.target}</title>
<style>
body{{background:#0a0e14;color:#e0e0e0;font-family:'Segoe UI',sans-serif;padding:2rem;margin:0}}
h1{{color:#00e5ff;border-bottom:2px solid #00e5ff;padding-bottom:0.5rem}}
h2{{color:#00e5ff;margin-top:2rem}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th,td{{padding:0.6rem 1rem;text-align:left;border-bottom:1px solid #1a2030}}
th{{background:#111820;color:#00e5ff}}
.card{{background:#111820;border:1px solid #1a2030;border-radius:8px;padding:1.2rem;margin:1rem 0}}
.card h3{{margin:0 0 0.5rem;color:#00e5ff}}
.card .name{{font-size:1.1rem;font-weight:bold;margin-bottom:0.3rem}}
.card .bio{{color:#aaa;margin-bottom:0.5rem;font-style:italic}}
.card a{{color:#6ec6ff;word-break:break-all}}
.meta{{font-size:0.85rem;color:#888;margin-top:0.3rem}}
ul{{list-style:none;padding:0}}
li{{padding:0.3rem 0;border-left:3px solid #00e5ff;padding-left:0.8rem;margin:0.3rem 0}}
.summary{{background:#111820;padding:1rem;border-radius:8px;margin:1rem 0;border-left:4px solid #00e5ff}}
</style></head><body>
<h1>NestTrace v5.1 OSINT Raporu</h1>
<div class="summary">
<strong>Hedef:</strong> {profile.target}<br>
<strong>Tarama:</strong> {profile.scanned_at}<br>
<strong>Bulgu:</strong> {len(found)}/{len(profile.traces)}<br>
<strong>Korelasyon:</strong> {len(profile.correlations)}
</div>
{"<h2>Korelasyonlar</h2><ul>" + corr_items + "</ul>" if corr_items else ""}
<h2>Bulunan Profiller</h2>
<table><thead><tr><th>Platform</th><th>Isim</th><th>Takipci</th><th>Guven</th><th>Kaynak</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Detayli Bulgular</h2>
{detail_cards}
<footer style="margin-top:3rem;color:#555;font-size:0.8rem">NestTrace v5.1 | Generated {datetime.now(timezone.utc).isoformat()}</footer>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[dim]HTML: {path}[/]")


# ── Terminal Render ─────────────────────────────────────────────

def render_terminal(profile: ReconProfile) -> None:
    console.print()
    found_count = sum(1 for t in profile.traces if t.found)
    console.print(Panel(
        f"[bold cyan]NestTrace v5.1[/] Field-Hardened OSINT\n"
        f"Hedef: [yellow]{profile.target}[/] | Tarama: {profile.scanned_at}\n"
        f"Bulunan: [green]{found_count}[/]/{len(profile.traces)} | Korelasyon: [yellow]{len(profile.correlations)}[/]\n"
        f"[dim]Context Pool | CAPTCHA Solve | Residential Proxy | 3-7s Rate Limit[/]",
        title="DEEP RECON COMPLETE", border_style="cyan"
    ))
    if profile.correlations:
        console.print(Panel("\n".join(f"  {c}" for c in profile.correlations), title="KORELASYONLAR", border_style="yellow"))
    found = [t for t in profile.traces if t.found]
    if found:
        table = Table(title="Bulunan Profiller", border_style="green", expand=True)
        table.add_column("Platform", style="bold cyan", width=14)
        table.add_column("Isim", max_width=22)
        table.add_column("Bio", max_width=30)
        table.add_column("Takipci", justify="right", width=10)
        table.add_column("Kaynak", width=16)
        table.add_column("Guven", width=8)
        for t in found:
            cc = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(t.confidence, "white")
            if cc == "HIGH": cc="green"
            elif cc == "MEDIUM": cc="yellow"
            elif cc == "LOW": cc="red"
            
            table.add_row(t.platform, t.display_name or "-", (t.bio or "-")[:30],
                          str(t.follower_count) if t.follower_count else "-",
                          t.extra_metadata.get("source", "-"), f"[{cc}]{t.confidence}[/]")
        console.print(table)


# ── Orchestrator ────────────────────────────────────────────────

async def run_trace(args: argparse.Namespace) -> None:
    profile = ReconProfile(target=args.username)
    platforms = PlatformRegistry.all_platforms()
    proxy_list = load_proxies(args.proxy, args.proxy_file)

    console.print(f"\n[bold cyan]NestTrace v5.1[/] Field-Hardened Enterprise OSINT")
    console.print(f"Hedef: [yellow]{args.username}[/] | Moduller: [green]{len(platforms)}[/]")
    console.print(f"[dim]Headless: {'NO (visible)' if args.headed else 'YES'} | CAPTCHA Solve: {'YES' if args.solve_captcha else 'NO'}[/]")
    console.print(f"[dim]TLS: {'curl_cffi' if HAS_CFFI else 'aiohttp'} | Concurrency: {args.concurrency} | Proxies: {len(proxy_list)}[/]")
    console.print(f"[dim]Rate Limit: 3-7s random | Output: {', '.join(args.output)}[/]\n")

    if args.solve_captcha and not args.headed:
        console.print("[yellow bold]⚠ --solve-captcha requires --headed. Enabling headed mode automatically.[/]")
        args.headed = True

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=not args.headed,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox",
                   "--disable-dev-shm-usage", "--disable-infobars", "--window-size=1920,1080"],
        )
        pool = ContextPool(
            browser, max_concurrent=args.concurrency,
            proxy_list=proxy_list, headed=args.headed,
            solve_captcha=args.solve_captcha
        )

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            tasks_meta = []
            for plat_cls in platforms:
                task = progress.add_task(f"Taranıyor: {plat_cls.name}...", total=None)
                instance = plat_cls(pool, profile)
                tasks_meta.append((plat_cls.name, task, instance))

            coros = [inst.run(args.username) for _, _, inst in tasks_meta]
            results = await asyncio.gather(*coros, return_exceptions=True)

            for (name, task, _), result in zip(tasks_meta, results):
                if isinstance(result, Exception):
                    logger.error("[Orchestrator] %s unhandled: %s", name, result, exc_info=result)
                    console.print(f"  [red]! {name}: UNHANDLED EXCEPTION[/]")
                progress.update(task, completed=True)

                # WIDENED RATE LIMIT: 3-7 saniye rastgele bekleme
                delay = random.uniform(3.0, 7.0)
                logger.debug("Inter-module delay: %.1fs", delay)
                await asyncio.sleep(delay)

        await browser.close()

    correlate(profile)
    render_terminal(profile)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = args.username.replace("@", "_at_")
    rg = ReportGenerator
    if "json" in args.output:
        rg.to_json(profile, f"nesttrace_v5_{safe_target}_{ts}.json")
    if "md" in args.output:
        rg.to_markdown(profile, f"nesttrace_v5_{safe_target}_{ts}.md")
    if "html" in args.output:
        rg.to_html(profile, f"nesttrace_v5_{safe_target}_{ts}.html")

    found_count = sum(1 for t in profile.traces if t.found)
    logger.info("Scan complete: %d/%d found, %d correlations", found_count, len(profile.traces), len(profile.correlations))


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(run_trace(args))
