"""
Dawena Downloader Backend - FastAPI
- POST /api/info  : يحلل أي لينك ويرجع فيديوهات + صور + ملفات + جودات
- GET  /api/download : يجيب رابط التحميل المباشر لجودة معينة (redirect)
- POST /api/mp3 : يحول الفيديو لصوت mp3 ويرجعه
- POST /api/scan : يفحص الرابط عبر VirusTotal
يدعم: YouTube, TikTok, Instagram, Facebook, X, وأي موقع عام
"""

import os
import re
import base64
import tempfile
import subprocess
import requests
from urllib.parse import urljoin, urlparse
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse, JSONResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup

try:
    import yt_dlp
    HAS_YTDLP = True
except ImportError:
    HAS_YTDLP = False

app = FastAPI(title="Dawena Downloader API")

# السماح للفرونت إند (Vercel + localhost) بالوصول
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

FILE_EXTS = (".pdf", ".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx",
             ".ppt", ".pptx", ".txt", ".csv", ".apk", ".exe", ".mp4", ".mp3",
             ".avi", ".mkv", ".mov")


class InfoRequest(BaseModel):
    url: str


class ScanRequest(BaseModel):
    url: str


def _is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url.strip())
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def extract_with_ytdlp(url: str) -> dict | None:
    """يحاول استخراج معلومات الفيديو عبر yt-dlp. يرجع None لو الموقع مش فيديو مدعوم."""
    if not HAS_YTDLP:
        return None
    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "noplaylist": True,
        "extract_flat": False,
        "socket_timeout": 20,
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            if not info:
                return None
            # لو بلاي ليست، خد أول عنصر فقط في الـ MVP
            if info.get("_type") == "playlist" and info.get("entries"):
                info = next((e for e in info["entries"] if e), info)

            title = info.get("title", "بدون عنوان")
            thumbnail = info.get("thumbnail", "")
            duration = info.get("duration")
            uploader = info.get("uploader") or info.get("channel") or ""

            videos = []
            audios = []
            seen_res = set()

            for f in (info.get("formats") or []):
                f_url = f.get("url")
                if not f_url:
                    continue
                ext = (f.get("ext") or "").lower()
                vcodec = f.get("vcodec", "")
                acodec = f.get("acodec", "")
                height = f.get("height")
                filesize = f.get("filesize") or f.get("filesize_approx")

                # فيديو (فيه صورة)
                if vcodec and vcodec != "none" and ext in ("mp4", "webm", "mkv", "mov"):
                    label = f"{height}p" if height else (f.get("format_note") or ext)
                    if height and height in seen_res and filesize is None:
                        pass
                    videos.append({
                        "format_id": f.get("format_id", ""),
                        "quality": label,
                        "height": height or 0,
                        "ext": ext,
                        "filesize": filesize,
                        "fps": f.get("fps"),
                        "direct_url": f_url,
                        "has_audio": acodec not in (None, "none"),
                    })
                    if height:
                        seen_res.add(height)
                # صوت فقط
                elif (vcodec in (None, "none")) and acodec not in (None, "none"):
                    audios.append({
                        "format_id": f.get("format_id", ""),
                        "ext": ext,
                        "abr": f.get("abr"),
                        "filesize": filesize,
                        "direct_url": f_url,
                    })

            # رتب الفيديوهات من الأعلى جودة للأقل
            videos = sorted(videos, key=lambda x: x["height"], reverse=True)
            # احتفظ بأفضل نسخة لكل جودة لتقليل الزحمة
            uniq = {}
            for v in videos:
                key = (v["quality"], v["ext"])
                if key not in uniq:
                    uniq[key] = v
            videos = list(uniq.values())

            # صور: الثامبنيل + أي صور إضافية
            images = []
            if thumbnail:
                images.append({"url": thumbnail, "alt": title})
            for th in (info.get("thumbnails") or [])[-3:]:
                if th.get("url") and th["url"] != thumbnail:
                    images.append({"url": th["url"], "alt": title})

            if not videos and not audios:
                return None

            return {
                "source": "ytdlp",
                "platform": info.get("extractor_key") or info.get("extractor") or "video",
                "title": title,
                "thumbnail": thumbnail,
                "uploader": uploader,
                "duration": duration,
                "original_url": url,
                "videos": videos,
                "audios": audios,
                "images": images,
                "files": [],
            }
    except Exception:
        return None


def scrape_generic_site(url: str) -> dict:
    """كشط أي موقع عام: يجمع <video> و <img> وروابط الملفات."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DawenaBot/1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"تعذر فتح الرابط: {e}")

    soup = BeautifulSoup(r.text, "lxml")
    title = (soup.title.string.strip() if soup.title and soup.title.string else url)

    # og:image / og:video (الأدق)
    images = []
    videos = []
    files = []

    for meta in soup.find_all("meta"):
        prop = (meta.get("property") or meta.get("name") or "").lower()
        content = meta.get("content", "")
        if not content:
            continue
        full = urljoin(url, content)
        if prop in ("og:image", "twitter:image"):
            images.append({"url": full, "alt": title})
        elif prop in ("og:video", "og:video:url", "twitter:player:stream"):
            videos.append({
                "format_id": "og-video",
                "quality": "مباشر",
                "height": 0,
                "ext": full.split(".")[-1].split("?")[0][:4] or "mp4",
                "filesize": None,
                "direct_url": full,
                "has_audio": True,
            })

    # <video> و <source>
    for v in soup.find_all("video"):
        src = v.get("src")
        if src:
            videos.append({"format_id": "html5", "quality": "مباشر", "height": 0,
                           "ext": "mp4", "filesize": None,
                           "direct_url": urljoin(url, src), "has_audio": True})
        for s in v.find_all("source"):
            if s.get("src"):
                videos.append({"format_id": "html5-source", "quality": s.get("label") or s.get("size") or "مباشر",
                               "height": 0, "ext": "mp4", "filesize": None,
                               "direct_url": urljoin(url, s["src"]), "has_audio": True})

    # <img>
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src")
        if not src or src.startswith("data:"):
            continue
        full = urljoin(url, src)
        # تجاهل الأيقونات الصغيرة
        if any(x in full.lower() for x in ("logo", "icon", "sprite", "1x1")):
            continue
        images.append({"url": full, "alt": img.get("alt", title)})

    # روابط ملفات مباشرة
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(url, href)
        low = full.lower().split("?")[0]
        if low.endswith(FILE_EXTS):
            files.append({"url": full, "name": a.get_text(strip=True)[:80] or full.split("/")[-1]})

    # إزالة التكرار
    images = list({i["url"]: i for i in images}.values())[:30]
    videos = list({v["direct_url"]: v for v in videos}.values())[:20]
    files = list({f["url"]: f for f in files}.values())[:30]

    return {
        "source": "generic",
        "platform": urlparse(url).netloc,
        "title": title,
        "thumbnail": images[0]["url"] if images else "",
        "uploader": "",
        "duration": None,
        "original_url": url,
        "videos": videos,
        "audios": [],
        "images": images,
        "files": files,
    }


@app.get("/")
def health():
    return {"status": "ok", "service": "Dawena Downloader API", "ytdlp": HAS_YTDLP}


@app.post("/api/info")
def api_info(body: InfoRequest):
    url = (body.url or "").strip()
    if not _is_valid_url(url):
        raise HTTPException(status_code=400, detail="الرابط غير صالح. الصق رابط يبدأ بـ http")
    # 1) جرب yt-dlp (يوتيوب/تيك توك/انستا/فيسبوك/X)
    data = extract_with_ytdlp(url)
    if data:
        return JSONResponse(data)
    # 2) fallback: كشط عام
    return JSONResponse(scrape_generic_site(url))


@app.get("/api/download")
def api_download(url: str = Query(...), format_id: str = Query(default="best")):
    """يرجع redirect لرابط التحميل المباشر بأفضل جودة مطلوبة."""
    if not _is_valid_url(url):
        raise HTTPException(status_code=400, detail="الرابط غير صالح")
    if HAS_YTDLP:
        try:
            ydl_opts = {"quiet": True, "no_warnings": True, "noplaylist": True}
            fmt = "best"
            if format_id and format_id not in ("best", "og-video", "html5", "html5-source"):
                fmt = format_id
            elif format_id == "best":
                fmt = "best[ext=mp4]/best"
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                if info and info.get("_type") == "playlist" and info.get("entries"):
                    info = next((e for e in info["entries"] if e), info)
                # لو المستخدم اختار format_id معين، هاته
                if format_id not in ("best",):
                    for f in (info.get("formats") or []):
                        if f.get("format_id") == format_id and f.get("url"):
                            return RedirectResponse(f["url"])
                # وإلا استخرج أفضل رابط بالصيغة المطلوبة
                ydl2_opts = {"quiet": True, "format": fmt, "noplaylist": True}
                with yt_dlp.YoutubeDL(ydl2_opts) as ydl2:
                    info2 = ydl2.extract_info(url, download=False)
                    if info2 and info2.get("url"):
                        return RedirectResponse(info2["url"])
                    if info2 and info2.get("requested_downloads"):
                        return RedirectResponse(info2["requested_downloads"][0]["url"])
                # fallback: أول فورمات
                for f in (info.get("formats") or []):
                    if f.get("url"):
                        return RedirectResponse(f["url"])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"تعذر تجهيز التحميل: {e}")
    # لو رابط مباشر أصلا
    return RedirectResponse(url)


@app.post("/api/mp3")
def api_mp3(body: InfoRequest):
    """يحول الفيديو إلى mp3 ويرجعه كملف. يحتاج ffmpeg على السيرفر."""
    url = (body.url or "").strip()
    if not _is_valid_url(url):
        raise HTTPException(status_code=400, detail="الرابط غير صالح")
    if not HAS_YTDLP:
        raise HTTPException(status_code=500, detail="yt-dlp غير مثبت على السيرفر")
    tmpdir = tempfile.mkdtemp(prefix="dawena_")
    out_tpl = os.path.join(tmpdir, "%(title).50s.%(ext)s")
    try:
        subprocess.run(
            ["yt-dlp", "-x", "--audio-format", "mp3", "--audio-quality", "0",
             "-o", out_tpl, "--no-playlist", url],
            check=True, timeout=300, capture_output=True,
        )
        mp3s = [f for f in os.listdir(tmpdir) if f.lower().endswith(".mp3")]
        if not mp3s:
            raise HTTPException(status_code=500, detail="فشل التحويل إلى mp3")
        path = os.path.join(tmpdir, mp3s[0])
        return FileResponse(path, media_type="audio/mpeg", filename=mp3s[0])
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="التحويل أخذ وقتا طويلا، جرب فيديو أقصر")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=400, detail=f"تعذر تحويل الفيديو: {e.stderr.decode()[:300]}")


@app.post("/api/scan")
def api_scan(body: ScanRequest):
    """يفحص الرابط عبر VirusTotal. يحتاج VIRUSTOTAL_API_KEY."""
    url = (body.url or "").strip()
    if not _is_valid_url(url):
        raise HTTPException(status_code=400, detail="الرابط غير صالح")
    if not VIRUSTOTAL_API_KEY:
        return JSONResponse({
            "scanned": False,
            "verdict": "unknown",
            "message": "لم يتم ضبط مفتاح VirusTotal (VIRUSTOTAL_API_KEY). الفحص معطل حاليا.",
        })
    try:
        # 1) إرسال الرابط للفحص
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.post("https://www.virustotal.com/api/v3/urls",
                          data={"url": url}, headers=headers, timeout=20)
        r.raise_for_status()
        analysis_id = r.json()["data"]["id"]
        # 2) جلب النتيجة
        r2 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                          headers=headers, timeout=20)
        r2.raise_for_status()
        stats = r2.json()["data"]["attributes"].get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        verdict = "clean" if (malicious == 0 and suspicious == 0) else ("suspicious" if malicious == 0 else "malicious")
        return JSONResponse({
            "scanned": True,
            "verdict": verdict,
            "stats": stats,
            "message": "نظيف ✅" if verdict == "clean" else ("مشبوه ⚠️" if verdict == "suspicious" else "خطير ⛔"),
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل الفحص: {e}")


# للتشغيل المحلي: uvicorn main:app --reload
