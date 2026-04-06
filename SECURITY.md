# نموذج الأمان — Sibna Protocol v3.0.0

---

## نضج المشروع

> [!WARNING]
> Sibna v3.0.0 تطبيق تشفير مستقل يستخدم primitives مُدقَّقة من RustCrypto. **لم تُجرَ مراجعة أمنية خارجية مستقلة** على التنسيق البروتوكولي. يُنصح بمراجعة مستقلة قبل التكامل في بيئات حرجة.

---

## الحمايات المُطبَّقة

| الميزة | الآلية | الحالة |
|--------|--------|--------|
| **سرية البيانات** | ChaCha20-Poly1305 (256-bit) AEAD | ✅ |
| **مقاومة الكم** | هجين ML-KEM-768 + X25519 | ✅ افتراضي |
| **Key-Substitution / UKS** | BLAKE3 Transcript Binding في X3DH v10 | ✅ |
| **إخفاء هوية P2P** | Stealth Handshake — `StealthBundle` مُشفَّر | ✅ |
| **Forward Secrecy** | HMAC-SHA256 chain ratchet لكل رسالة | ✅ |
| **Post-Compromise Security** | DH ratchet بعد كل جولة | ✅ |
| **حماية كلمة المرور** | Argon2id (memory-hard) عند `feature = "argon2"` | ✅ |
| **حماية الذاكرة من Swap** | `mlock` (Unix) / `VirtualLock` (Windows) | ✅ |
| **تثبيت مفاتيح الأجهزة** | `device_id [u8;16]` في KDF — سلاسل ratchet مستقلة | ✅ |
| **Sealed Sender** | الخادم لا يرى هوية المُرسِل | ✅ |
| **نزاهة المغلَّف** | Ed25519 + SHA-512 على جميع الحقول بما فيها `is_dummy` | ✅ |
| **إخفاء حجم الرسالة** | كتل ثابتة 256B / 1KB / 4KB / 16KB | ✅ |
| **Cover Traffic** | توزيع أسي (Poisson) — متوسط 5 ثوانٍ | ✅ |
| **حد الـ Peers** | MAX_ACTIVE_PEERS = 500 في HybridRouter | ✅ |
| **حد حجم الرسالة** | 64 MiB قبل أي تخصيص ذاكرة | ✅ |
| **تحقق عناوين P2P** | رفض loopback / multicast / unspecified / port 0 | ✅ |
| **Graceful Shutdown** | `stop_discovery()` + `tokio::select!` | ✅ |
| **نزاهة Challenges** | HMAC-SHA256(challenge, jwt_secret) في sled | ✅ |
| **مقارنة HMAC ثابتة الزمن** | `subtle::ConstantTimeEq` في `prove_handler` | ✅ |
| **Rate Limiting متعدد الطبقات** | IP + Identity، حد عالمي + per-client | ✅ |

---

## القيود الحرجة

### 1. المراقب العالمي السلبي (GPA)

Sibna لا يوفر حماية كاملة من خصم يرى الشبكة الكاملة. Cover traffic وpadding يُصعِّبان التحليل لكن لا يمنعانه.

**التخفيف:** Tor عبر `P2pConfig { proxy: Some("socks5://127.0.0.1:9050"), .. }`.

### 2. TOFU

التبادل الأول عرضة لـ MITM. Stealth Handshake يُخفي هويتك من المراقب السلبي لكن لا يُثبت صحة هوية الطرف الآخر. **يجب التحقق من Safety Numbers خارج النطاق.**

### 3. إخفاء الهوية

ليس ميزة مدمجة. IP مرئي للخادم بشكل افتراضي. إخفاء الهوية فقط عبر Tor أو SOCKS5 صراحةً.

### 4. Timing Oracle في Rate Limiter (جزئي)

`RateLimiter::check()` يستخدم `RwLock` عالمي — فرق زمن صغير قابل للقياس يكشف وجود client_id. الإصلاح الكامل يتطلب إعادة هيكلة النوع بـ `DashMap` + `subtle::ConstantTimeEq` — مؤجل لـ v2.1.0.

### 5. قنوات الجانب (Side Channels)

`subtle` يحمي من timing attacks في الكود. لا ضمان ضد Spectre / Meltdown أو مسابر الأجهزة.

---

## المواصفات التشفيرية

| المعامل | الخوارزمية |
|---------|-----------|
| KEM (كمي) | ML-KEM-768 (FIPS 203) — Category 3 |
| DH (كلاسيكي) | X25519 — ~128-bit |
| AEAD | ChaCha20-Poly1305 — 256-bit |
| KDF | HKDF-SHA256 |
| Transcript Hash | BLAKE3 |
| التوقيع | Ed25519 |
| كلمة المرور | Argon2id |
| HMAC (Challenges) | HMAC-SHA256 |
| مقارنة ثابتة الزمن | `subtle` crate |

---

## الإبلاغ عن الثغرات

**لا تفتح issues عامة.**  
📧 `security@sibna.dev`
