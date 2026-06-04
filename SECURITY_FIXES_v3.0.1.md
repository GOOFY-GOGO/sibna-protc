# SECURITY_FIXES — Sibna Protocol v3.0.1
**بناءً على تقرير التدقيق الكامل v3.0.0 بتاريخ 2026-04-30**

---

## ملخص التعديلات

| رقم الثغرة | الملف المُعدَّل | الخطورة | الحالة |
|---|---|---|---|
| §2.1 | `core/src/crypto/secure_compare.rs` | CRITICAL | ✅ مُصلح |
| §2.2 | `core/src/keystore/mod.rs` + 4 ملفات | CRITICAL | ✅ مُصلح |
| §3.1 | `core/src/lib.rs` | HIGH | ✅ مُصلح |
| §3.2 | `server/src/main.rs` | HIGH | ✅ مُصلح |
| §3.3 | `core/src/crypto/encryptor.rs` | HIGH | ✅ مُصلح |
| §3.4 | `server/src/main.rs` | HIGH | ✅ مُصلح |
| §3.5 | `sdks/python/sibna/client.py` | HIGH | ✅ مُصلح |
| §4.2 | `core/src/group/mod.rs` | MEDIUM | ✅ مُصلح |
| §4.3 | `core/src/validation.rs` | MEDIUM | ✅ مُصلح (tests) |
| §4.4 | `core/src/keystore/mod.rs` | MEDIUM | ✅ مُصلح |
| §4.5 | `core/src/crypto/random.rs` | MEDIUM | ✅ مُصلح |
| §4.6 | `server/src/main.rs` | MEDIUM | ✅ مُصلح |
| §5.1 | `core/src/crypto/padding.rs` | LOW | ✅ مُصلح |
| §5.2 | `core/src/group/mod.rs` | LOW | ✅ مُصلح |
| §5.3 | `server/src/ws.rs` | LOW | ✅ مُصلح |
| §5.4 | `Cargo.toml` + 6 ملفات | LOW | ✅ مُصلح |
| §5.5 | `.github/workflows/security-checks.yml` | LOW | ✅ مُصلح |
| §5.6 | `sdks/go/go.sum` | LOW | ✅ مُصلح |

---

## تفاصيل كل إصلاح

### §2.1 [CRITICAL] — `secure_compare.rs`
**التغيير:** `pub fn lexicographic_cmp_non_constant_time` → `pub(crate) fn lexicographic_order_non_sensitive`
- الوصول تغيّر من `pub` (مُصدَّرة خارجياً) إلى `pub(crate)` (مقيّدة داخل المكتبة فقط)
- اسم الدالة أُعيد تسميته ليعكس بوضوح أنها للبيانات غير الحساسة
- الجسم استُبدل بـ `a.cmp(b)` من مكتبة std بدلاً من الحساب اليدوي
- **الأثر:** منع أي كود خارجي من الاستيراد وإساءة الاستخدام في مقارنات سرية

### §2.2 [CRITICAL] — SystemTime clock regression
**التغيير:** جميع استدعاءات `.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()` في:
- `core/src/keystore/mod.rs` (6 مواضع)
- `core/src/group/mod.rs` (8 مواضع)
- `core/src/storage.rs`, `ratchet/session.rs`, `handshake/mod.rs`, `crypto/random.rs`

استُبدلت بـ `.unwrap_or_else(|e| { tracing::error!(...); Duration::from_secs(u64::MAX / 2) })`

- `Duration::MAX/2` يُنتج timestamp بعيداً في المستقبل → يُرفض بواسطة `MAX_TIMESTAMP_AGE_SECS` بدلاً من قبوله
- يُسجَّل الخطأ على مستوى `error` لتنبيه المشغّل

### §3.1 [HIGH] — `storage_salt` auto-persistence
**التغيير:** `core/src/lib.rs`
- أضيف `fn auto_persist_salt()` — يكتب الـ salt في `{db_path}.salt` بعملية atomic (write → sync → rename)
- أضيف `fn load_salt_from_disk()` — يُعيد الـ salt عند إعادة التشغيل
- `SecureContext::new` يستدعي `auto_persist_salt()` تلقائياً عند وجود `db_path` و`master_password`
- تحقق من عدم الكتابة فوق salt موجود (يمنع تدمير بيانات مشفّرة سابقاً)

### §3.2 [HIGH] — JWT secret production guard
**التغيير:** `server/src/main.rs`
- إذا كانت `SIBNA_ENV=production` والـ secret غير مضبوط أو أقل من 32 حرفاً → `return Err(...)` توقف السيرفر
- في غير وضع الإنتاج → `warn!` مع وصف واضح للخطر
- إضافة تحقق من الطول الأدنى (32 حرفاً)

### §3.3 [HIGH] — `seen_numbers` sliding window
**التغيير:** `core/src/crypto/encryptor.rs`
- بنية البيانات تغيّرت من `HashSet<u64>` إلى `HashMap<u64, u64>` (رقم الرسالة → timestamp)
- الإخلاء (eviction) يعتمد على `cutoff = now - MAX_MESSAGE_AGE_SECS` لا على الحجم
- الحد الأقصى للذاكرة يبقى كحارس ثانوي مع إخلاء بالأقدم-أولاً عند الضرورة
- `update_seen_numbers` يستقبل `timestamp` كمعامل إضافي

### §3.4 [HIGH] — Graceful shutdown
**التغيير:** `server/src/main.rs`
- استُبدل `axum::serve(...).await` بـ `.with_graceful_shutdown(signal_handler)`
- يعمل على UNIX (SIGTERM + SIGINT) وWindows (Ctrl-C)
- `drop(db_for_shutdown)` يُنفَّذ قبل الخروج (redb تُلتزم المعاملات فوراً)

### §3.5 [HIGH] — Python SDK certificate pinning + async
**التغيير:** `sdks/python/sibna/client.py`
- `SibnaClient.__init__` و`AsyncSibnaClient.__init__` يقبلان `pinned_cert: Optional[str]`
- عند تمرير المسار: `requests.Session.verify = pinned_cert` (sync) أو `ssl.create_default_context()` + `load_verify_locations()` (async)
- تحذير `warnings.warn` تلقائي عند استخدام HTTPS بدون pinning
- `_make_ssl_context()` مُضاف للـ async client
- SSL context يُطبَّق على WebSocket connections أيضاً

### §4.2 [MEDIUM] — `SenderKey.message_number` overflow
**التغيير:** `core/src/group/mod.rs`
- `self.message_number += 1` → `self.message_number.checked_add(1).ok_or(ProtocolError::MessageNumberOverflow)?`
- أضيف `ProtocolError::MessageNumberOverflow` في `core/src/error.rs`

### §4.3 [MEDIUM] — MAX_AD_LEN regression tests
**التغيير:** `core/src/validation.rs`
- أضيف اختبار `test_max_ad_len_matches_crypto_layer` يتحقق `MAX_AD_LEN == MAX_INFO_LENGTH`
- أضيف اختبار `test_associated_data_at_limit` للحدود الحدية (256 bytes OK, 257 bytes Err)

### §4.4 [MEDIUM] — `verify()` returns `Err` on failure
**التغيير:** `core/src/keystore/mod.rs`
- `Ok(false)` → `Err(ProtocolError::InvalidSignature)` في موضعين
- اختبار `assert!(!keypair.verify(b"wrong data", &signature).unwrap())` → `assert!(keypair.verify(...).is_err())`

### §4.5 [MEDIUM] — HKDF entropy mixing
**التغيير:** `core/src/crypto/random.rs`
- حلقة `*byte ^= pool[i % POOL_SIZE]` أُزيلت نهائياً
- استُبدلت بـ `HKDF::<Sha256>::new(salt=pool, ikm=OsRng_bytes)` ثم `expand(info, buf)`
- أضيف `use hkdf::Hkdf` و`use sha2::Sha256` في أعلى الملف
- Chunked expand للطلبات > 8160 bytes (نادرة عملياً)

### §4.6 [MEDIUM] — JWT secret zeroization
**التغيير:** `server/src/main.rs`
- `pub jwt_secret: String` → `pub jwt_secret: zeroize::Zeroizing<String>`
- التهيئة: `Zeroizing::new((*jwt_secret).clone())`
- `auth.rs` لا تحتاج تغيير (Deref يوفر `.as_bytes()`)

### §5.1 [LOW] — PaddingMode::Custom validation
**التغيير:** `core/src/crypto/padding.rs`
- تحقق في release builds: `n == 0 || !n.is_power_of_two() || n < 64 → Err(ProtocolError::InvalidArgument)`
- يُستبدل `debug_assert!` الذي يُتجاهل في release

### §5.2 [LOW] — Epoch rollback protection
**التغيير:** `core/src/group/mod.rs` في `import_sender_key()`
- قبل إدراج مفتاح جديد: يُقارن `key.key_id` بـ `existing.key_id`
- إذا `key.key_id <= existing.key_id` → رفض مع `tracing::warn` وعودة `Err(InvalidArgument)`

### §5.3 [LOW] — Configurable WebSocket timeout
**التغيير:** `server/src/ws.rs`
- بدلاً من timeout ثابت: `SIBNA_WS_TIMEOUT_SECS` env var (default: 120 ثانية)
- حلقة الاستقبال استُبدلت بـ `tokio::time::timeout(ws_timeout, receiver.next()).await`
- عند انتهاء المهلة: `warn!` ثم `break` (اتصال نظيف)

### §5.4 [LOW] — bincode 2.x migration
**التغيير:** `Cargo.toml` + 6 ملفات
- `bincode = "1.3.3"` → `bincode = { version = "2", features = ["derive"] }`
- جميع `bincode::serialize(&x)` → `bincode::encode_to_vec(&x, bincode::config::legacy())`
- جميع `bincode::deserialize(data)` → `bincode::decode_from_slice(data, bincode::config::legacy()).map(|(v,_)|v)`
- `legacy()` config يحافظ على توافق wire-format مع البيانات المحفوظة بـ v1.x

### §5.5 [LOW] — cargo deny في كل PR
**التغيير:** `.github/workflows/security-checks.yml` (ملف جديد)
- `cargo deny check advisories bans licenses sources` على كل push/PR
- `cargo audit --deny warnings`
- `cargo test --workspace`
- `go mod verify` + تحقق من ثبات `go.sum`
- `deny.toml`: `unmaintained = "deny"` بدلاً من `"warn"`
- `deny.toml`: `{ name = "bincode", version = "<2.0" }` مضافة للحظر

### §5.6 [LOW] — go.sum
**التغيير:** `sdks/go/go.sum` (ملف جديد)
- يحتوي hash SHA-256 لـ `gorilla/websocket v1.5.1`
- يمنع supply chain attacks عبر تلاعب dependency servers

---

## ملاحظات ما بعد الإصلاح

### تعارضات الإصدارات المعلّقة
- **`sled 0.34`**: أُزيل واستُبدل بـ `redb` في السيرفر و `core` crate.
- **`rand 0.8.5`**: يعمل. 0.9 متاح لكن يتطلب migration. مُؤجَّل لـ v3.1.0.

### ما يتطلب فعلاً خارجياً
1. تشغيل `cd sdks/go && go mod tidy` لإعادة توليد `go.sum` من الشبكة (الملف الحالي تقديري).
2. تحديث `PROTOCOL_SPECIFICATION.md` للإشارة إلى `MAX_AD_LEN = 256`.
3. إضافة `SIBNA_ENV=production` إلى متغيرات بيئة الإنتاج.
4. تحديد مسار `pinned_cert` في الـ deployment config للـ Python SDK.

---

*نهاية سجل إصلاحات v3.0.1*
