# المساهمة في Sibna Protocol

## الأمان أولاً

هذه مكتبة تشفير. كل مساهمة يجب أن تتبع هذه القواعد.

### القواعد الحرجة

- **لا `.unwrap()` أو `.expect()` في كود الإنتاج** — استخدم `?` أو معالجة صريحة
- **لا تبعيات جديدة بدون مراجعة** — شغّل `cargo audit` قبل الإضافة
- **لا primitives تشفير مخصصة** — استخدم فقط crates مُدقَّقة من RustCrypto
- **كل Public API يجب توثيقه** — ملاحظات أمنية مطلوبة للدوال التشفيرية
- **جميع الاختبارات يجب أن تنجح** بما فيها `cargo clippy -- -D warnings`

### قواعد معالجة الأخطاء

**`InternalErrorDetailed`** مسموح به للتسجيل الداخلي فقط — لا يُرجَع للمستدعي الخارجي:

```rust
// ✅ صحيح
.map_err(|e| {
    warn!("OPERATION_FAILED: {:?}", e);   // تفاصيل في السجل الداخلي
    debug!("Details: {}", e);
    ProtocolError::InternalError          // عام للمستدعي
})?;

// ❌ خطأ — يُسرِّب تفاصيل داخلية
.map_err(|e| ProtocolError::InternalErrorDetailed { details: e.to_string() })?;
```

**المقارنات الأمنية** يجب أن تكون constant-time:

```rust
// ✅ صحيح — ثابت الزمن
use subtle::ConstantTimeEq;
if computed_mac.ct_eq(&stored_mac[..]).unwrap_u8() == 0 { ... }

// ❌ خطأ — timing oracle
if computed_mac_hex != stored_mac_hex { ... }
```

### إرسال التغييرات

1. Fork وأنشئ feature branch
2. `cargo test --all`
3. `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used`
4. `cargo fmt --all`
5. `cargo audit`
6. Pull request مع وصف واضح

### الإبلاغ عن الثغرات

**لا تفتح issues عامة.**  
📧 `security@sibna.dev`
