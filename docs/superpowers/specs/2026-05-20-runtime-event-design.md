# RuntimeEvent — Upstream Evidence Events for the Audit Chain

**Date:** 2026-05-20
**Status:** Draft, awaiting user approval
**Scope:** Add a tipli upstream-evidence record type (`RuntimeEvent`) that is signed verbatim into the existing Ed25519 audit chain alongside `Decision` records.
**Out of scope:** ROS2 subscriber bridge, third-party adapter implementations, new MCP tools, any change to the existing `Decision` schema.

---

## 1. Goal

Kernel'in audit chain'i şu an sadece `Decision` kayıtlarını içeriyor. Upstream sistemler (sensor monitor, guard middleware, external policy adapter) tarafından üretilen kanıt event'leri **tipsiz dict** olarak yazılıyor veya hiç yazılmıyor. Bu durum:

1. MCP query'lerini zayıflatıyor — `event_type` ve `source` gibi semantik field'lar yok.
2. Karma evidence (Decision + upstream signal) için verifiable bir log yok.
3. EU AI Act Article 12 ("logging of events relevant to the operation of the high-risk AI system") için yetersiz.

Bu spec, **`RuntimeEvent`** adında ikinci bir kayıt türü tanımlıyor; aynı Ed25519 imza ve SHA-256 hash-link şeması ile chain'e yazılıyor, böylece tek bir doğrulanabilir karma log oluşuyor.

---

## 2. Out of scope (açık ifadeyle)

- **Decision schema'sı değişmez** — geriye uyumluluk korunur. Mevcut chain dosyaları olduğu gibi okunabilir.
- **Yeni MCP tool eklenmez** — mevcut 5 tool RuntimeEvent'i de döndürecek şekilde genişletilir.
- **ROS2 subscriber yazılmaz** — bu spec sadece tipli kayıt + zincir entegrasyonu.
- **Üçüncü taraf adapter yazılmaz** — `append_runtime_event()` API'si dış kullanıcılar için hazır olur, ama ilk caller'lar manuel test fixture'ları olacak.

---

## 3. RuntimeEvent vs Decision — taşıma şeması

| Boyut | `Decision` | `RuntimeEvent` |
|---|---|---|
| Üretici | kernel'in karar grafiği | Dış sistemler (sensor monitor, guard middleware, policy adapter) |
| Anlamı | "Şunu yaptım" | "Şunu gözlemledim" |
| Ana field'ları | `action`, `threat_level`, `policy_version_id` | `event_type`, `source`, `source_id`, `payload`, `context` |
| Discriminator | `record_type` field'ı YOK | `record_type: "runtime_event"` |
| İmza şeması | Ed25519, SHA-256 hash-link | Aynı şema |
| Aynı zincirde mi? | Evet — karma JSONL | Evet — karma JSONL |

---

## 4. Tek chain_index sırası (KRİTİK)

`chain_index` **tek bir monotonik counter**'dır — `Decision` ve `RuntimeEvent` arasında paylaşılır. İki ayrı sıra YOKTUR.

Örneğin karma bir zincir şöyledir:

```
chain_index=0  Decision        prev_hash=null
chain_index=1  RuntimeEvent    prev_hash=<hash@0>
chain_index=2  RuntimeEvent    prev_hash=<hash@1>
chain_index=3  Decision        prev_hash=<hash@2>
chain_index=4  RuntimeEvent    prev_hash=<hash@3>
```

`append_runtime_event()` ve mevcut `sign_decision()`+yazma yolu **dosyanın son satırına** bakıp `chain_index = last.chain_index + 1` üretir. Tip-spesifik counter yoktur. `verify_chain()` mevcut implementasyonu bunu zaten karşılar (linear scan, expected_index += 1 her entry için).

Bu kuralı **mixed chain test'i** explicit doğrular.

---

## 5. Schema — `shared/schemas.py`

```python
import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# Module-level constant — RuntimeEvent.payload JSON-serialized byte limit.
# Audit chain bloat'u önler; sensor monitor / guard middleware için 64KB
# yetiyor (örneğin: 100 detection point + metadata). Configurable: production
# operators bu sabiti environment-spesifik bir değerle override edebilir.
RUNTIME_EVENT_PAYLOAD_MAX_BYTES = 64 * 1024  # 64 KB


class PayloadTooLargeError(ValueError):
    """Raised when RuntimeEvent.payload exceeds RUNTIME_EVENT_PAYLOAD_MAX_BYTES.

    Subclass of ValueError so Pydantic wraps it in ValidationError when raised
    inside a field_validator. The original exception type is preserved in the
    error context for test assertions and structured logging.
    """


class RuntimeEvent(BaseModel):
    """Upstream evidence event from external systems (sensor monitors,
    guard middleware, external policy adapters). Signed verbatim into
    the audit chain alongside Decision records."""

    # Discriminator — sadece RuntimeEvent'te var. Decision dict'leri bu
    # field'a sahip olmadığı için "decision" implicit olarak çıkar.
    record_type: Literal["runtime_event"] = "runtime_event"

    event_type: str          # "guardrail_downgrade" | "sensor_anomaly" | "policy_violation"
    source: str              # logical source name e.g. "kinematic_guard", "lidar_monitor"
    source_id: str = Field(min_length=1, max_length=256)
                             # stable instance ID (UUID veya hostname+namespace).
                             # min_length=1: boş source_id zincire girmemeli;
                             # max_length=256: mantıksız uzunlukları engeller.
    timestamp_iso: str
    payload: dict[str, Any]  # source-defined schema, kept verbatim
    context: dict[str, Any] = Field(default_factory=dict)

    # Audit chain fields (chain tarafından doldurulur)
    signature: str | None = None
    prev_hash: str | None = None
    payload_hash: str | None = None
    chain_index: int = 0
    policy_version_id: str | None = None

    @field_validator("payload")
    @classmethod
    def _validate_payload_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        size = len(json.dumps(v, separators=(",", ":")).encode("utf-8"))
        if size > RUNTIME_EVENT_PAYLOAD_MAX_BYTES:
            raise PayloadTooLargeError(
                f"payload exceeds {RUNTIME_EVENT_PAYLOAD_MAX_BYTES} bytes "
                f"(got {size} bytes); use file references or chunking for "
                f"larger evidence."
            )
        return v
```

### Tasarım notları

- `record_type` `Literal["runtime_event"]` — instance yarattığında değiştirilemez, JSON'da string olarak çıkar, Decision'da bulunmadığı için ayırt edici.
- `payload` limit'i sadece `payload` için — `context` daha küçük, ilave metadata için (timestamps, correlation IDs, vb.).
- `source_id` `min_length=1, max_length=256` — boş veya mantıksız uzun değerleri engeller. Aynı `source` adıyla birden fazla instance varsa (örn. 3 lidar) ayırt edici. UUID veya hostname+namespace formatı serbest.
- `PayloadTooLargeError` özel bir exception sınıfı — generic `ValueError`'dan ayrıştırılabilir, structured logging ve test assertion'ları için anlamlı. `ValueError` subclass'ı olduğu için Pydantic `field_validator`'da raise edildiğinde `ValidationError` içine sarılır; ham exception `__cause__` üzerinden erişilebilir.

---

## 6. `append_runtime_event` — `services/decision/audit_chain.py`

```python
def append_runtime_event(
    event: RuntimeEvent,
    chain_path: Path,
    signing_key: ed25519.Ed25519PrivateKey,
    policy_version_id: str,
) -> RuntimeEvent:
    """Sign and append a RuntimeEvent to the JSONL audit chain.

    Reads the last line of chain_path (if any) to derive prev_hash and
    chain_index. Calls the existing (type-agnostic) sign_decision() on
    the model dict, then appends a single JSON line to chain_path.

    Args:
        event: the RuntimeEvent to sign. policy_version_id and chain
               fields will be overwritten.
        chain_path: JSONL chain file. Created if absent.
        signing_key: Ed25519 private key (same key used for Decisions).
        policy_version_id: bound to this event for later policy audit.

    Returns:
        A new RuntimeEvent instance with signature, prev_hash,
        payload_hash, chain_index, and policy_version_id filled in.
    """
```

### Davranış sözleşmesi

1. **Payload size validation:** Validates payload size ≤ 64KB (configurable via `RUNTIME_EVENT_PAYLOAD_MAX_BYTES`). Raises `PayloadTooLargeError` if exceeded. Bu kontrol Section 5'teki schema validator'ı tarafından yapılır — `RuntimeEvent` instance'ı oluşturulurken fire eder, bu yüzden `append_runtime_event` çağrısı oversized bir event'i ASLA persist etmez. **Rationale:** prevents chain file bloat from misbehaving sources. Bu, Decision'da olmayan **asimetrik bir koruma**dır: Decision senin policy engine'inden çıkar (kontrollü), RuntimeEvent dış sistemden gelir (kontrol edilemez) — kontrol asimetrisi koruma asimetrisini gerektirir.
2. **Chain field over-write:** `signature`, `prev_hash`, `payload_hash`, `chain_index`, `policy_version_id` — bunların **hepsi** fonksiyon tarafından doldurulur/üzerine yazılır. Caller'ın bu field'lardaki değerleri yok sayılır. (Pydantic default'ları da geçersiz olur.) Malicious veya buggy caller'lar zincir bütünlüğünü bozamaz — Section 9'da `test_caller_provided_chain_fields_are_overwritten` bunu kanıtlar.
3. **prev_hash** — son satır varsa onun `payload_hash`'i; yoksa `None` (genesis).
4. **chain_index** — son satır varsa onun `chain_index + 1`; yoksa `0`. Decision/RuntimeEvent ayrımı yapmaz — Section 4'teki tek monotonik counter kuralı.
5. **policy_version_id** — parametreden alınır.
6. **sign_decision()** çağrılır — generic dict üzerinde çalıştığı için RuntimeEvent dict'i ile çalışır.
7. JSON line append edilir (`open("a")` + flush). **Single-writer varsayımı:** bu fonksiyon dosya kilitlemesi YAPMAZ. Eşzamanlı yazıcılar için arayan taraf locking sağlamalı (örn. fcntl, ya da tek bir audit-writer service). Bu varsayım Decision tarafı için de geçerli, kernel'in mevcut runtime modeli ile uyumlu.
8. Return değeri: imza/hash/index field'ları dolu yeni RuntimeEvent instance.

### `sign_decision` adı yanıltıcı mı?

Evet, ama yeniden adlandırma riski yüksek (Decision tarafı üretimde). Docstring'i güncellenecek:

```python
def sign_decision(decision: dict[str, Any], ...) -> dict[str, Any]:
    """Sign an audit chain entry with Ed25519 + SHA-256 hash linking.

    Polymorphic: works for Decision dicts AND RuntimeEvent dicts. The
    function does not inspect record type; it canonicalizes the dict
    (excluding signature/payload_hash), computes payload_hash, signs the
    canonical JSON, and returns the dict with signature + payload_hash
    + prev_hash + chain_index set.
    """
```

---

## 7. Verification

`verify_decision`, `verify_chain` zaten **tip-agnostik** (sadece signature + hash-link kontrolü). Yeni mantık gerekmez.

**Yapılacaklar:**
- `verify_decision` docstring'ine "polymorphic" notu.
- `verify_chain` docstring'ine "handles mixed Decision/RuntimeEvent chains; chain_index is a single shared sequence" notu.
- **Thin alias:** `verify_runtime_event(event: dict, public_key) -> bool` — sadece `verify_decision`'ı çağırır. Spec'in "yeni bir verify_runtime_event fonksiyonu ekle" alternatifini karşılar; semantik karışıklık olmaz.

---

## 8. MCP entegrasyonu

### 8.1 `AuditChainStore.filter()` (`kernel/audit/store.py`)

Field-aware filtreler. Bir filtre parametresi geldiğinde:
- `action` veya `threat_level` → SADECE Decision döner (RuntimeEvent'ler elenir, çünkü o field'lar yok).
- `event_type` veya `source` → SADECE RuntimeEvent döner (Decision'lar elenir, çünkü o field'lar yok).
- `start_time`, `end_time` → her ikisine uygulanır (timestamp_iso ortak).
- Hiçbir filtre yoksa → her iki tip de döner.

Implementasyon: `filter()` her entry için `record_type == "runtime_event"` mi bakar; filtre alanına göre uygunsa atlar.

### 8.2 `query_events` tool (`kernel/mcp/tools.py`)

```python
@app.tool(description="Query audit events (Decisions + RuntimeEvents) with field-aware filters.")
def query_events(
    start_time: str | None = None,
    end_time: str | None = None,
    action: str | None = None,        # Decision-only filter
    threat_level: str | None = None,  # Decision-only filter
    event_type: str | None = None,    # YENİ — RuntimeEvent-only filter
    source: str | None = None,        # YENİ — RuntimeEvent-only filter
    limit: int = 100,
) -> list[dict]:
    ...
```

### 8.3 `EventSummary` (`kernel/mcp/schemas.py`)

```python
class EventSummary(BaseModel):
    id: int
    timestamp_iso: str
    record_type: Literal["decision", "runtime_event"] = "decision"
    action: str | None = None         # Decision'da var
    threat_level: str | None = None   # Decision'da var
    event_type: str | None = None     # YENİ — RuntimeEvent'te var
    source: str | None = None         # YENİ — RuntimeEvent'te var
    sig_valid: bool | None = None
```

`_summary()` helper'ı entry'nin `record_type` field'ına bakar ve uygun field'ları doldurur.

### 8.4 `search_events` — değişiklik minimal

Recursive flatten zaten tip-agnostik, otomatik olarak RuntimeEvent içeriğini de bulur. Sadece `SearchHit` output'una `record_type` eklenir ki sonuç kullanıcısı tipini görsün.

### 8.5 `get_event` — değişiklik yok

Zaten tek bir entry döner. `event` field'ı dict olduğu için `record_type` zaten içinde gelir.

---

## 9. Test planı — `tests/test_runtime_event.py`

| Test | Doğrulanan |
|---|---|
| `test_runtime_event_creation` | Pydantic instantiation, default field'lar (`record_type="runtime_event"`, `context={}`, `chain_index=0`) |
| `test_payload_size_limit_enforced` | 64KB üstü payload `PayloadTooLargeError` atar (Pydantic `ValidationError` içinde sarılı); sınırın 1 byte altı geçer |
| `test_source_id_constraints` | `source_id=""` ValidationError; 257 char `source_id` ValidationError; 1 char ve 256 char sınırları kabul edilir |
| `test_append_single_runtime_event` | Boş zincire 1 RuntimeEvent append: `chain_index=0`, `prev_hash=None`, `verify_decision()` `True` |
| `test_mixed_chain_decision_then_runtime` | Decision (idx=0) → RuntimeEvent (idx=1) → Decision (idx=2): `verify_chain()` `(True, None)` döner |
| `test_prev_hash_integrity_mixed` | RuntimeEvent (idx=0) → Decision (idx=1) → RuntimeEvent (idx=2): her entry'nin `prev_hash`'i bir önceki entry'nin `payload_hash`'ine eşit |
| `test_payload_tampering_detected` | Signed RuntimeEvent'in `payload`'unu disk üstünde değiştir; `verify_decision()` `False` döner |
| `test_caller_provided_chain_fields_are_overwritten` | RuntimeEvent `signature="fake"`, `prev_hash="ff"`, `chain_index=999`, `payload_hash="bad"`, `policy_version_id="injected"` ile oluşturulup `append_runtime_event` çağrılır. Dönen instance'ta bu beş field'ın da fonksiyon tarafından override edildiği doğrulanır (caller's values discarded). **Güvenlik kontratı:** malicious veya buggy caller'lar zincir bütünlüğünü bozamaz. |
| `test_mcp_query_events_filters_by_event_type` | Karma zincir: `query_events(event_type="sensor_anomaly")` sadece o RuntimeEvent'leri döndürür, Decision'lar dahil olmaz; `query_events(action="allow")` sadece Decision'ları döndürür |

---

## 10. Dosya değişiklik listesi

| Dosya | Değişiklik |
|---|---|
| `shared/schemas.py` | `RuntimeEvent` modeli + `RUNTIME_EVENT_PAYLOAD_MAX_BYTES` sabiti |
| `services/decision/audit_chain.py` | `append_runtime_event()` fonksiyonu, `verify_runtime_event()` alias, `sign_decision`/`verify_decision`/`verify_chain` docstring güncellemeleri |
| `kernel/audit/store.py` | `filter()` metoduna field-aware semantik |
| `kernel/mcp/schemas.py` | `EventSummary` ve `SearchHit`'e `record_type`/`event_type`/`source` field'ları (Literal) |
| `kernel/mcp/tools.py` | `query_events`'e `event_type`+`source` parametreleri; `_summary()` helper'ı record_type-aware |
| `tests/test_runtime_event.py` | YENİ — 7 test |
| `docs/architecture.md` | "Upstream Evidence Events" bölümü (~200 kelime) |
| `CHANGELOG.md` | [Unreleased] bölümüne 3 satır |

---

## 11. Geriye uyumluluk

- Mevcut Decision JSONL dosyaları olduğu gibi okunabilir (record_type yokken "decision" varsayılır).
- `sign_decision`, `verify_decision`, `verify_chain` API imzaları değişmiyor — sadece docstring.
- `query_events` parametreleri ekleniyor ama default `None`, mevcut çağrılar etkilenmiyor.
- `EventSummary`'ye eklenen field'lar default `None`/`"decision"`, mevcut MCP istemcileri response'da yeni field'ları yok sayabilir.

Yeni RuntimeEvent kayıtları olan bir zincir, RuntimeEvent farkındalığı olmayan eski MCP istemcileri tarafından okunabilir; sadece field'lar görünmez.

---

## 12. Açık olmayan kararlar

Bu spec'te kapsanmayan ama implementasyonda netleşecek küçük noktalar:

- `_summary()` helper'ının `record_type` algılaması: `ev.get("record_type", "decision")` ile geriye uyumluluk.
- Test'lerde imza anahtarı: mevcut `signing_keypair` conftest fixture'ı yeniden kullanılır.
- `append_runtime_event()` chain file IO modu: text mode + `\n` terminator (`AuditChainStore.load()` ile uyumlu).

---

## 13. Done definition

- [ ] `RuntimeEvent` modeli `shared/schemas.py`'da, payload size validator + `PayloadTooLargeError` + `source_id` constraint'leri dahil
- [ ] `append_runtime_event()` `services/decision/audit_chain.py`'da, doğru chain_index/prev_hash mantığı + tüm chain field'larını override eder
- [ ] `verify_runtime_event()` alias eklendi
- [ ] `AuditChainStore.filter()` field-aware (action/threat_level → Decision-only; event_type/source → RuntimeEvent-only)
- [ ] `query_events` tool'u `event_type` + `source` parametreleriyle, mevcut davranış bozulmadı
- [ ] `EventSummary` ve `SearchHit` `Literal["decision", "runtime_event"]` record_type field'lı
- [ ] 9 yeni test geçiyor, mevcut 192 test de geçmeye devam ediyor
- [ ] `ruff check` temiz
- [ ] `docs/architecture.md`'de "Upstream Evidence Events" bölümü
- [ ] `CHANGELOG.md` [Unreleased] güncellendi
