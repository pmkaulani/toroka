# Toroka Enterprise — Secure File & SFTP Batch Ingestion

## 1. Overview & Processing Workflow

Many commercial banks provide bulk postings, daily GL extracts, and HR rosters via scheduled SFTP drops or secure file shares.

`BankFileConnector` processes structured CSV and JSONL files in directory batches with end-to-end cryptographic integrity verification:

```
[Bank Batch Export] ──(SFTP/SCP)──> [/var/data/toroka_inbox/]
                                              │
                                              ▼
                             1. Enumerate files matching pattern (e.g. *.csv)
                             2. Sort lexicographically by filename / timestamp
                             3. Resume after context.cursor (last processed filename)
                             4. Calculate SHA-256 file checksum
                             5. Stream records through Pydantic parser
                             6. Update cursor to latest completed filename
```

---

## 2. Configuration Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `connector_id` | `str` | Required | Unique identifier |
| `input_directory` | `Path \| str` | Required | Local or mounted directory path |
| `file_pattern` | `str` | `"*.csv"` | Glob pattern for file enumeration |
| `format` | `str` | `"csv"` | Supported: `"csv"`, `"jsonl"` |
| `delimiter` | `str` | `","` | CSV delimiter |
| `encoding` | `str` | `"utf-8"` | File text encoding |

---

## 3. Cryptographic Checksum & Idempotency

Before reading records from a batch file, `BankFileConnector` computes the SHA-256 hash across file contents:
```python
def compute_file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()
```
This checksum is embedded in the `Provenance` header of every record extracted from the file. If an identical file is re-dropped or ingested a second time, the payload digests match and all records are acknowledged as duplicates with zero duplicate side-effects.
