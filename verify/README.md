# Manual verification harness

Use this directory only after manually choosing an unverified lead. The HTTP client rejects every destination except literal loopback addresses and `localhost`, and it refuses to follow redirects. A redirect pointing away from loopback is also rejected.

Adapt `compose.local.yaml` inside the target clone using that project's own setup instructions. Keep the published port bound to `127.0.0.1`; do not change it to `0.0.0.0`. The template also uses an internal Docker network, drops capabilities, enables a read-only root filesystem, and allows writes only under `/tmp`. Some projects need additional writable volumes or capabilities—review each relaxation deliberately.

Example skeleton:

```python
from verify.harness import VerificationClient, save_observations

with VerificationClient("http://127.0.0.1:8080") as client:
    observations = client.compare_auth(
        "GET",
        "/api/example/1",
        authenticated_headers={"Authorization": "Bearer LOCAL_TEST_TOKEN"},
    )

save_observations("private-results/example.json", observations)
```

`compare_auth`, `probe_ids`, and `compare_variants` make controlled comparisons; they do not identify a vulnerability. Interpret results against the target's intended authorization model and keep working reproduction material private until a fix is available.
