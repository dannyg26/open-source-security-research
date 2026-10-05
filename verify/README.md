# Local HTTP observation helpers

These helpers compare responses for requests you define. They do not reproduce
the django CMS case study, infer the application's permission model, or confirm
a vulnerability automatically.

Use this directory only after manually choosing an unverified lead. Destination
validation accepts `localhost` and literal loopback IP addresses; redirects are
not followed, and off-loopback redirect locations raise an error. This is URL
validation, not network isolation: DNS resolution, proxy configuration, and
the local application's own behavior remain part of the environment.

Adapt `compose.local.yaml` inside the target clone using that project's own setup instructions. Keep the published port bound to `127.0.0.1`; do not change it to `0.0.0.0`. The template also uses an internal Docker network, drops capabilities, enables a read-only root filesystem, and allows writes only under `/tmp`. Some projects need additional writable volumes or capabilities—review each relaxation deliberately.

Example skeleton:

```python
from pathlib import Path

from verify.harness import VerificationClient, save_observations

with VerificationClient("http://127.0.0.1:8080") as client:
    observations = client.compare_auth(
        "GET",
        "/api/example/1",
        authenticated_headers={"Authorization": "Bearer LOCAL_TEST_TOKEN"},
    )

save_observations(Path("private-results/example.json"), observations)
```

Run this example from the repository root after installing `requirements.txt`
and starting your own local application. Replace the route and authentication
header with values appropriate to that application.

`compare_auth` changes the supplied headers; both requests share one HTTP
client and its cookie jar. Ensure cookies or other request options do not carry
authentication into the second request. It is not an automatic isolation test.
For independent identities, use separate clients and control their credentials.

Exports include response-body previews and redirect locations without automatic
secret redaction. Keep them private and review them before sharing.

`compare_auth`, `probe_ids`, and `compare_variants` make controlled comparisons; they do not identify a vulnerability. Interpret results against the target's intended authorization model and keep working reproduction material private until a fix is available.
