# cavet-engine licences

This image bundles third-party scanners and rule sets. Their licences differ;
read this before selling anything built on it (spec §7.2).

## Opengrep engine — LGPL-2.1

The Opengrep binary is licensed under the GNU Lesser General Public License
v2.1. Source: https://github.com/opengrep/opengrep. Full text ships with the
project; on Debian-family images see `/usr/share/common-licenses/LGPL-2.1`
equivalents or the upstream repository.

## Opengrep rule corpus — LGPL-2.1 + Commons Clause

The rules bundled at `/opt/opengrep-rules` are the `semgrep-rules` corpus.
Their licence, verbatim from `opengrep-rules/LICENSE`:

```
"Commons Clause" License Condition v1.0

The Software is provided to you by the Licensor under the License, as
defined below, subject to the following condition.

Without limiting other conditions in the License, the grant of rights under
the License will not include, and the License does not grant to you, the
right to Sell the Software.

For purposes of the foregoing, "Sell" means practicing any or all of the
rights granted to you under the License to provide to third parties, for a
fee or other consideration (including without limitation fees for hosting or
consulting/support services related to the Software), a product or service
whose value derives, entirely or substantially, from the Software or the
functionality of the Software. Any license notice or attribution required by
the License must also include this Commons Clause License Condition notice.

Software: semgrep-rules (https://github.com/semgrep/semgrep-rules)
License: LGPL 2.1
Licensor: Semgrep, Inc.
```

**Distribution inside this image is permitted. Selling a product or service
whose value derives substantially from the rule corpus is not.**

## Gitleaks — MIT

Copyright (c) 2022 Zachary Rice. Source: https://github.com/gitleaks/gitleaks.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Trivy — Apache-2.0

Copyright 2019-2026 Aqua Security Software Ltd.
Source: https://github.com/aquasecurity/trivy.
Licensed under the Apache License, Version 2.0:
https://www.apache.org/licenses/LICENSE-2.0

The bundled vulnerability database and misconfig policy bundle under
`/opt/trivy-cache` are distributed under Trivy's own data licences; see the
Trivy documentation for their terms.

## Checkov — Apache-2.0

Copyright 2019-2026 Bridgecrew / Palo Alto Networks.
Source: https://github.com/bridgecrewio/checkov.
Licensed under the Apache License, Version 2.0:
https://www.apache.org/licenses/LICENSE-2.0

## git — GPL-2.0

The GNU General Public License v2 applies to the git binary. Source:
https://git-scm.com. This image only ever runs git read operations plus local
commits (spec §7.3); linking concerns do not arise for a separate process.
