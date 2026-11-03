# Third-party notices

This repository is based on the DERO HE source code (BSD 3-Clause, Copyright 2017-2021 DERO Project; see `LICENSE`
and `license.txt`). Vendored Go dependencies keep their own licences under `vendor/` and `licenses/`.

## Descriptor suffix sort (`cmd/dero-miner/dsa/dsa.go`, `cmd/dero-miner/dsac/descriptor.c`, `descriptor.h`)

Used under the MIT License. Local changes are listed in each file's header (bounds hardening, NEON fast paths,
16-lane scatter, zero-run tie-break keys).

```
MIT License

Copyright (c) 2026 Notoriousjoshyb

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
```
