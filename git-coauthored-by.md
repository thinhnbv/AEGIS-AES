---
name: git-no-coworker-coauthor
description: Khong them Co-Authored-By khi commit
metadata:
  type: user
---

Quy tac commit cho repo aegis-aes:
- Chi thinhnbv la author, khong can Co-Authored-By

**Cach xoa Co-Authored-By: thinhnbv khi da commit:**

```bash
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter 'sed "/^[Cc]o-[Aa]uthored-[Bb]y: thinhnbv/d"' -- --all
```

**Why:** Dong Co-Authored-By: thinhnbv xuat hien trong commit history, nguoi dung phan anh va yeu cau xoa moi lan.

**How to apply:** Dam bao commit message khong co Co-Authored-By: thinhnbv.
