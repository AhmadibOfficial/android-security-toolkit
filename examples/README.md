# Local test APKs

Do **not** commit APK files unless distribution rights and all security implications have been reviewed. The sample used during development is intentionally excluded from the Git repository.

Automated CI uses **synthetic manifest fixtures** instead. For a local authorized scan:

```bash
ahmad-sec apk scan /path/to/your/authorized-test.apk
```
