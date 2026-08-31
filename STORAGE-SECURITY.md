TS_Daily file storage

- Files are stored privately in Netlify Blobs and never exposed as public static assets.
- A file is accessible only after session validation and note ownership verification.
- Upload limit: 4 MB per file; user storage target: 1 GB and 100 files.
- Allowed formats: PDF, TXT, JPG/JPEG, PNG, WebP, DOC/DOCX, XLS/XLSX, PPT/PPTX, ZIP. Generic binary is rejected and allowed uploads are checked against file signatures.
- Download responses use no-store and nosniff.
- Deleting an attachment removes both metadata and the underlying blob.
- Orphan cleanup is available to administrators only and requires admin step-up + email 2FA.
