# Storage

Supabase Storage keeps file metadata in `storage.objects`, protected by RLS like any table.
Buckets add one more switch: **public** buckets serve files by URL without any policy.

## Checklist

- [ ] Only buckets for intentionally public files are public
- [ ] Private files (receipts, documents, IDs, chat attachments) are in private buckets and served with signed URLs
- [ ] Upload, update and delete policies tie the object to the user (folder or owner)
- [ ] File size and MIME type limits are set on the bucket
- [ ] Object paths do not leak data (no emails or phone numbers in file names)

## Public buckets

`public = true` means `https://<project>.supabase.co/storage/v1/object/public/<bucket>/<path>`
works for anyone. Policies still control listing and writes, but reading a known path is open.
Avatars and product photos: fine. Receipts and passports: use a private bucket and
`createSignedUrl(path, 60)`.

## Owner checks

```sql
-- ❌ any signed-in user can overwrite or delete anyone's file in the bucket
create policy "upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts');

-- ✅ each user writes only inside their own folder: receipts/<user id>/...
create policy "upload own" on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "delete own" on storage.objects for delete to authenticated
  using (bucket_id = 'receipts' and owner_id = (select auth.uid())::text);
```

Uploading with `upsert: true` needs insert, select **and** update permissions, so check all
three. Anonymous upload policies (`to anon`/`public`) turn the bucket into free file hosting
for anyone with the anon key.
