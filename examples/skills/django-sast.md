---
id: django-sast
name: SAST — Django Application Review
short_name: SAST (Django)
description: Django-specific static review whose findings join the SAST dashboard.
version: 1
# Reuse the built-in SAST report format, so findings land in the SAST
# dashboard and its open/closed lifecycle.
output: sast
category: Frameworks
---

Perform a static security review of this Django application, focusing on the
mistakes that are specific to Django and that a generic SAST pass tends to miss:

- **Raw SQL.** `raw()`, `extra()`, `RawSQL`, and `cursor.execute()` built with
  string formatting or f-strings instead of parameters.
- **Template autoescaping.** `|safe`, `mark_safe`, `{% autoescape off %}` and
  `format_html` misuse on user-controlled values.
- **CSRF.** `@csrf_exempt` on views that change state, and DRF views using
  `SessionAuthentication` without CSRF enforcement.
- **Object-level authorization.** Views and DRF viewsets that fetch
  `Model.objects.get(pk=...)` from the URL without scoping to the requesting
  user, and `get_queryset()` methods that don't filter by owner or tenant.
- **Settings.** `DEBUG = True`, a hard-coded `SECRET_KEY`, permissive
  `ALLOWED_HOSTS`, missing `SECURE_*` and session-cookie flags in production
  settings.
- **Mass assignment.** `ModelForm` / `ModelSerializer` with `fields = "__all__"`
  or `exclude` on models that have privilege or ownership fields.
- **Unsafe deserialization and file handling.** `pickle`, `yaml.load`, and
  uploads saved under user-controlled names or served from `MEDIA_ROOT`
  without validation.

Report each finding with its taint path from the request to the sink.
