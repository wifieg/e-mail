# Email Manager — صورة Docker
# تشغّل واجهة الويب + سيرفر البريد الداخلي المدمج (SMTP/IMAP) في حاوية واحدة.
# نثبّت على bookworm تحديداً حتى نقدر نركّب postgresql-client-16 من مستودع PGDG
# (نفس نسخة سيرفر Postgres 16 — ضروري لأن أدوات نسخة أحدث تكتب توجيهات لا يقبلها
#  السيرفر الأقدم وقت الاستعادة).
FROM python:3.12-slim-bookworm

# إعدادات بايثون نظيفة داخل الحاوية
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# توقيت السعودية (Asia/Riyadh = UTC+3) — عشان مواعيد الحملات تطابق ساعتك
ENV TZ=Asia/Riyadh
# tzdata لتوقيت السعودية + postgresql-client-16 من مستودع PGDG (يطابق سيرفر Postgres 16).
RUN apt-get update && apt-get install -y --no-install-recommends \
        tzdata curl ca-certificates gnupg \
    && ln -sf /usr/share/zoneinfo/Asia/Riyadh /etc/localtime \
    && echo "Asia/Riyadh" > /etc/timezone \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-16 \
    && apt-get purge -y curl gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ثبّت المتطلبات أولاً (طبقة تُخزَّن مؤقتاً)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# انسخ كود التطبيق
COPY app.py .

# مجلد البيانات (قاعدة البيانات + المفاتيح + السجلّات) — يُركَّب كـ volume
RUN mkdir -p /app/data
VOLUME ["/app/data"]

# إعدادات التشغيل داخل الحاوية
ENV EM_HOST=0.0.0.0 \
    EM_PORT=8000 \
    EM_NO_BROWSER=1 \
    EM_DB=/app/data/email_manager.db \
    EM_INT_SMTP_PORT=8025 \
    EM_INT_IMAP_PORT=8143

# الويب + SMTP الداخلي + IMAP الداخلي
EXPOSE 8000 8025 8143

CMD ["python", "app.py"]
