# Email Manager — صورة Docker
# تشغّل واجهة الويب + سيرفر البريد الداخلي المدمج (SMTP/IMAP) في حاوية واحدة.
FROM python:3.12-slim

# إعدادات بايثون نظيفة داخل الحاوية
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# توقيت السعودية (Asia/Riyadh = UTC+3) — عشان مواعيد الحملات تطابق ساعتك
ENV TZ=Asia/Riyadh
# tzdata لتوقيت السعودية + postgresql-client لأدوات النسخ الاحتياطي (pg_dump/pg_restore).
# نسخة عميل Debian trixie (17) تقدر تعمل dump لسيرفر Postgres 16 بدون مشاكل.
RUN apt-get update && apt-get install -y --no-install-recommends tzdata postgresql-client \
    && ln -sf /usr/share/zoneinfo/Asia/Riyadh /etc/localtime \
    && echo "Asia/Riyadh" > /etc/timezone \
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
