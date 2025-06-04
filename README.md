<div align="center">
  <h1>SSH-Cracker v1.0</h1>
  <p>
    یک ابزار بروت-فورس SSH سریع، تمیز و چندنخی به زبان پایتون
    <br/>
    A fast, clean, and multi-threaded SSH brute-force tool in Python
  </p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.x-blue.svg" alt="Python 3.x">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License MIT">
    <img src="https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red" alt="Made with Love">
  </p>

</div>

---

<details>
  <summary><strong>🌍 Table of Contents (فهرست مطالب)</strong></summary>
  <ol>
    <li>
        <a href="#-درباره-پروژه--about-the-project">درباره پروژه / About The Project</a>
    </li>
    <li>
        <a href="#-ویژگی‌های-کلیدی--key-features">ویژگی‌های کلیدی / Key Features</a>
    </li>
    <li>
      <a href="#-شروع-به-کار--getting-started">شروع به کار / Getting Started</a>
      <ul>
        <li><a href="#-پیش‌نیازها--prerequisites">پیش‌نیازها / Prerequisites</a></li>
        <li><a href="#-نصب--installation">نصب / Installation</a></li>
      </ul>
    </li>
    <li><a href="#-نحوه-استفاده--usage">نحوه استفاده / Usage</a></li>
    <li><a href="#️-سلب-مسئولیت-اخلاقی--ethical-disclaimer">سلب مسئولیت اخلاقی / Ethical Disclaimer</a></li>
    <li><a href="#-مجوز--license">مجوز / License</a></li>
    <li><a href="#-سازنده--author">سازنده / Author</a></li>
  </ol>
</details>

---

<div dir="rtl">

## 🇮🇷 درباره پروژه / 🇬🇧 About The Project

این پروژه یک اسکریپت ساده برای اجرای حملات بروت فورس (Brute-Force) علیه سرویس‌های SSH است. هدف اصلی، فراهم کردن ابزاری برای متخصصان امنیت و مدیران شبکه است تا بتوانند مقاومت سرورهای خود را در برابر این نوع حملات آزمایش کنند.

این ابزار با استفاده از کتابخانه‌های مدرن پایتون ساخته شده است:
* **`Paramiko`**: برای مدیریت کامل اتصالات و فرآیند احراز هویت SSH.
* **`Rich`**: برای ایجاد یک رابط کاربری جذاب و خوانا در ترمینال، که تجربه کاربری را بهبود می‌بخشد.
* **`concurrent.futures`**: برای پیاده‌سازی چندنخی (Multi-threading) و افزایش چشمگیر سرعت تست رمزهای عبور.

---

## ✨ ویژگی‌های کلیدی / Key Features

* **🚀 عملکرد سریع**: با بهره‌گیری از پردازش موازی، هزاران رمز عبور را در زمان کوتاهی آزمایش می‌کند.
* **🎨 رابط کاربری زیبا**: نمایش اطلاعات به صورت سازماندهی‌شده و رنگی برای درک بهتر وضعیت حمله.
* **✔️ توقف هوشمند**: به محض یافتن اولین رمز عبور معتبر، عملیات متوقف شده و نتیجه اعلام می‌شود.
* **📋 گزارش‌دهی دقیق**: تمامی تلاش‌ها به همراه وضعیت موفق یا ناموفق بودن آن‌ها در فایل `pentest_report.log` ثبت می‌شود.
* **⚙️ کاملاً قابل تنظیم**: تمام پارامترهای حمله از جمله IP هدف، پورت، نام کاربری و تعداد تردها از طریق خط فرمان قابل مدیریت است.

---

## 🚀 شروع به کار / Getting Started

برای راه‌اندازی و اجرای پروژه روی سیستم خود، مراحل زیر را دنبال کنید.

### ✅ پیش‌نیازها / Prerequisites

* Python 3.6 یا بالاتر
* `pip` (مدیریت پکیج پایتون)

### 🛠️ نصب / Installation

1.  مخزن پروژه را کلون کنید (یا فایل‌ها را دانلود نمایید):
    ```sh
    git clone https://github.com/Amirprx3/SSH-BruteForce.git
    ```
2.  وارد پوشه پروژه شوید:
    ```sh
    cd SSH-BruteForce
    ```
3.  کتابخانه‌های مورد نیاز را نصب کنید:
    ```sh
    pip install paramiko rich
    ```
---

## 👨‍💻 نحوه استفاده / Usage

برای اجرای اسکریپت از دستور زیر استفاده کنید. مقادیر نمونه را با اطلاعات هدف خود جایگزین نمایید.

```bash
python ssh-cracker.py -i <TARGET_IP> -u <USERNAME> -P <PATH_TO_PASSLIST> -t <THREADS(optional)>
```

مثال:
```bash
python ssh-cracker.py -i 192.168.1.101 -u root -P passlist.txt -t 50
```

## 📄 مجوز / License
این پروژه تحت مجوز MIT منتشر شده است. این به این معنی است که شما آزاد هستید تا از کد استفاده، آن را تغییر و توزیع کنید.

## 👤 سازنده / Author
این ابزار توسط [Amirprx3](https://github.com/Amirprx3) ساخته شده است.