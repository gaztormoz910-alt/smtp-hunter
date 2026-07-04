# SMTP Relay Scanner

Инструмент для поиска и верификации SMTP Open Relay серверов в глобальной сети.

## Возможности

- **ASN Lookup** — получение IP-диапазонов по домену (ipwhois, hackertarget)
- **Shodan/Censys** — поиск SMTP-серверов через публичные API
- **MX Resolver** — DNS MX + A запись для популярных доменов
- **Google Dorks** — поиск публичных SMTP credentials
- **Port Scanner** — асинхронный TCP connect scan (25, 465, 587, 2525+)
- **MTA Fingerprinting** — определение Postfix, Exim, Exchange, Sendmail и др.
- **6 методов проверки Open Relay**:
  - External → External
  - Internal → External
  - Null sender → External
  - Source route (%)
  - Source route (@)
  - AUTH bypass probe
- **VRFY/EXPN/RCPT TO** — перебор пользователей
- **SPF Enforcement Check** — проверка на спам
- **SMTP Smuggling** — детект CVE-2023-51764

## Установка

```bash
git clone https://github.com/yourusername/smtp_relay_scanner
cd smtp_relay_scanner
pip install -r requirements.txt