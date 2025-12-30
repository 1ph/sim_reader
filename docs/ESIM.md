# eSIM Profile Support in sim_reader

## Overview

Пакет `esim` предоставляет инструменты для работы с eSIM профилями в формате GSMA SGP.22 / SAIP (Subscriber Identity Application Programming). Поддерживается декодирование, валидация и сборка профилей, включая работу с Java Card апплетами.

### Поддерживаемые Profile Elements

| Tag | Имя элемента | Описание |
|-----|--------------|----------|
| 0 | ProfileHeader | Заголовок профиля (версия, ICCID, сервисы) |
| 1 | MF | Master File (корневая файловая система) |
| 2 | PukCodes | Коды PUK |
| 3 | PinCodes | Коды PIN |
| 4 | Telecom | Телеком директория |
| 8 | **Application** | **Java Card апплеты (PE-Application)** |
| 9 | USIM | USIM приложение |
| 10 | OptUSIM | Опциональные файлы USIM |
| 12 | ISIM | ISIM приложение |
| 13 | OptISIM | Опциональные файлы ISIM |
| 14 | CSIM | CSIM приложение |
| 15 | OptCSIM | Опциональные файлы CSIM |
| 20 | GSMAccess | GSM Access файлы |
| 22 | AKAParameter | Параметры аутентификации (Ki, OPc, алгоритм) |
| 23 | CDMAParameter | Параметры CDMA |
| 24 | DF5GS | 5G файлы |
| 25 | DFSAIP | SAIP файлы |
| 26 | GenericFileManagement | Управление файлами |
| 55 | SecurityDomain | GlobalPlatform Security Domain |
| 56 | RFM | Remote File Management |
| 63 | End | Маркер конца профиля |

---

## Команды CLI

### Общий синтаксис

```bash
sim_reader esim <subcommand> [flags]
```

### Доступные подкоманды

| Команда | Описание |
|---------|----------|
| `decode` | Декодировать и отобразить содержимое профиля |
| `validate` | Проверить профиль на корректность |
| `build` | Собрать профиль из конфигурации и шаблона |

---

## Декодирование профилей (decode)

```bash
sim_reader esim decode <profile.der> [--verbose] [--json]
```

### Флаги

| Флаг | Описание |
|------|----------|
| `-v, --verbose` | Показать детальную информацию (АКА параметры, апплеты, PIN/PUK) |
| `--json` | Вывод в формате JSON |

### Примеры

```bash
# Базовая информация о профиле
sim_reader esim decode profile.der

# Детальная информация включая апплеты и ключи
sim_reader esim decode profile.der --verbose

# Экспорт в JSON
sim_reader esim decode profile.der --json > profile_info.json
```

### Пример вывода

```
=== eSIM Profile Summary ===

Version:      2.3
Profile Type: operationalProfile
ICCID:        89701501078000006814

--- Applications ---
USIM: true
ISIM: true
CSIM: false

--- USIM ---
IMSI: 250880000000010
AID:  a0000000871002ff33ff01890000010f

--- Authentication ---
Algorithm: Milenage
Ki:        00112233445566778899aabbccddeeff
OPc:       ffeeddccbbaa99887766554433221100

--- PIN/PUK ---
PIN1: 0000
PUK1: 12345678
ADM1: 88888888

--- Profile Elements: 25 ---
  [ 0] ProfileHeader
  [ 1] MasterFile
  [ 2] PukCodes
  ...
```

---

## Валидация профилей (validate)

```bash
sim_reader esim validate <profile.der> [--template <base.der>]
```

### Флаги

| Флаг | Описание |
|------|----------|
| `-t, --template` | Шаблон профиля для сравнения структуры |
| `--json` | Вывод результатов в формате JSON |

### Выполняемые проверки

1. **Обязательные элементы**
   - ProfileHeader (обязателен)
   - MasterFile (обязателен)
   - End (обязателен)

2. **ICCID**
   - Длина: 18-20 цифр
   - Формат: только цифры
   - Контрольная сумма Luhn

3. **IMSI**
   - Длина: 15 цифр
   - Формат: только цифры
   - Требуется при наличии USIM

4. **AKA параметры**
   - Наличие AlgoConfiguration
   - Ki: 16 или 32 байта
   - OPc: 16 или 32 байта (рекомендуется для Milenage/TUAK)

5. **PIN/PUK**
   - PIN: 4-8 цифр
   - PUK: 8 цифр

6. **Апплеты (PE-Application)**
   - Валидность AID (5-16 байт)
   - Наличие LoadBlock или InstanceList
   - Формат APDU команд персонализации

### Примеры

```bash
# Базовая валидация
sim_reader esim validate profile.der

# Сравнение с шаблоном
sim_reader esim validate profile.der --template TS48v4_SAIP2.3.der

# JSON вывод для автоматизации
sim_reader esim validate profile.der --json
```

### Пример вывода

```
Profile validation: PASSED

✓ ProfileHeader: v2.3
✓ MasterFile: Present
✓ ProfileEnd: Present
✓ ICCID: 89701501078000006814 (Luhn OK)
✓ IMSI: 250880000000010
✓ AKA: Milenage, Ki/OPc present
✓ PIN/PUK: PIN/PUK codes valid
✓ Applications: 1 applet(s) found, 1 instance(s)
✓ SecurityDomains: 1 SD(s) found
```

---

## Сборка профилей (build)

```bash
sim_reader esim build --config <config.json> --template <base.der> -o <output.der> [flags]
```

### Флаги

| Флаг | Описание |
|------|----------|
| `-c, --config` | JSON файл конфигурации (обязателен) |
| `-t, --template` | Шаблон профиля DER (обязателен) |
| `-o, --output` | Выходной файл профиля (по умолчанию: profile.der) |
| `--applet` | CAP файл апплета для включения в профиль |
| `--use-applet-auth` | Делегировать аутентификацию апплету (algorithmID=3) |

### Формат конфигурации (JSON)

```json
{
  "iccid": "89701501078000006814",
  "imsi": "250880000000010",
  "ki": "00112233445566778899aabbccddeeff",
  "opc": "ffeeddccbbaa99887766554433221100",
  
  "impi": "250880000000010@ims.mnc088.mcc250.3gppnetwork.org",
  "impu": [
    "sip:250880000000010@ims.mnc088.mcc250.3gppnetwork.org",
    "tel:+70000000010"
  ],
  "domain": "ims.mnc088.mcc250.3gppnetwork.org",
  
  "pin1": "0000",
  "puk1": "12345678",
  "adm1": "88888888",
  
  "algorithm_id": 1,
  "profile_type": "operationalProfile",
  
  "applet_cap": "/path/to/milenage_usim.cap",
  "applet_config": {
    "package_aid": "A00000008710020101",
    "class_aid": "A0000000871002010101",
    "instance_aid": "A000000087100201010101",
    "milenage_usim": {
      "ki": "00112233445566778899aabbccddeeff",
      "opc": "ffeeddccbbaa99887766554433221100",
      "amf": "8000"
    }
  }
}
```

### Пример сборки

```bash
# Базовая сборка
sim_reader esim build \
  --config rusim.json \
  --template TS48v4_SAIP2.3_NoBERTLV.der \
  -o my_profile.der

# С апплетом Milenage USIM
sim_reader esim build \
  --config rusim.json \
  --template TS48v4_SAIP2.3_NoBERTLV.der \
  --applet milenage_usim.cap \
  --use-applet-auth \
  -o my_profile.der
```

---

## Поддержка апплетов (PE-Application)

### Структура PE-Application

PE-Application (Tag 8) содержит:

1. **LoadBlock** - данные CAP файла
   - `LoadPackageAID` - AID пакета
   - `SecurityDomainAID` - целевой Security Domain (опционально)
   - `LoadBlockObject` - содержимое CAP файла

2. **InstanceList** - список экземпляров апплетов
   - `ApplicationLoadPackageAID` - ссылка на пакет
   - `ClassAID` - AID класса апплета
   - `InstanceAID` - AID экземпляра
   - `ApplicationPrivileges` - привилегии GP
   - `LifeCycleState` - состояние жизненного цикла (0x07 = SELECTABLE)
   - `ProcessData` - APDU команды персонализации

### ProcessData (команды персонализации)

ProcessData содержит APDU команды, которые выполняются после установки апплета. Типичное использование - загрузка ключей в Milenage USIM апплет:

```
STORE DATA (CLA=80, INS=E2):
  80 E2 00 00 12 01 10 <16 bytes Ki>          # Ki
  80 E2 00 00 12 02 10 <16 bytes OPc>         # OPc
  80 E2 00 00 04 04 02 80 00                  # AMF
```

### Конфигурация апплета в JSON

```json
{
  "applet_config": {
    "package_aid": "A00000008710020101",
    "class_aid": "A0000000871002010101",
    "instance_aid": "A000000087100201010101",
    "sd_aid": "A000000151000000",
    
    "apdus": [
      "80E20000120110FFEEDDCCBBAA99887766554433221100",
      "80E20000120210FFEEDDCCBBAA99887766554433221100"
    ],
    
    "milenage_usim": {
      "ki": "00112233445566778899aabbccddeeff",
      "opc": "ffeeddccbbaa99887766554433221100",
      "amf": "8000",
      "sqn": "000000000000"
    }
  }
}
```

---

## Примеры использования

### 1. Проверка профиля перед загрузкой

```bash
# Валидация
sim_reader esim validate my_profile.der

# Если OK, загрузка на eUICC
# (через внешние инструменты или SM-DP+)
```

### 2. Создание профиля для тестирования

```bash
# 1. Подготовить конфигурацию
cat > test_config.json << 'EOF'
{
  "iccid": "89701501078000006814",
  "imsi": "250880000000010",
  "ki": "00112233445566778899aabbccddeeff",
  "opc": "ffeeddccbbaa99887766554433221100",
  "pin1": "0000",
  "puk1": "12345678"
}
EOF

# 2. Собрать профиль
sim_reader esim build \
  -c test_config.json \
  -t base_template.der \
  -o test_profile.der

# 3. Проверить результат
sim_reader esim decode test_profile.der --verbose
```

### 3. Анализ апплетов в профиле

```bash
sim_reader esim decode profile_with_applet.der --verbose

# Вывод покажет:
# --- Java Card Applications (PE-Application) ---
# Application[0]:
#   LoadBlock:
#     PackageAID: a00000008710020101
#     LoadBlockObject: 15234 bytes
#   Instance[0]:
#     PackageAID: a00000008710020101
#     ClassAID:   a0000000871002010101
#     InstanceAID: a000000087100201010101
#     LifeCycle: 0x07
#     ProcessData (3 APDUs):
#       [0] 80e20000120110ffeeddccbbaa998877665544...
```

---

## Troubleshooting

### Профиль не декодируется

1. Проверьте формат файла (должен быть DER, не PEM)
2. Проверьте целостность файла (размер > 0)
3. Запустите с `--verbose` для детальной диагностики

### Валидация показывает ошибки

| Ошибка | Причина | Решение |
|--------|---------|---------|
| ICCID Luhn failed | Неверная контрольная сумма | Пересчитать ICCID |
| Ki missing | Нет ключа в AKA параметрах | Добавить Ki в конфигурацию |
| Invalid AID | AID < 5 или > 16 байт | Проверить формат AID |

### Апплет не работает после загрузки

1. Проверьте совместимость CAP файла с платформой eUICC
2. Убедитесь, что ProcessData содержит все необходимые команды
3. Проверьте правильность порядка команд персонализации

---

## Глоссарий

| Термин | Описание |
|--------|----------|
| ICCID | Integrated Circuit Card Identifier - 18-20 значный идентификатор карты |
| IMSI | International Mobile Subscriber Identity - 15 значный идентификатор абонента |
| Ki | Subscriber Key - 128-битный ключ аутентификации |
| OPc | Derived Operator Key - производный ключ оператора |
| AID | Application Identifier - идентификатор приложения (5-16 байт) |
| CAP | Converted Applet - файл Java Card апплета |
| PE | Profile Element - элемент профиля |
| SAIP | Subscriber Identity Application Programming - формат профилей SGP.22 |
| ProcessData | APDU команды персонализации апплета |

