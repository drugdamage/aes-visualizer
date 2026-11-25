import tkinter as tk  # основная библиотека для создания окон и кнопок
from tkinter import ttk, scrolledtext, messagebox  # дополнительные виджеты: ползунки, текст со скроллом, всплывающие ошибки
import os  # нужен для генерации случайного ключа через os.urandom()
import sys  # нужен для определения операционной системы

# ============================================================
# шрифты, зависящие от операционной системы
# ============================================================
# Segoe UI и Courier New есть только в windows, на macOS они подменяются
# системой на произвольные и интерфейс выглядит неаккуратно
IS_MAC = sys.platform == "darwin"  # true если программа запущена на macOS
UI_FONT = "SF Pro Text" if IS_MAC else "Segoe UI"  # шрифт интерфейса
MONO_FONT = "Menlo" if IS_MAC else "Courier New"  # моноширинный шрифт для байт


# ============================================================
# константы алгоритма aes
# ============================================================

# таблица замен s-box — 256 значений, каждый байт заменяется на другой по этой таблице
# например байт 0x00 становится 0x63, байт 0x01 становится 0x7c и т.д.
# это нелинейная замена — главная защита от математических атак
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# обратная таблица замен — используется при дешифровании
# строим её автоматически: если sbox[i] = v, то inv_sbox[v] = i
INV_SBOX = [0] * 256  # создаём пустой список на 256 позиций
for _i, _v in enumerate(SBOX):  # проходим по каждому элементу s-box
    INV_SBOX[_v] = _i  # записываем обратное соответствие

# константы раундов rcon — используются при генерации раундовых ключей
# каждый раунд использует свою константу чтобы ключи не повторялись
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


# ============================================================
# математика поля галуа gf(2^8)
# ============================================================

# умножение двух байт в поле галуа — специальная математика где нет переполнения
# используется в операции mixcolumns для перемешивания байт внутри столбца
def gmul(a, b):
    p = 0  # результат умножения начинается с нуля
    for _ in range(8):  # повторяем 8 раз — по одному биту числа b
        if b & 1:  # если последний бит b равен 1
            p ^= a  # прибавляем a к результату через xor
        hi = a & 0x80  # запоминаем старший бит a перед сдвигом
        a = (a << 1) & 0xff  # сдвигаем a влево на 1 бит, обрезаем до байта
        if hi:  # если старший бит был 1 — делаем редукцию по полиному aes
            a ^= 0x1b  # xor с полиномом 0x1b — это правило поля галуа
        b >>= 1  # сдвигаем b вправо чтобы перейти к следующему биту
    return p  # возвращаем результат умножения


# ============================================================
# основные операции aes
# ============================================================

# subbytes — заменяем каждый байт матрицы на значение из таблицы s-box
# это нелинейная операция — без неё алгоритм можно было бы взломать линейно
def sub_bytes(state):
    return [[SBOX[b] for b in row] for row in state]  # для каждого байта b берём sbox[b]

# invsubbytes — обратная операция для дешифрования, используем inv_sbox
def inv_sub_bytes(state):
    return [[INV_SBOX[b] for b in row] for row in state]  # для каждого байта берём inv_sbox[b]

# shiftrows — циклически сдвигаем строки матрицы влево
# строка 0 не сдвигается, строка 1 — на 1 байт, строка 2 — на 2, строка 3 — на 3
# это перемешивает байты между столбцами — улучшает рассеивание
def shift_rows(state):
    return [
        state[0],  # строка 0 — без изменений
        state[1][1:] + state[1][:1],  # строка 1 — сдвиг влево на 1
        state[2][2:] + state[2][:2],  # строка 2 — сдвиг влево на 2
        state[3][3:] + state[3][:3],  # строка 3 — сдвиг влево на 3
    ]

# invshiftrows — обратный сдвиг строк для дешифрования (сдвигаем вправо)
def inv_shift_rows(state):
    return [
        state[0],  # строка 0 — без изменений
        state[1][-1:] + state[1][:-1],  # строка 1 — сдвиг вправо на 1
        state[2][-2:] + state[2][:-2],  # строка 2 — сдвиг вправо на 2
        state[3][-3:] + state[3][:-3],  # строка 3 — сдвиг вправо на 3
    ]

# mixcolumns — перемешиваем каждый столбец через умножение на фиксированную матрицу
# каждый байт в столбце становится зависимым от всех четырёх байт — лавинный эффект
def mix_columns(state):
    result = []  # сюда будем складывать новые столбцы
    for col_idx in range(4):  # проходим по каждому из 4 столбцов
        col = [state[row][col_idx] for row in range(4)]  # берём все 4 байта текущего столбца
        new_col = [  # вычисляем новые значения по формулам из стандарта aes
            gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2]          ^ col[3],  # новый байт 0
            col[0]          ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3],  # новый байт 1
            col[0]          ^ col[1]          ^ gmul(col[2], 2) ^ gmul(col[3], 3),  # новый байт 2
            gmul(col[0], 3) ^ col[1]          ^ col[2]          ^ gmul(col[3], 2),  # новый байт 3
        ]
        result.append(new_col)  # добавляем новый столбец в результат
    return [[result[c][r] for c in range(4)] for r in range(4)]  # транспонируем обратно в строки

# invmixcolumns — обратное перемешивание для дешифрования, другие коэффициенты
def inv_mix_columns(state):
    result = []  # сюда складываем новые столбцы
    for col_idx in range(4):  # проходим по каждому столбцу
        col = [state[row][col_idx] for row in range(4)]  # берём 4 байта столбца
        new_col = [  # обратные коэффициенты: 0x0e, 0x0b, 0x0d, 0x09
            gmul(col[0], 0x0e) ^ gmul(col[1], 0x0b) ^ gmul(col[2], 0x0d) ^ gmul(col[3], 0x09),
            gmul(col[0], 0x09) ^ gmul(col[1], 0x0e) ^ gmul(col[2], 0x0b) ^ gmul(col[3], 0x0d),
            gmul(col[0], 0x0d) ^ gmul(col[1], 0x09) ^ gmul(col[2], 0x0e) ^ gmul(col[3], 0x0b),
            gmul(col[0], 0x0b) ^ gmul(col[1], 0x0d) ^ gmul(col[2], 0x09) ^ gmul(col[3], 0x0e),
        ]
        result.append(new_col)  # добавляем столбец
    return [[result[c][r] for c in range(4)] for r in range(4)]  # возвращаем в формате строк

# addroundkey — накладываем раундовый ключ на матрицу через xor
# xor обратим: чтобы снять ключ — нужно снова сделать xor с тем же ключом
def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]  # xor каждого байта


# ============================================================
# генерация раундовых ключей (key schedule)
# ============================================================

# из одного исходного ключа 16 байт генерируем 11 раундовых ключей
# каждый следующий ключ зависит от предыдущего — ключи не повторяются
def key_expansion(key_bytes):
    w = []  # список всех слов (слово = 4 байта)
    for i in range(4):  # первые 4 слова — это сам исходный ключ
        w.append(list(key_bytes[4 * i: 4 * i + 4]))  # берём по 4 байта из ключа

    for i in range(4, 44):  # генерируем ещё 40 слов (итого 44 = 11 ключей по 4 слова)
        temp = list(w[i - 1])  # берём предыдущее слово как основу
        if i % 4 == 0:  # каждое четвёртое слово обрабатывается по-особому
            temp = temp[1:] + temp[:1]  # rotword — сдвигаем байты слова влево на 1
            temp = [SBOX[b] for b in temp]  # subword — заменяем каждый байт через s-box
            temp[0] ^= RCON[(i // 4) - 1]  # xor первого байта с константой раунда
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])  # новое слово = xor с словом 4 позиции назад

    round_keys = []  # список из 11 готовых раундовых ключей
    for rnd in range(11):  # формируем каждый из 11 ключей
        rk = [[w[rnd * 4 + c][r] for c in range(4)] for r in range(4)]  # собираем матрицу 4x4 из 4 слов
        round_keys.append(rk)  # добавляем ключ в список
    return round_keys  # возвращаем все 11 раундовых ключей


# ============================================================
# вспомогательные функции для работы с матрицей состояния
# ============================================================

# переводим 16 байт входного текста в матрицу 4x4
# байты заполняются по столбцам: state[строка][столбец] = data[строка + 4*столбец]
def bytes_to_state(data):
    return [[data[r + 4 * c] for c in range(4)] for r in range(4)]

# переводим матрицу 4x4 обратно в последовательность байт
# порядок тот же — по столбцам
def state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ============================================================
# шифрование с трассировкой всех шагов
# ============================================================

# шифруем 16 байт открытого текста и записываем каждый шаг в список trace
# trace потом используется для визуализации в программе
def aes_encrypt_trace(plaintext_bytes, key_bytes):
    round_keys = key_expansion(key_bytes)  # генерируем все 11 раундовых ключей
    state = bytes_to_state(plaintext_bytes)  # переводим текст в матрицу состояния
    trace = []  # список шагов для визуализации

    # записываем начальное состояние до любых операций
    trace.append({
        "round": 0,
        "operation": "Начальное состояние",
        "state": [row[:] for row in state],  # копируем матрицу чтобы не изменялась
        "description": (
            "Исходный блок открытого текста (16 байт) преобразован в матрицу состояния 4x4.\n"
            "Байты заполняются по столбцам: state[r][c] = plaintext[r + 4*c]."
        )
    })

    # нулевой раунд — только addroundkey, без других операций
    state = add_round_key(state, round_keys[0])  # накладываем нулевой ключ
    trace.append({
        "round": 0,
        "operation": "AddRoundKey",
        "state": [row[:] for row in state],
        "description": (
            "Раунд 0 — начальный XOR.\n"
            "Каждый байт матрицы состояния складывается по модулю 2 (XOR) с соответствующим байтом "
            "нулевого раундового ключа. Это «забеливание» ключом перед основными раундами."
        )
    })

    for rnd in range(1, 11):  # основные раунды с 1 по 10
        state = sub_bytes(state)  # шаг 1 — замена байт через s-box
        trace.append({
            "round": rnd,
            "operation": "SubBytes",
            "state": [row[:] for row in state],
            "description": (
                f"Раунд {rnd} — SubBytes.\n"
                "Нелинейная замена: каждый байт b заменяется значением SBOX[b].\n"
                "S-Box построен как инверсия в GF(2^8), за которой следует аффинное преобразование. "
                "Обеспечивает нелинейность и устойчивость к линейному криптоанализу."
            )
        })

        state = shift_rows(state)  # шаг 2 — сдвигаем строки матрицы
        trace.append({
            "round": rnd,
            "operation": "ShiftRows",
            "state": [row[:] for row in state],
            "description": (
                f"Раунд {rnd} — ShiftRows.\n"
                "Циклический сдвиг строк матрицы влево:\n"
                "  Строка 0: без сдвига\n"
                "  Строка 1: сдвиг на 1 байт\n"
                "  Строка 2: сдвиг на 2 байта\n"
                "  Строка 3: сдвиг на 3 байта\n"
                "Обеспечивает диффузию между столбцами."
            )
        })

        if rnd < 10:  # mixcolumns выполняется во всех раундах кроме последнего (10-го)
            state = mix_columns(state)  # шаг 3 — перемешиваем столбцы
            trace.append({
                "round": rnd,
                "operation": "MixColumns",
                "state": [row[:] for row in state],
                "description": (
                    f"Раунд {rnd} — MixColumns.\n"
                    "Каждый столбец умножается на фиксированную матрицу в поле GF(2^8):\n"
                    "  [2 3 1 1]\n"
                    "  [1 2 3 1]\n"
                    "  [1 1 2 3]\n"
                    "  [3 1 1 2]\n"
                    "Максимально рассеивает изменения внутри столбца (лавинный эффект)."
                )
            })

        state = add_round_key(state, round_keys[rnd])  # шаг 4 — накладываем раундовый ключ
        trace.append({
            "round": rnd,
            "operation": "AddRoundKey",
            "state": [row[:] for row in state],
            "description": (
                f"Раунд {rnd} — AddRoundKey.\n"
                f"XOR состояния с раундовым ключом №{rnd}, полученным из ключевого расписания. "
                "Добавление ключевого материала на каждом раунде обеспечивает зависимость шифртекста от ключа."
            )
        })

    ciphertext = state_to_bytes(state)  # переводим итоговую матрицу обратно в байты — это и есть шифртекст
    return ciphertext, trace, round_keys  # возвращаем шифртекст, список шагов и все ключи


# ============================================================
# дешифрование с трассировкой всех шагов
# ============================================================

# дешифруем 16 байт шифртекста — операции те же, но в обратном порядке и обратные
def aes_decrypt_trace(ciphertext_bytes, key_bytes):
    round_keys = key_expansion(key_bytes)  # генерируем те же 11 ключей что и при шифровании
    state = bytes_to_state(ciphertext_bytes)  # переводим шифртекст в матрицу состояния
    trace = []  # список шагов для визуализации

    # записываем начальное состояние шифртекста
    trace.append({
        "round": 0,
        "operation": "Начальное состояние",
        "state": [row[:] for row in state],
        "description": (
            "Исходный блок шифртекста (16 байт) преобразован в матрицу состояния 4x4.\n"
            "Дешифрование AES использует инверсные операции в обратном порядке."
        )
    })

    state = add_round_key(state, round_keys[10])  # начинаем с последнего ключа — ключа раунда 10
    trace.append({
        "round": 0,
        "operation": "AddRoundKey",
        "state": [row[:] for row in state],
        "description": (
            "Начальный AddRoundKey при дешифровании использует раундовый ключ №10 "
            "(последний при шифровании). XOR является самообратной операцией."
        )
    })

    for rnd in range(9, -1, -1):  # идём от раунда 9 до 0 включительно — в обратном порядке
        disp = 10 - rnd  # номер шага для отображения (от 1 до 10)

        state = inv_shift_rows(state)  # обратный сдвиг строк
        trace.append({
            "round": disp,
            "operation": "InvShiftRows",
            "state": [row[:] for row in state],
            "description": (
                f"Раунд {disp} — InvShiftRows.\n"
                "Обратный циклический сдвиг строк вправо:\n"
                "  Строка 0: без сдвига\n"
                "  Строка 1: сдвиг на 1 байт вправо\n"
                "  Строка 2: сдвиг на 2 байта вправо\n"
                "  Строка 3: сдвиг на 3 байта вправо"
            )
        })

        state = inv_sub_bytes(state)  # обратная замена байт через inv_sbox
        trace.append({
            "round": disp,
            "operation": "InvSubBytes",
            "state": [row[:] for row in state],
            "description": (
                f"Раунд {disp} — InvSubBytes.\n"
                "Обратная замена через инверсную таблицу подстановки INV_SBOX.\n"
                "Каждый байт b заменяется значением INV_SBOX[b], что отменяет действие SubBytes."
            )
        })

        state = add_round_key(state, round_keys[rnd])  # накладываем ключ текущего раунда
        trace.append({
            "round": disp,
            "operation": "AddRoundKey",
            "state": [row[:] for row in state],
            "description": (
                f"Раунд {disp} — AddRoundKey с ключом №{rnd}.\n"
                "XOR является самообратной операцией, поэтому она идентична при шифровании и дешифровании."
            )
        })

        if rnd > 0:  # invmixcolumns не применяется в самом последнем шаге (rnd=0)
            state = inv_mix_columns(state)  # обратное перемешивание столбцов
            trace.append({
                "round": disp,
                "operation": "InvMixColumns",
                "state": [row[:] for row in state],
                "description": (
                    f"Раунд {disp} — InvMixColumns.\n"
                    "Обратное умножение столбцов на инверсную матрицу в GF(2^8):\n"
                    "  [14  11  13   9]\n"
                    "  [ 9  14  11  13]\n"
                    "  [13   9  14  11]\n"
                    "  [11  13   9  14]"
                )
            })

    plaintext = state_to_bytes(state)  # переводим итоговую матрицу обратно в байты — это открытый текст
    return plaintext, trace, round_keys  # возвращаем открытый текст, шаги и ключи


# ============================================================
# цветовая палитра интерфейса
# ============================================================

# все цвета программы в одном месте — тёмная тема
PALETTE = {
    "bg":        "#1e1e2e",  # основной фон окна — тёмно-синий
    "surface":   "#2a2a3e",  # фон панелей — чуть светлее основного
    "accent":    "#7c6fff",  # основной акцентный цвет — фиолетовый (кнопка шифровать)
    "accent2":   "#ff6b9d",  # второй акцент — розовый (кнопка расшифровать)
    "accent3":   "#43e97b",  # зелёный — для успешных сообщений
    "text":      "#e5e7eb",  # основной цвет текста — светло-серый
    "subtext":   "#b8c0cc",  # второстепенный текст — чуть темнее
    "border":    "#566070",  # цвет рамок и кнопки случайного ключа
    "cell_bg":   "#25293a",  # фон ячеек матрицы и полей ввода
    "header_bg": "#181825",  # фон верхней и нижней панели
    "op_colors": {  # цвета для каждой операции aes — подсвечивают изменённые байты
        "SubBytes":        "#d19a5b",  # оранжевый для subbytes
        "InvSubBytes":     "#d19a5b",  # тот же цвет для обратной операции
        "ShiftRows":       "#6fa8bd",  # голубой для shiftrows
        "InvShiftRows":    "#6fa8bd",  # голубой для обратного shiftrows
        "MixColumns":      "#c47b94",  # розовый для mixcolumns
        "InvMixColumns":   "#c47b94",  # розовый для обратного mixcolumns
        "AddRoundKey":     "#7fb38d",  # зелёный для addroundkey
        "Начальное состояние": "#b8c0cc",  # серый для начального состояния
    },
}


# вспомогательная функция — переводит число в двузначный hex
# например 15 -> "0F", 255 -> "FF"
def hex2(v):
    return f"{v:02X}"


# ============================================================
# главный класс программы — окно и весь интерфейс
# ============================================================

# наследуемся от tk.Tk — это и есть главное окно программы
class AESVisualizer(tk.Tk):
    def __init__(self):
        super().__init__()  # вызываем конструктор родительского класса (создаём окно)
        self.title("Popov AES")  # заголовок окна в заголовочной строке
        self.configure(bg=PALETTE["bg"])  # устанавливаем цвет фона окна
        self.geometry("1140x800")  # размер окна при запуске: ширина x высота
        self.minsize(940, 700)  # минимальный размер — меньше сжать нельзя

        self.trace = []  # список шагов текущей трассировки (пуст до первого шифрования)
        self.step_idx = 0  # индекс текущего отображаемого шага
        self.round_keys = []  # список раундовых ключей (пуст до первого шифрования)
        self.auto_play = False  # флаг автовоспроизведения — false = выключено
        self.auto_job = None  # хранит id задачи автовоспроизведения чтобы её можно было отменить

        self._build_ui()  # строим весь интерфейс

    # ---- построение интерфейса -----------------------------------------------

    # вызывает все методы построения интерфейса по порядку
    def _build_ui(self):
        self._build_input_panel()  # панель ввода текста и ключа
        self._build_result_bar()   # строка с результатом шифрования
        self._build_main_area()    # основная область: список шагов + матрица + описание
        self._build_nav_bar()      # нижняя панель навигации по шагам

    # строим верхнюю панель ввода данных
    def _build_input_panel(self):
        top = tk.Frame(self, bg=PALETTE["bg"], padx=18, pady=10)  # контейнер для всей панели ввода
        top.pack(fill="x")  # растягиваем по ширине окна

        # --- строка 0: открытый текст ---
        self._lbl(top, "Открытый текст:").grid(row=0, column=0, sticky="nw", pady=(6, 0))  # подпись слева

        plain_frame = tk.Frame(top, bg=PALETTE["bg"])  # контейнер для всего что связано с вводом текста
        plain_frame.grid(row=0, column=1, padx=10, sticky="w")  # ставим правее подписи

        # переключатель режима ввода: обычный текст или hex
        self.input_mode = tk.StringVar(value="text")  # переменная хранит текущий режим: "text" или "hex"
        mode_f = tk.Frame(plain_frame, bg=PALETTE["bg"])  # контейнер для радиокнопок
        mode_f.pack(anchor="w")  # прижимаем к левому краю
        for val, label in [("text", "Обычный текст"), ("hex", "Hex вручную")]:  # два варианта переключателя
            tk.Radiobutton(
                mode_f, text=label, variable=self.input_mode, value=val,  # привязываем к переменной input_mode
                bg=PALETTE["bg"], fg=PALETTE["text"],
                selectcolor=PALETTE["cell_bg"],
                activebackground=PALETTE["bg"], activeforeground=PALETTE["text"],
                command=self._on_mode_change  # при переключении вызываем метод смены режима
            ).pack(side="left", padx=(0, 12))  # размещаем кнопки рядом

        # строка с полем ввода обычного текста
        text_row = tk.Frame(plain_frame, bg=PALETTE["bg"])  # контейнер для поля и подсказки
        text_row.pack(anchor="w", pady=(4, 0))  # отступ сверху
        self.txt_text_input = self._entry(text_row, width=20)  # поле ввода обычного текста (20 символов)
        self.txt_text_input.pack(side="left")  # ставим слева
        # поле пустое при запуске — не вставляем никакой текст по умолчанию
        self.txt_text_input.bind("<KeyRelease>", self._on_text_input_change)  # обновляем счётчик при каждом нажатии
        self.lbl_text_hint = tk.Label(  # подсказка о количестве введённых символов
            text_row, text="0/16 — нужно ещё 16 символов",
            bg=PALETTE["bg"], fg=PALETTE["accent2"], font=(UI_FONT, 9))
        self.lbl_text_hint.pack(side="left", padx=(8, 0))  # ставим справа от поля

        # строка с полем hex ввода (скрыта по умолчанию — показывается только в режиме hex)
        self.hex_row = tk.Frame(plain_frame, bg=PALETTE["bg"])  # контейнер для hex поля
        self.txt_plain = self._entry(self.hex_row, width=36)  # поле для ввода hex — 36 символов = 32 hex + запас
        self.txt_plain.pack(side="left")  # ставим в контейнер
        # поле пустое при запуске — пользователь сам вводит hex

        # --- строка 1: ключ ---
        self._lbl(top, "Ключ AES-128:").grid(row=1, column=0, sticky="w", pady=(10, 0))  # подпись слева

        key_frame = tk.Frame(top, bg=PALETTE["bg"])  # контейнер для поля ключа и кнопки
        key_frame.grid(row=1, column=1, padx=10, sticky="w", pady=(10, 0))  # ставим правее подписи

        self.txt_key = self._entry(key_frame, width=36)  # поле для ввода ключа в hex
        self.txt_key.pack(side="left")  # ставим слева в контейнере
        # поле пустое при запуске — пользователь вводит ключ сам или генерирует

        self._btn(key_frame, "Случайный ключ", self._generate_random_key,
                  PALETTE["border"]).pack(side="left", padx=(10, 0))  # кнопка генерации случайного ключа

        self.lbl_key_hint = tk.Label(  # подсказка которая появляется после генерации ключа
            key_frame, text="",
            bg=PALETTE["bg"], fg=PALETTE["accent3"], font=(UI_FONT, 9))
        self.lbl_key_hint.pack(side="left", padx=(8, 0))  # ставим справа от кнопки

        # --- кнопки шифровать / расшифровать ---
        btn_f = tk.Frame(top, bg=PALETTE["bg"])  # контейнер для кнопок действий
        btn_f.grid(row=0, column=2, rowspan=2, padx=14, sticky="ns")  # ставим справа от полей
        self._btn(btn_f, "  Зашифровать  ", self._encrypt,
                  PALETTE["accent"]).pack(pady=(0, 6))  # кнопка шифрования сверху
        self._btn(btn_f, "  Расшифровать  ", self._decrypt,
                  PALETTE["accent2"]).pack()  # кнопка дешифрования снизу

    # строим полосу с результатом под панелью ввода
    def _build_result_bar(self):
        # внешний контейнер — две строки: полная строка результата и отдельное hex поле
        outer = tk.Frame(self, bg=PALETTE["header_bg"], padx=18, pady=7)
        outer.pack(fill="x")  # растягиваем по ширине окна

        # --- верхняя строка: подпись + полный текст результата ---
        top_row = tk.Frame(outer, bg=PALETTE["header_bg"])
        top_row.pack(fill="x")
        self._lbl(top_row, "Результат:", parent_bg=PALETTE["header_bg"]).pack(side="left")  # подпись "результат:"

        # поле с полным текстом результата — только для чтения, выглядит как метка
        self.result_var = tk.StringVar(value="—")  # переменная хранит полный текст результата
        self.lbl_result_entry = tk.Entry(
            top_row,
            textvariable=self.result_var,  # привязываем к переменной
            state="readonly",  # readonly — выделять можно, редактировать нельзя
            readonlybackground=PALETTE["header_bg"],  # фон такой же как у полосы
            fg=PALETTE["subtext"],  # более тусклый цвет — это не главное поле
            font=(MONO_FONT, 11),
            relief="flat", bd=0,
            highlightthickness=0,
            width=80)
        self.lbl_result_entry.pack(side="left", padx=14, fill="x", expand=True)

        # --- нижняя строка: отдельное поле только с hex + кнопки ---
        hex_row = tk.Frame(outer, bg=PALETTE["header_bg"])
        hex_row.pack(fill="x", pady=(5, 0))
        self._lbl(hex_row, "Hex:", parent_bg=PALETTE["header_bg"]).pack(side="left")  # подпись "hex:"

        # поле только с чистым hex — его легко выделить и скопировать вручную
        self.result_hex_var = tk.StringVar(value="—")  # переменная хранит только hex часть результата
        self.lbl_hex_entry = tk.Entry(
            hex_row,
            textvariable=self.result_hex_var,  # привязываем к переменной
            state="readonly",  # readonly — только чтение
            readonlybackground=PALETTE["cell_bg"],  # более тёмный фон — выделяется визуально
            fg=PALETTE["accent3"],
            font=(MONO_FONT, 13, "bold"),
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
            width=36)
        self.lbl_hex_entry.pack(side="left", padx=(10, 0))
        self.lbl_hex_entry.bind("<Control-c>", lambda e: (
            self.lbl_hex_entry.selection_range(0, "end"),
            self.clipboard_clear(),
            self.clipboard_append(self.result_hex_var.get()),
        ) or "break")

        # кнопка копирования — копирует только hex в буфер обмена
        self.btn_copy = self._btn(  # кнопка копирования только hex в буфер обмена
            hex_row, "Копировать hex", self._copy_result,
            PALETTE["border"], small=True)
        self.btn_copy.pack(side="left", padx=(8, 0))

        # кнопка вставки hex в поле ввода — переключает режим на hex и подставляет значение
        self.btn_paste = self._btn(  # кнопка подстановки hex в поле ввода для дешифрования
            hex_row, "Вставить в поле ввода", self._paste_to_input,
            PALETTE["accent2"], small=True)
        self.btn_paste.pack(side="left", padx=(6, 0))

        self.lbl_copy_hint = tk.Label(  # подсказка "скопировано!" которая появляется на 2 секунды
            hex_row, text="",
            bg=PALETTE["header_bg"], fg=PALETTE["accent3"],
            font=(UI_FONT, 9))
        self.lbl_copy_hint.pack(side="left", padx=(8, 0))

    # строим основную область: список шагов слева и детали справа
    def _build_main_area(self):
        main = tk.Frame(self, bg=PALETTE["bg"])  # главный контейнер
        main.pack(fill="both", expand=True, padx=12, pady=6)  # заполняет всё оставшееся пространство
        main.columnconfigure(0, weight=1, minsize=250)  # левая колонка (список шагов) — минимум 250px
        main.columnconfigure(1, weight=3)  # правая колонка (детали) — в 3 раза шире левой
        main.rowconfigure(0, weight=1)  # строка растягивается по высоте

        # --- левая часть: список всех шагов алгоритма ---
        lf = tk.Frame(main, bg=PALETTE["surface"])  # тёмный контейнер для списка
        lf.grid(row=0, column=0, sticky="nsew", padx=(0, 7))  # прижимаем к краям
        lf.rowconfigure(1, weight=1)  # строка со списком растягивается
        lf.columnconfigure(0, weight=1)  # колонка растягивается

        self._lbl(lf, "Шаги алгоритма", bold=True,
                  parent_bg=PALETTE["surface"]).grid(
            row=0, column=0, sticky="w", padx=10, pady=(8, 4))  # заголовок над списком

        sb = tk.Scrollbar(lf)  # полоса прокрутки для списка
        sb.grid(row=1, column=1, sticky="ns")  # ставим справа от списка
        self.listbox = tk.Listbox(  # сам список шагов
            lf, yscrollcommand=sb.set,  # подключаем прокрутку
            bg=PALETTE["cell_bg"], fg=PALETTE["text"],  # цвета фона и текста
            selectbackground=PALETTE["accent"],  # цвет выделенного элемента
            selectforeground="#ffffff",  # белый текст у выделенного элемента
            font=(MONO_FONT, 10),  # моноширинный шрифт — байты выровнены
            activestyle="none", bd=0, highlightthickness=0)  # убираем лишние рамки
        self.listbox.grid(row=1, column=0, sticky="nsew", padx=(4, 0), pady=(0, 4))
        sb.config(command=self.listbox.yview)  # прокрутка управляет списком
        self.listbox.bind("<<ListboxSelect>>", self._on_list_select)  # при клике на шаг — показываем его

        # --- правая часть: детали выбранного шага ---
        right = tk.Frame(main, bg=PALETTE["bg"])  # контейнер для правой части
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self.lbl_op = tk.Label(  # заголовок текущей операции
            right, text="  Введите данные и нажмите «Зашифровать»",
            bg=PALETTE["header_bg"], fg=PALETTE["accent"],
            font=(UI_FONT, 13, "bold"), pady=10, padx=14, anchor="w")
        self.lbl_op.grid(row=0, column=0, sticky="ew")

        detail = tk.Frame(right, bg=PALETTE["bg"])  # контейнер для матрицы и описания
        detail.grid(row=1, column=0, sticky="nsew", pady=6)
        detail.columnconfigure(0, weight=0)  # левая часть (матрица) — фиксированная ширина
        detail.columnconfigure(1, weight=1)  # правая часть (описание) — растягивается
        detail.rowconfigure(0, weight=1)

        # панель с матрицей состояния
        mp = tk.Frame(detail, bg=PALETTE["surface"], padx=16, pady=14)
        mp.grid(row=0, column=0, sticky="nsew", padx=(0, 7))

        self._lbl(mp, "Матрица состояния (4×4)", bold=True,
                  parent_bg=PALETTE["surface"]).pack(anchor="w", pady=(0, 8))  # заголовок матрицы

        mf = tk.Frame(mp, bg=PALETTE["surface"])  # сетка для ячеек матрицы
        mf.pack()
        self.cells = [[None] * 4 for _ in range(4)]  # 4x4 пустых ячеек — заполним ниже
        for r in range(4):  # строки матрицы
            for c in range(4):  # столбцы матрицы
                lbl = tk.Label(
                    mf, text="??", width=5, height=2,  # каждая ячейка — квадратная метка с байтом
                    bg=PALETTE["cell_bg"], fg=PALETTE["text"],
                    font=(MONO_FONT, 15, "bold"), relief="flat")
                lbl.grid(row=r, column=c, padx=3, pady=3)  # размещаем в сетке
                self.cells[r][c] = lbl  # сохраняем ссылку чтобы обновлять значения

        for c in range(4):  # подписи "col0", "col1"... под столбцами
            tk.Label(mf, text=f"col{c}", bg=PALETTE["surface"],
                     fg=PALETTE["subtext"], font=(MONO_FONT, 8)).grid(row=4, column=c)
        for r in range(4):  # подписи "r0", "r1"... справа от строк
            tk.Label(mf, text=f"r{r}", bg=PALETTE["surface"],
                     fg=PALETTE["subtext"], font=(MONO_FONT, 8)).grid(row=r, column=4, padx=(4, 0))

        # панель с описанием операции и раундовым ключом
        ip = tk.Frame(detail, bg=PALETTE["surface"], padx=16, pady=14)
        ip.grid(row=0, column=1, sticky="nsew")
        ip.rowconfigure(1, weight=1)
        ip.columnconfigure(0, weight=1)

        self._lbl(ip, "Описание операции", bold=True,
                  parent_bg=PALETTE["surface"]).grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.txt_desc = scrolledtext.ScrolledText(  # текстовое поле с прокруткой для описания шага
            ip, height=7, wrap="word",  # перенос по словам
            bg=PALETTE["cell_bg"], fg=PALETTE["text"],
            font=(UI_FONT, 11), relief="flat", bd=0,
            state="disabled")  # disabled — только чтение, пользователь не может редактировать
        self.txt_desc.grid(row=1, column=0, sticky="nsew")

        self._lbl(ip, "Раундовый ключ", bold=True,
                  parent_bg=PALETTE["surface"]).grid(row=2, column=0, sticky="w", pady=(14, 4))

        rk_f = tk.Frame(ip, bg=PALETTE["surface"])  # сетка для ячеек раундового ключа
        rk_f.grid(row=3, column=0, sticky="w")
        self.rk_cells = [[None] * 4 for _ in range(4)]  # 4x4 ячеек для ключа
        for r in range(4):
            for c in range(4):
                lbl = tk.Label(
                    rk_f, text="??", width=4, height=1,  # ячейка раундового ключа
                    bg=PALETTE["cell_bg"], fg=PALETTE["subtext"],
                    font=(MONO_FONT, 11), relief="flat")
                lbl.grid(row=r, column=c, padx=2, pady=1)
                self.rk_cells[r][c] = lbl  # сохраняем ссылку

    # строим нижнюю панель навигации по шагам
    def _build_nav_bar(self):
        nav = tk.Frame(self, bg=PALETTE["header_bg"], pady=9)  # тёмная полоса снизу
        nav.pack(fill="x")  # на всю ширину

        self._btn(nav, "|◀ Начало", self._go_first, PALETTE["border"]).pack(side="left", padx=6)  # перейти к первому шагу
        self._btn(nav, "◀ Назад",   self._go_prev,  PALETTE["border"]).pack(side="left", padx=2)  # предыдущий шаг
        self.btn_play = self._btn(nav, "▶  Авто", self._toggle_auto, PALETTE["accent"])  # кнопка автовоспроизведения
        self.btn_play.pack(side="left", padx=6)
        self._btn(nav, "Вперёд ▶", self._go_next, PALETTE["border"]).pack(side="left", padx=2)  # следующий шаг
        self._btn(nav, "Конец ▶|", self._go_last, PALETTE["border"]).pack(side="left", padx=6)  # последний шаг

        self.lbl_step = tk.Label(  # счётчик шагов в правом углу
            nav, text="Шаг 0 / 0",
            bg=PALETTE["header_bg"], fg=PALETTE["subtext"],
            font=(UI_FONT, 10))
        self.lbl_step.pack(side="right", padx=18)

        self._lbl(nav, "Скорость:", parent_bg=PALETTE["header_bg"]).pack(side="right", padx=(14, 4))  # подпись ползунка
        self.speed_var = tk.IntVar(value=700)  # начальная скорость автовоспроизведения — 700 мс на шаг
        ttk.Scale(nav, from_=100, to=2000, orient="horizontal",  # ползунок от 100мс (быстро) до 2000мс (медленно)
                  variable=self.speed_var, length=130).pack(side="right", padx=4)

    # ---- вспомогательные методы для создания виджетов -------------------------

    # создаём текстовую метку с правильными цветами палитры
    def _lbl(self, parent, text, bold=False, parent_bg=None):
        bg = parent_bg if parent_bg else parent["bg"]  # берём цвет фона родителя
        font = (UI_FONT, 10, "bold") if bold else (UI_FONT, 10)  # жирный или обычный
        return tk.Label(parent, text=text, bg=bg, fg=PALETTE["text"], font=font)

    # создаём поле ввода текста с правильными цветами
    def _entry(self, parent, **kw):
        return tk.Entry(
            parent,
            bg=PALETTE["cell_bg"], fg=PALETTE["text"],  # тёмный фон, светлый текст
            insertbackground=PALETTE["text"],  # цвет курсора в поле
            font=(MONO_FONT, 12), relief="flat",  # моноширинный шрифт — для hex удобно
            highlightthickness=1,  # тонкая рамка
            highlightcolor=PALETTE["accent"],  # рамка становится фиолетовой при фокусе
            highlightbackground=PALETTE["border"],  # цвет рамки без фокуса
            **kw)

    # создаём кнопку с нужным цветом фона
    # на macOS tk.Button рисуется средствами системы и игнорирует bg и fg,
    # из-за чего белый текст оказывается на белом фоне. поэтому кнопка
    # собирается из tk.Label — метка красится одинаково на всех системах
    def _btn(self, parent, text, cmd, color, small=False):
        font = (UI_FONT, 9, "bold") if small else (UI_FONT, 10, "bold")  # размер шрифта
        padx, pady = (10, 3) if small else (12, 5)  # внутренние отступы кнопки
        btn = tk.Label(
            parent, text=text,  # надпись на кнопке
            bg=color, fg="#ffffff",  # фон — переданный цвет, текст — белый
            font=font, padx=padx, pady=pady,
            cursor="hand2")  # курсор-рука при наведении
        btn.base_color = color  # запоминаем основной цвет для возврата после наведения
        btn.bind("<Button-1>", lambda _e: cmd())  # клик левой кнопкой вызывает команду
        btn.bind("<Enter>", lambda _e: btn.config(bg=PALETTE["accent"]))  # подсветка при наведении
        btn.bind("<Leave>", lambda _e: btn.config(bg=btn.base_color))  # возврат к основному цвету
        return btn

    # меняем надпись и цвет уже созданной кнопки
    # обычный config не подходит: обработчик <Leave> вернул бы старый цвет
    def _btn_set(self, btn, text, color):
        btn.base_color = color  # обновляем запомненный цвет
        btn.config(text=text, bg=color)  # применяем новую надпись и цвет

    # ---- логика программы ------------------------------------------------------

    # вызывается при переключении радиокнопки "обычный текст / hex"
    def _on_mode_change(self):
        if self.input_mode.get() == "text":  # если выбрали режим обычного текста
            self.hex_row.pack_forget()  # скрываем hex поле
            self.txt_text_input.master.pack(anchor="w", pady=(4, 0))  # показываем поле обычного текста
            self.lbl_text_hint.pack(side="left", padx=(8, 0))  # показываем счётчик символов
            self._on_text_input_change()  # обновляем подсказку
        else:  # если выбрали режим hex
            self.txt_text_input.master.pack_forget()  # скрываем поле текста
            self.lbl_text_hint.pack_forget()  # скрываем счётчик
            self.hex_row.pack(anchor="w", pady=(4, 0))  # показываем hex поле

    # вызывается при каждом нажатии клавиши в поле обычного текста
    def _on_text_input_change(self, event=None):
        text = self.txt_text_input.get()  # получаем текущий текст из поля
        n = len(text)  # считаем количество символов
        if n == 16:  # ровно 16 — всё хорошо
            self.lbl_text_hint.config(text=f"{n}/16 символов — OK", fg=PALETTE["accent3"])
        elif n < 16:  # меньше 16 — нужно ещё
            self.lbl_text_hint.config(text=f"{n}/16 — нужно ещё {16 - n} символов", fg=PALETTE["accent2"])
        else:  # больше 16 — слишком длинно
            self.lbl_text_hint.config(text=f"{n}/16 — слишком длинно (лишних: {n - 16})", fg="#ff4444")

    # копируем только hex часть результата в буфер обмена
    def _copy_result(self):
        hex_text = self.result_hex_var.get()  # берём только hex значение, без лишнего текста
        if hex_text and hex_text != "—":  # копируем только если hex есть
            self.clipboard_clear()  # очищаем буфер обмена
            self.clipboard_append(hex_text)  # вставляем только hex в буфер обмена
            self.lbl_copy_hint.config(text="✓ Скопировано!")  # показываем подтверждение
            self.after(2000, lambda: self.lbl_copy_hint.config(text=""))  # через 2 сек убираем подтверждение

    # вставляем текущий hex результата в поле ввода и переключаем режим на hex
    def _paste_to_input(self):
        hex_text = self.result_hex_var.get()  # берём текущий hex результата
        if not hex_text or hex_text == "—":  # если результата ещё нет — ничего не делаем
            return
        self.input_mode.set("hex")  # переключаем режим ввода на hex
        self._on_mode_change()  # применяем переключение (показываем hex поле, скрываем текстовое)
        self.txt_plain.delete(0, "end")  # очищаем поле hex ввода
        self.txt_plain.insert(0, hex_text)  # вставляем hex результата в поле ввода
        self.lbl_copy_hint.config(text="✓ Вставлено!")  # показываем подтверждение
        self.after(2000, lambda: self.lbl_copy_hint.config(text=""))  # через 2 сек убираем подтверждение

    # генерируем случайный ключ и вставляем его в поле ключа
    def _generate_random_key(self):
        key_bytes = os.urandom(16)  # генерируем 16 случайных байт через криптографический генератор ОС
        hex_key = key_bytes.hex()  # переводим в hex строку (32 символа)
        self.txt_key.delete(0, "end")  # очищаем поле ключа
        self.txt_key.insert(0, hex_key)  # вставляем новый случайный ключ
        self.lbl_key_hint.config(text="Случайный ключ сгенерирован")  # показываем подтверждение
        self.after(3000, lambda: self.lbl_key_hint.config(text=""))  # через 3 секунды убираем подтверждение

    # получаем байты открытого текста с учётом режима ввода
    def _get_plaintext_bytes(self):
        if self.input_mode.get() == "text":  # режим обычного текста
            text = self.txt_text_input.get()  # берём текст из поля
            if len(text) != 16:  # проверяем что ровно 16 символов
                messagebox.showerror("Ошибка",
                    f"Текст должен быть ровно 16 символов.\nСейчас: {len(text)} символов.")
                return None
            return text.encode("utf-8")  # переводим строку в байты через кодировку utf-8
        else:  # режим hex
            ph = self.txt_plain.get().strip().replace(" ", "")  # убираем пробелы из введённого hex
            if len(ph) != 32:  # hex должен быть ровно 32 символа (16 байт × 2 символа)
                messagebox.showerror("Ошибка",
                    "Открытый текст должен быть ровно 32 hex-символа (16 байт).")
                return None
            try:
                return bytes.fromhex(ph)  # переводим hex в байты
            except ValueError:
                messagebox.showerror("Ошибка", "Некорректные hex-символы.")
                return None

    # считываем и проверяем оба поля — текст и ключ
    def _parse_inputs(self):
        pb = self._get_plaintext_bytes()  # получаем байты открытого текста
        if pb is None:  # если была ошибка — выходим
            return None, None
        kh = self.txt_key.get().strip().replace(" ", "")  # убираем пробелы из ключа
        if len(kh) != 32:  # ключ должен быть 32 hex-символа
            messagebox.showerror("Ошибка",
                "Ключ должен быть ровно 32 hex-символа (16 байт).\n"
                "Нажмите «Случайный ключ» чтобы сгенерировать автоматически.")
            return None, None
        try:
            kb = bytes.fromhex(kh)  # переводим hex ключа в байты
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректные hex-символы в ключе.")
            return None, None
        return pb, kb  # возвращаем байты текста и ключа

    # нажатие кнопки "зашифровать"
    def _encrypt(self):
        pb, kb = self._parse_inputs()  # считываем и проверяем поля
        if pb is None:  # если ошибка — выходим
            return
        cipher, trace, rks = aes_encrypt_trace(pb, kb)  # шифруем и получаем трассировку
        self.trace = trace  # сохраняем шаги для навигации
        self.round_keys = rks  # сохраняем ключи для отображения
        self.step_idx = 0  # сбрасываем на первый шаг

        # формируем строку полного результата и отдельно сохраняем чистый hex
        hex_upper = cipher.hex().upper()  # чистый hex шифртекста — только его копируем и вставляем
        self.result_hex_var.set(hex_upper)  # сохраняем hex отдельно для кнопок копирования и вставки
        if self.input_mode.get() == "text":  # если вводили обычный текст — показываем его рядом
            src = f'"{self.txt_text_input.get()}"  →  '
        else:
            src = ""
        self.result_var.set(src + "Шифртекст: " + hex_upper)  # выводим полный результат в верхнее поле
        self._populate_list()  # заполняем список шагов
        self._show_step(0)  # показываем первый шаг

    # нажатие кнопки "расшифровать"
    def _decrypt(self):
        pb, kb = self._parse_inputs()  # считываем и проверяем поля
        if pb is None:  # если ошибка — выходим
            return
        plain, trace, rks = aes_decrypt_trace(pb, kb)  # дешифруем и получаем трассировку
        self.trace = trace  # сохраняем шаги
        self.round_keys = rks  # сохраняем ключи
        self.step_idx = 0  # сбрасываем на первый шаг

        hex_result = plain.hex().upper()  # переводим результат в hex строку
        self.result_hex_var.set(hex_result)  # сохраняем hex отдельно для кнопок копирования и вставки

        # пробуем перевести байты в читаемый текст
        try:
            readable = plain.decode("utf-8")  # пробуем декодировать как utf-8 текст
            if readable:
                text_part = f'  |  Текст: "{readable}"'  # добавляем текст к результату
            else:
                text_part = "  |  (бинарные данные)"
        except Exception:
            text_part = "  |  (бинарные данные)"  # не utf-8 — бинарные данные

        self.result_var.set(f"Hex: {hex_result}{text_part}")  # выводим hex и текст вместе в поле
        self._populate_list()  # заполняем список шагов
        self._show_step(0)  # показываем первый шаг

    # заполняем список шагов слева — названия всех операций
    def _populate_list(self):
        self.listbox.delete(0, "end")  # очищаем список перед заполнением
        for step in self.trace:  # проходим по всем шагам трассировки
            self.listbox.insert("end", f"[{step['round']:2d}] {step['operation']}")  # добавляем строку

    # показываем конкретный шаг с номером idx
    def _show_step(self, idx):
        if not self.trace:  # если трассировки нет — ничего не делаем
            return
        idx = max(0, min(idx, len(self.trace) - 1))  # ограничиваем индекс допустимым диапазоном
        self.step_idx = idx  # запоминаем текущий шаг
        step = self.trace[idx]  # берём данные этого шага

        self.listbox.selection_clear(0, "end")  # снимаем выделение со всех элементов списка
        self.listbox.selection_set(idx)  # выделяем текущий шаг
        self.listbox.see(idx)  # прокручиваем список чтобы шаг был виден

        op = step["operation"]  # название операции этого шага
        color = PALETTE["op_colors"].get(op, PALETTE["accent"])  # цвет для этой операции
        self.lbl_op.config(text=f"  Раунд {step['round']}  —  {op}", fg=color)  # обновляем заголовок

        state = step["state"]  # матрица состояния на этом шаге

        for r in range(4):  # сбрасываем все ячейки матрицы на исходный цвет
            for c in range(4):
                self.cells[r][c].config(text=hex2(state[r][c]), bg=PALETTE["cell_bg"], fg=PALETTE["text"])

        # подсвечиваем байты которые изменились по сравнению с предыдущим шагом
        if idx > 0:
            prev = self.trace[idx - 1]["state"]  # матрица предыдущего шага
            for r in range(4):
                for c in range(4):
                    if state[r][c] != prev[r][c]:  # если байт изменился
                        self.cells[r][c].config(bg=color, fg=PALETTE["header_bg"])  # подсвечиваем цветом операции

        # обновляем поле описания
        self.txt_desc.config(state="normal")  # временно разрешаем редактирование чтобы вставить текст
        self.txt_desc.delete("1.0", "end")  # очищаем старый текст
        self.txt_desc.insert("end", step["description"])  # вставляем новое описание
        self.txt_desc.config(state="disabled")  # снова запрещаем редактирование

        # обновляем матрицу раундового ключа
        rnd = min(step["round"], 10)  # номер раунда (не больше 10)
        if self.round_keys:
            rk = self.round_keys[rnd]  # берём ключ нужного раунда
            for r in range(4):
                for c in range(4):
                    self.rk_cells[r][c].config(text=hex2(rk[r][c]))  # обновляем ячейку

        self.lbl_step.config(text=f"Шаг {idx + 1} / {len(self.trace)}")  # обновляем счётчик шагов

    # вызывается при клике на элемент в списке шагов
    def _on_list_select(self, _event):
        sel = self.listbox.curselection()  # получаем индекс выбранного элемента
        if sel:  # если что-то выбрано
            self._show_step(sel[0])  # показываем этот шаг

    # кнопки навигации по шагам
    def _go_first(self): self._show_step(0)  # перейти к первому шагу
    def _go_last(self):  self._show_step(len(self.trace) - 1)  # перейти к последнему шагу
    def _go_prev(self):  self._show_step(self.step_idx - 1)  # предыдущий шаг
    def _go_next(self):  self._show_step(self.step_idx + 1)  # следующий шаг

    # кнопка автовоспроизведения — запускает или останавливает автоматический переход по шагам
    def _toggle_auto(self):
        self.auto_play = not self.auto_play  # переключаем флаг
        if self.auto_play:  # если включили
            self._btn_set(self.btn_play, "⏸  Пауза", PALETTE["accent2"])  # меняем кнопку на "пауза"
            self._auto_step()  # запускаем первый шаг автовоспроизведения
        else:  # если выключили
            self._btn_set(self.btn_play, "▶  Авто", PALETTE["accent"])  # возвращаем кнопку "авто"
            if self.auto_job:
                self.after_cancel(self.auto_job)  # отменяем запланированный следующий шаг

    # один тик автовоспроизведения — переходит к следующему шагу и планирует следующий тик
    def _auto_step(self):
        if not self.auto_play:  # если автовоспроизведение выключено — выходим
            return
        if self.step_idx < len(self.trace) - 1:  # если не последний шаг
            self._go_next()  # переходим к следующему
            delay = max(100, int(self.speed_var.get()))  # задержка из ползунка (минимум 100мс)
            self.auto_job = self.after(delay, self._auto_step)  # планируем следующий тик
        else:  # если достигли последнего шага
            self.auto_play = False  # останавливаем автовоспроизведение
            self._btn_set(self.btn_play, "▶  Авто", PALETTE["accent"])  # возвращаем кнопку


# ============================================================
# точка входа — запуск программы
# ============================================================

# эта проверка нужна чтобы код ниже выполнялся только при прямом запуске файла
# если файл импортируют как модуль — окно не откроется
if __name__ == "__main__":
    app = AESVisualizer()  # создаём главное окно программы
    app.mainloop()  # запускаем цикл обработки событий — программа работает пока окно открыто
