# מדריך הפעלה — שלב אחר שלב (מאפס)

המדריך הזה מניח שלא נגעת בפרויקט חודשים ולא זוכרת כלום. עבדי לפי הסדר.
כל פקודות ה-PowerShell רצות בתיקיית הפרויקט שלך (`EDR-main`).

> **איפה הכול יושב:** החלק החדש (הגלאי) הוא תיקיית `ml/`. שחררי את ה-zip
> שקיבלת לתוך תיקיית הפרויקט כך שתהיה `EDR-main\ml\`. הקוד של ה-EDR עצמו הוא
> C/C++ ונמצא ב-`src\`. הדשבורד ב-`dashboard\`.

---

## מה צריך להיות מותקן (בדקי פעם אחת)

- Windows 10/11 x64
- Visual Studio 2022 עם ה-workload של **Desktop development with C++**
- CMake 3.20+
- vcpkg (מנהל החבילות של C++)
- Python 3.9+ (יש לך — את עובדת עם Python)

אם VS2022 / vcpkg לא מותקנים אצלך יותר, זה מה שלוקח הכי הרבה זמן — התקיני קודם.

---

## שלב 0 — להחזיר את הפרויקט הקיים לפעול

**בלי השלב הזה שום דבר אחר לא יעבוד**, כי הגלאי לומד מהאירועים שהסוכן מייצר.

### 0.1 להוריד את pe-sieve (חובה!)
ב-zip של GitHub תיקיית `pe-sieve\` **ריקה** — זה תת-מודול שלא נכלל ב-zip.
בלעדיו הבנייה תיכשל. פתחי PowerShell בתיקיית הפרויקט והריצי:

```powershell
git clone --recursive https://github.com/hasherezade/pe-sieve.git pe-sieve
git -C pe-sieve checkout f1dc39d
git -C pe-sieve submodule update --init --recursive
```

### 0.2 לבנות את הפרויקט
(החליפי את נתיב ה-vcpkg אם הוא מותקן אצלך במקום אחר)

```powershell
cmake -B build -S . -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
```

הבנייה הראשונה לוקחת זמן (vcpkg מוריד cjson, detours, yara). בסוף כל הקבצים
יהיו ב-`build\bin\Release\`.

### 0.3 לוודא שהכול חי — הדמו
האנטי-וירוס יסמן את הבדיקות (הן כותבות מחרוזת EICAR לזיכרון). לכן:
- הוסיפי את תיקיית `build` ל-Exclusions של Windows Defender, **או** עבדי ב-VM.
- פתחי PowerShell **כמנהל** (As Administrator) — ההזרקה דורשת הרשאות.

```powershell
.\start_dashboard.bat
```

זה פותח את הדשבורד ב-<http://localhost:8080>. לחצי **RUN DEMO** וצפי בחומרה
עולה LOW → MEDIUM → HIGH → CRITICAL. אם זה קורה — הפרויקט חי ואפשר להמשיך. ✅

אם משהו נתקע כאן, ראי "פתרון תקלות" בסוף.

---

## שלב 1 — להכין את החלק החדש

1. ודאי שתיקיית `ml\` נמצאת בתוך `EDR-main\`.
2. התקיני PyTorch (גרסת CPU מספיקה):

```powershell
pip install torch numpy
```

(`collect.py` — איסוף הדאטה — צריך רק Python, בלי torch. torch נחוץ רק לאימון.)

3. בדיקת שפיות של הצינור, בלי שום דאטה:

```powershell
cd ml
python _smoke_test.py
```

אם מודפס `PIPELINE OK` — הכול מחובר נכון.

---

## שלב 2 — לאסוף דאטה (זה הלב של העבודה)

הרעיון: מריצים את הסוכן, מריצים לידו את ה-recorder שמתעד, ואז מפעילים
תהליך — תקיפה (מהבדיקות הקיימות שלך) או תהליך תקין. ה-recorder כותב קובץ
`.ndjson` אחד עם ה-traces.

תצטרכי **שלושה** חלונות PowerShell (כולם As Administrator), כולם ב-`build\bin\Release`.

### 2.1 דאטה של הזרקות — לכל בדיקה בנפרד
דוגמה ל-`test_ProcessHollowing`:

```powershell
# חלון A — הסוכן, עם לוג לקובץ
.\argus_agent.exe > argus_agent.log 2>&1

# חלון B — ה-recorder (מתייג לפי הטכניקה)
cd ..\..\..\ml
python collect.py --agent-log ..\build\bin\Release\argus_agent.log `
    --label injection --technique process_hollowing `
    --out data\hollowing_01.ndjson

# חלון C — מריצים את הבדיקה ומזריקים אליה את ה-hook
.\test_ProcessHollowing.exe        # רשמי את ה-PID שמודפס
.\injector.exe <PID> argus_hook.dll
.\injector.exe <PID> argus_pesieve.dll
```

כשהבדיקה סיימה — Ctrl-C בחלון B (או שהוא עוצר לבד אחרי 15 שניות בלי אירועים).

**חזרי על זה הרבה פעמים** (20–30) כדי לצבור traces. חזרה פשוטה בלולאה מספיקה —
השונות הטבעית בין ריצות היא מה שהמודל לומד ממנו.

עשי את זה לכל בדיקה קיימת, עם `--technique` שונה בכל קובץ:

| הבדיקה שמריצים | `--technique` | שם קובץ מוצע |
|---|---|---|
| `test_target` | `remote_thread` | `remote_thread_01.ndjson` |
| `test_ProcessHollowing` | `process_hollowing` | `hollowing_01.ndjson` |
| `test_ModuleStomping` / `2` | `module_stomping` | `stomping_01.ndjson` |
| `shellcode_runner` | `shellcode_runner` | `shellcode_01.ndjson` |

### 2.2 דאטה תקין (כולל המקרה הקשה)
אותו דבר, אבל מזריקים את ה-hook לתהליך **רגיל** ומשתמשים בו דקה:

```powershell
# חלון B
python collect.py --agent-log ..\build\bin\Release\argus_agent.log `
    --label benign --out data\benign_powershell_01.ndjson

# חלון C — מזריקים לתהליך קיים (powershell / node / java / chrome)
.\injector.exe <PID-של-powershell> argus_hook.dll
# ואז פשוט תשתמשי בו: הריצי פקודות, פתחי דברים
```

**הכי חשוב:** powershell, node ו-java (מנועי JIT) — אלה התהליכים התקינים
שהכי מבלבלים את ה-FSM, אז הם הדאטה התקין הכי בעל ערך. אספי מכמה אפליקציות.

**איזון:** כמה עשרות traces של תקיפות וכמה עשרות תקינים, פחות או יותר שווה.

---

## שלב 3 — אימון

כשיש לך קבצי `.ndjson` בתיקיית `ml\data\`:

```powershell
cd ml
python train.py --data "data/*.ndjson" --epochs 40 --out model.pt
```

זה ידפיס לכל epoch את ה-detection ו-FPR על ה-validation, וישמור את המודל הכי טוב.

---

## שלב 4 — הערכה (המספרים לקורות חיים / לדו"ח)

```powershell
python evaluate.py --data "data/*.ndjson" --model model.pt
```

מדפיס detection rate, false-positive rate (כולל על ה-JIT), precision, AUC,
ופירוק לפי טכניקה.

**המבחן שהכי שווה בדו"ח — leave-one-technique-out** (מאמן בלי טכניקה אחת ובודק
אם המודל עדיין תופס אותה). הריצי ב-Python:

```python
from dataset import load_many
from evaluate import leave_one_technique_out
import glob, json
traces = load_many(glob.glob("data/*.ndjson"))
print(json.dumps(leave_one_technique_out(traces, epochs=40), indent=2))
```

---

## פתרון תקלות נפוצות

- **הבנייה נכשלת על pe-sieve** → לא עשית את שלב 0.1. הריצי אותו.
- **`cmake` לא נמצא / vcpkg** → ודאי ש-CMake ו-vcpkg מותקנים ושהנתיב ל-vcpkg נכון.
- **ההזרקה נכשלת (injector)** → את לא ב-PowerShell As Administrator.
- **הבדיקות נעלמות מיד / האנטי-וירוס מתלונן** → הוסיפי את `build` ל-Defender Exclusions.
- **`collect.py` כותב 0 traces** → ודאי שחלון A (הסוכן) כותב ל-`argus_agent.log`
  ושהנתיב שנתת ל-`--agent-log` נכון, ושההזרקה הצליחה.
- **ה-recorder לא תופס כלום** → הוא קורא רק שורות חדשות. הפעילי אותו *לפני*
  שמזריקים, או הוסיפי `--from-start` כדי לקרוא את כל הלוג.

---

## ריאלי להגיע לתוצאות היום ומחר?

כן, בתנאי אחד: שהבנייה (שלב 0) עובדת.

- **היום:** שלב 0 (להחיות את הפרויקט) + שלב 1 + להתחיל איסוף דאטה (שלב 2).
  אם הבנייה חלקה, זה כמה שעות. רוב הזמן ילך לאיסוף חזרות.
- **מחר:** לסיים איסוף, אימון (שלב 3) והערכה (שלב 4) כולל leave-one-technique-out.
  זה החלק המהיר — דקות, לא שעות.

הסיכון היחיד ללו"ז הוא שלב 0: אם VS/vcpkg צריכים התקנה מחדש או שהבנייה נשברה
אחרי 5 חודשים, זה יכול לאכול חצי יום. ברגע שהדמו רץ — השאר מהיר.
```
