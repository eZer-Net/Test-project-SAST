package main

import (
    "encoding/json"
    "fmt"
    "regexp"
    "html/template"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "image"
    "image/color"
    "image/draw"
    "image/png"
    "math/rand"
    "time"
    "bytes"
    "encoding/base64"
    "golang.org/x/image/font"
    "golang.org/x/image/font/basicfont"
    "golang.org/x/image/math/fixed"
    "github.com/gorilla/sessions"
    "github.com/gorilla/mux"
)
var sessionStore *sessions.FilesystemStore
type User struct {
    Username      string `json:"username"`
    Password      string `json:"password"`
    FreeMinutesRest      uint64 `json:"freeins"`
    BalanceMinutes uint64 `json:"minutes"`
    BalanceKapibaks uint64 `json:"kapibaks"`
}

var rate_min_to_baks uint64 = 101

const (
    usersDir    = "data/users"
)

func generateCaptchaBase64(num1, num2 int) (string, int) {
    img := image.NewRGBA(image.Rect(0, 0, 200, 80))
    draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)
    text := fmt.Sprintf("%d + %d = ?", num1, num2)
    addTextToImage(img, text)
    var buf bytes.Buffer
    png.Encode(&buf, img)
    base64Str := base64.StdEncoding.EncodeToString(buf.Bytes())
    return base64Str, num1 + num2
}

func addTextToImage(img *image.RGBA, text string) {
    col := color.Black
    x, y := 20, 40
    for _, char := range text {
        drawChar(img, x, y, col, char)
        x += 20
    }
}

func drawChar(img *image.RGBA, x, y int, col color.Color, char rune) {
    d := &font.Drawer{
        Dst:  img,
        Src:  image.NewUniform(col),
        Face: basicfont.Face7x13,
        Dot:  fixed.P(x, y),
    }
    d.DrawString(string(char))
}

func init() {
    sessionDir := "./sessions"
    err := os.MkdirAll(sessionDir, 0755)
    if err != nil {
        panic(fmt.Sprintf("Не удалось создать директорию для сессий: %v", err))
    }

    // Инициализируем FilesystemStore
    sessionStore = sessions.NewFilesystemStore(sessionDir,  []byte(os.Getenv("SESSION_KEY")))
}

func saveUser(user *User) {
    data, err := json.Marshal(user)
    if err != nil {
        log.Printf("Ошибка при сериализации пользователя %s: %v", user.Username, err)
        return
    }

    err = os.MkdirAll(usersDir, 0755)
    if err != nil {
        log.Printf("Ошибка при создании директории для пользователей: %v", err)
        return
    }

    filePath := filepath.Join(usersDir, fmt.Sprintf("%s.json", user.Username))
    err = ioutil.WriteFile(filePath, data, 0644)
    if err != nil {
        log.Printf("Ошибка при записи пользователя %s в файл: %v", user.Username, err)
    }
}

func loadUser(username string) (*User, bool) {
    filePath := filepath.Join(usersDir, fmt.Sprintf("%s.json", username))
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, false
        }
        log.Printf("Ошибка при чтении пользователя %s: %v", username, err)
        return nil, false
    }

    var user User
    err = json.Unmarshal(data, &user)
    if err != nil {
        log.Printf("Ошибка при десериализации пользователя %s: %v", username, err)
        return nil, false
    }

    return &user, true
}
func sanitizeUsername(username string) string {
    re := regexp.MustCompile(`[^a-zA-Z0-9]`)
    sanitized := re.ReplaceAllString(username, "")
    return sanitized
}
func main() {
    r := mux.NewRouter()
    r.HandleFunc("/", homeHandler).Methods("GET")
    r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
    r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
    r.HandleFunc("/exchange", exchangeHandler).Methods("GET", "POST")
    r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
    println("Сервер на 8080")
    http.ListenAndServe(":8080", r)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    session, err := sessionStore.Get(r, "session_id")
    if err != nil {
        tmpl := template.Must(template.ParseFiles("templates/login.html"))
        tmpl.Execute(w, nil)
        return
    }
    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        tmpl := template.Must(template.ParseFiles("templates/login.html"))
        tmpl.Execute(w, nil)
        return
    }
    user, exists := loadUser(username)
    if !exists {
        http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
        return
    }

    tmpl := template.Must(template.ParseFiles("templates/home.html"))
    tmpl.Execute(w, map[string]interface{}{
        "username": user.Username,
        "user":  user,
        "rate":   rate_min_to_baks,
    })
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        rand.Seed(time.Now().UnixNano())
        num1 := rand.Intn(10) + 1
        num2 := rand.Intn(10) + 1

        captchaBase64, sum := generateCaptchaBase64(num1, num2)

        session, err := sessionStore.Get(r, "session_id")
        if err != nil {
            session, _ = sessionStore.New(r, "session_id")
        }
        session.Values["captcha"] = sum
        err = session.Save(r, w)

        tmpl := template.Must(template.ParseFiles("templates/register.html"))
        tmpl.Execute(w, map[string]interface{}{
            "captcha_base64": captchaBase64,
        })
        return
    }
    session, err := sessionStore.Get(r, "session_id")
    if err != nil {
        session, _ = sessionStore.New(r, "session_id")
    }
    username := r.FormValue("username")
    username = sanitizeUsername(username)
    password := r.FormValue("password")
    captchaAnswer := r.FormValue("captcha_answer")

    captcha, ok := session.Values["captcha"]
    if !ok {
        http.Error(w, "Нет капчи", http.StatusBadRequest)
        return
    }
    expectedSum := captcha.(int)
    userAnswer, err := strconv.ParseInt(captchaAnswer, 10, 64)
    if err != nil || userAnswer != int64(expectedSum) {
        http.Error(w, "Неверный ответ на капчу", http.StatusBadRequest)
        return
    }

    if username == "" || password == "" {
        http.Error(w, "Имя пользователя и пароль обязательны", http.StatusBadRequest)
        return
    }

    if len(username) < 9 || len(password) < 9 {
        http.Error(w, "Имя пользователя или пароль слишком короткие", http.StatusBadRequest)
        return
    }

    _, exists := loadUser(username)
    if exists {
        http.Error(w, "Пользователь уже существует", http.StatusBadRequest)
        return
    }

    user := &User{
        Username:      username,
        Password:      password,
        FreeMinutesRest: 10000000,
        BalanceMinutes: 0,
        BalanceKapibaks:  1,
    }
    log.Printf("Новый пользователь %s:%s", user.Username,user.Password)
    saveUser(user)

    http.Redirect(w, r, "/", http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    username = sanitizeUsername(username)
    password := r.FormValue("password")

    user, exists := loadUser(username)
    if !exists || user.Password != password {
        http.Error(w, "Неверное имя пользователя или пароль", http.StatusUnauthorized)
        return
    }
    session, err := sessionStore.Get(r, "session_id")
    if err != nil {
        session, _ = sessionStore.New(r, "session_id")
    }
    log.Printf("Вход пользователя %s:%s", user.Username,user.Password)
    session.Values["username"] = username
    err = session.Save(r, w)
    http.Redirect(w, r, "/", http.StatusFound)
}
func exchangeHandler(w http.ResponseWriter, r *http.Request) {
    session, err := sessionStore.Get(r, "session_id")
    if err != nil {
        session, _ = sessionStore.New(r, "session_id")
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }
    user, exists := loadUser(username)
    if !exists {
        http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }
    amountStr := r.FormValue("amount")
    amountBaks, err := strconv.ParseUint(amountStr, 10, 64)

    if err != nil || amountBaks <= 0 {
        http.Error(w, "Неверное количество минут", http.StatusBadRequest)
        return
    }
    dirStr := r.FormValue("direction")
    log.Printf("Транзакция пользователя %s %v %v", user.Username,dirStr,amountBaks)
    if dirStr == "min_to_baks" {
        mins := amountBaks * rate_min_to_baks
        if user.BalanceMinutes < mins {
                http.Error(w, "Недостаточно минут", http.StatusBadRequest)
                return
        }
        user.BalanceMinutes -= mins
        user.FreeMinutesRest += mins
        user.BalanceKapibaks += amountBaks
    } else if dirStr == "baks_to_min" {
        amount_mins := amountBaks * rate_min_to_baks
        if user.BalanceKapibaks < amountBaks {
                http.Error(w, "Недостаточно капибаксов", http.StatusBadRequest)
                return
        }
        user.BalanceMinutes += amount_mins
        user.FreeMinutesRest -= amount_mins
        user.BalanceKapibaks -= amountBaks
    } else{
        http.Error(w, "Не поддерживается", http.StatusBadRequest)
        return
    }
    saveUser(user)
    if user.FreeMinutesRest < rate_min_to_baks {
        flag := "tctf{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
        
        tmpl := template.Must(template.ParseFiles("templates/flag.html"))
        tmpl.Execute(w, map[string]interface{}{
                "username": user.Username,
                "flag":     flag,
                "balance":  user,
        })
    } else {
        http.Redirect(w, r, "/", http.StatusFound)
    }
}
