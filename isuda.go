package main

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Songmu/strrand"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/render"
)

const (
	sessionName   = "isuda_session"
	sessionSecret = "tonymoris"
)

var (
	entryCache *EntryCache
	repl1      *strings.Replacer
	repl2      *strings.Replacer
	replver    int64
	replmtx    *sync.RWMutex

	lastID    int
	lastIDmux *sync.Mutex

	cachePopulated bool

	isutarEndpoint string
	isupamEndpoint string

	baseUrl *url.URL
	db      *sql.DB
	re      *render.Render
	store   *sessions.CookieStore

	errInvalidUser = errors.New("Invalid User")

	// stars
	stardb    *sql.DB
	starre    *render.Render
	starCache *StarCache
)

func getReplacers() (int64, *strings.Replacer, *strings.Replacer) {
	replmtx.RLock()
	ver := replver
	r1 := repl1
	r2 := repl2
	replmtx.RUnlock()
	return ver, r1, r2
}

func replacerRules() ([]string, []string) {
	rows, err := db.Query(`
		SELECT keyword FROM entry ORDER BY CHARACTER_LENGTH(keyword) DESC
	`)
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	ks := make([]string, 0, 8000)
	for rows.Next() {
		var k string
		err := rows.Scan(&k)
		if err != nil {
			rows.Close()
			panic(err)
		}
		ks = append(ks, k)
	}
	rows.Close()
	rule1 := make([]string, 0, 16000)
	rule2 := make([]string, 0, 16000)
	for _, k := range ks {
		sha := "isuda_" + fmt.Sprintf("%x", sha1.Sum([]byte(k)))
		u, err := url.Parse(baseUrl.String() + "/keyword/" + pathURIEscape(k))
		panicIf(err)
		link := fmt.Sprintf("<a href=\"%s\">%s</a>", u, html.EscapeString(k))
		rule1 = append(rule1, k, sha)
		rule2 = append(rule2, sha, link)
	}
	rule2 = append(rule2, "\n", "<br />\n")
	return rule1, rule2
}

func updateReplacers() {
	replmtx.Lock()
	rule1, rule2 := replacerRules()
	replver++
	repl1 = strings.NewReplacer(rule1...)
	repl2 = strings.NewReplacer(rule2...)
	replmtx.Unlock()
	go refreshCacheForTop()
}

func initializeReplacers() {
	replmtx.Lock()
	rule1, rule2 := replacerRules()
	replver++
	repl1 = strings.NewReplacer(rule1...)
	repl2 = strings.NewReplacer(rule2...)
	replmtx.Unlock()
}

func init() {
	entryCache = NewEntryCache()
	replmtx = &sync.RWMutex{}
	lastIDmux = &sync.Mutex{}
	starCache = NewStarCache()
}

func setName(w http.ResponseWriter, r *http.Request) error {
	session := getSession(w, r)
	userID, ok := session.Values["user_id"]
	if !ok {
		return nil
	}
	setContext(r, "user_id", userID)
	row := db.QueryRow(`SELECT name FROM user WHERE id = ?`, userID)
	user := User{}
	err := row.Scan(&user.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return errInvalidUser
		}
		panicIf(err)
	}
	setContext(r, "user_name", user.Name)
	return nil
}

func authenticate(w http.ResponseWriter, r *http.Request) error {
	if u := getContext(r, "user_id"); u != nil {
		return nil
	}
	return errInvalidUser
}

func initializeHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec(`DELETE FROM entry WHERE id > 7101`)
	panicIf(err)

	initializeReplacers()
	go populateCache()

	lastIDmux.Lock()
	row := db.QueryRow(`
		SELECT id FROM entry ORDER BY id DESC LIMIT 1
	`)
	err = row.Scan(&lastID)
	panicIf(err)
	lastIDmux.Unlock()

	_, err = stardb.Exec("TRUNCATE star")
	panicIf(err)
	populateStarCache()
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func profileStartHandler(w http.ResponseWriter, r *http.Request) {
	f, err := ioutil.TempFile(os.TempDir(), getProgName()+".pprof.")
	if err != nil {
		panic(err)
	}
	pprof.StartCPUProfile(f)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			logdbg("captured %v, stopping profiler and exiting...", sig)
			pprof.StopCPUProfile()
			os.Exit(1)
		}
	}()
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
	logdbg("profile started: %s", f.Name())
}

func profileStopHandler(w http.ResponseWriter, r *http.Request) {
	pprof.StopCPUProfile()
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
	logdbg("profile stopped")
}

func dumpMemprofileHandler(w http.ResponseWriter, r *http.Request) {
	f, err := ioutil.TempFile(os.TempDir(), getProgName()+".memprof.")
	if err != nil {
		panic(err)
	}
	pprof.WriteHeapProfile(f)
	f.Close()
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
	logdbg("memory profile dumped")
}

func cacheSizeHandler(w http.ResponseWriter, r *http.Request) {
	entryCache.mtx.RLock()
	n := len(entryCache.m)
	entryCache.mtx.RUnlock()
	re.JSON(w, http.StatusOK, map[string]string{
		"result": "ok",
		"size":   fmt.Sprintf("%d", n),
	})
}

func cacheClearHandler(w http.ResponseWriter, r *http.Request) {
	entryCache.mtx.Lock()
	entryCache.m = make(map[string]*Entry)
	entryCache.mtx.Unlock()
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func topHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	perPage := 10
	p := r.URL.Query().Get("page")
	if p == "" {
		p = "1"
	}
	page, _ := strconv.Atoi(p)

	rows, err := db.Query(fmt.Sprintf(
		"SELECT keyword FROM entry ORDER BY updated_at DESC LIMIT %d OFFSET %d",
		perPage, perPage*(page-1),
	))
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	ks := make([]string, 0, 10)
	for rows.Next() {
		var k string
		err := rows.Scan(&k)
		if err != nil {
			rows.Close()
			panic(err)
		}
		ks = append(ks, k)
	}
	rows.Close()

	entries := make([]*Entry, 0, 10)
	for _, k := range ks {
		e, ok := loadEntry(k)
		if !ok {
			continue
		}
		htmlify(e)
		ce := e.Copy()
		ce.Stars = readStars(k)
		entries = append(entries, &ce)
	}

	var totalEntries int
	row := db.QueryRow(`SELECT COUNT(*) FROM entry`)
	err = row.Scan(&totalEntries)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}

	lastPage := int(math.Ceil(float64(totalEntries) / float64(perPage)))
	pages := make([]int, 0, 10)
	start := int(math.Max(float64(1), float64(page-5)))
	end := int(math.Min(float64(lastPage), float64(page+5)))
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}

	re.HTML(w, http.StatusOK, "index", struct {
		Context  context.Context
		Entries  []*Entry
		Page     int
		LastPage int
		Pages    []int
	}{
		r.Context(), entries, page, lastPage, pages,
	})
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	notFound(w)
}

func keywordPostHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := r.FormValue("keyword")
	if keyword == "" {
		badRequest(w)
		return
	}
	userID := getContext(r, "user_id").(int)
	description := r.FormValue("description")

	if isSpamContents(description) || isSpamContents(keyword) {
		http.Error(w, "SPAM!", http.StatusBadRequest)
		return
	}
	err := insertOrUpdateEntry(userID, keyword, description)
	panicIf(err)
	http.Redirect(w, r, "/", http.StatusFound)
	//entryCache.Clear()
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "login",
	})
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	row := db.QueryRow(`SELECT * FROM user WHERE name = ?`, name)
	user := User{}
	err := row.Scan(&user.ID, &user.Name, &user.Salt, &user.Password, &user.CreatedAt)
	if err == sql.ErrNoRows || user.Password != fmt.Sprintf("%x", sha1.Sum([]byte(user.Salt+r.FormValue("password")))) {
		forbidden(w)
		return
	}
	panicIf(err)
	session := getSession(w, r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "register",
	})
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	pw := r.FormValue("password")
	if name == "" || pw == "" {
		badRequest(w)
		return
	}
	userID := register(name, pw)
	session := getSession(w, r)
	session.Values["user_id"] = userID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func register(user string, pass string) int64 {
	salt, err := strrand.RandomString(`....................`)
	panicIf(err)
	res, err := db.Exec(`INSERT INTO user (name, salt, password, created_at) VALUES (?, ?, ?, NOW())`,
		user, salt, fmt.Sprintf("%x", sha1.Sum([]byte(salt+pass))))
	panicIf(err)
	lastInsertID, _ := res.LastInsertId()
	return lastInsertID
}

func keywordByKeywordHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword, uerr := pathURIUnescape(mux.Vars(r)["keyword"])
	if uerr != nil {
		panic(uerr)
	}
	e, ok := loadEntry(keyword)
	if !ok {
		notFound(w)
		return
	}
	htmlify(e)
	ce := e.Copy()
	ce.Stars = readStars(keyword)

	re.HTML(w, http.StatusOK, "keyword", struct {
		Context context.Context
		Entry   Entry
	}{
		r.Context(), ce,
	})
}

func keywordByKeywordDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword, _ := pathURIUnescape(mux.Vars(r)["keyword"])
	if keyword == "" {
		badRequest(w)
		return
	}
	if r.FormValue("delete") == "" {
		badRequest(w)
		return
	}
	ok, err := dropEntry(keyword)
	panicIf(err)
	if !ok {
		notFound(w)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func htmlify(e *Entry) {
	v, r1, r2 := getReplacers()

	e.RLock()
	hv := e.HtmlVersion
	e.RUnlock()

	if hv >= v {
		return
	}

	e.Lock()
	hv = e.HtmlVersion
	if hv >= v {
		e.Unlock()
		return
	}
	e.Html = r2.Replace(html.EscapeString(r1.Replace(e.Description)))
	e.HtmlVersion = v
	e.Unlock()
}

func isSpamContents(content string) bool {
	v := url.Values{}
	v.Set("content", content)
	resp, err := http.PostForm(isupamEndpoint, v)
	panicIf(err)

	var data struct {
		Valid bool `json:valid`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		resp.Body.Close()
		panic(err)
	}
	resp.Body.Close()
	return !data.Valid
}

func getContext(r *http.Request, key interface{}) interface{} {
	return r.Context().Value(key)
}

func setContext(r *http.Request, key, val interface{}) {
	if val == nil {
		return
	}

	r2 := r.WithContext(context.WithValue(r.Context(), key, val))
	*r = *r2
}

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, sessionName)
	return session
}

func main() {
	starMain()

	host := os.Getenv("ISUDA_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUDA_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUDA_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUDA_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUDA_DB_PASSWORD")
	dbname := os.Getenv("ISUDA_DB_NAME")
	if dbname == "" {
		dbname = "isuda"
	}

	db, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, dbname,
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	db.Exec("SET NAMES utf8mb4")

	isutarEndpoint = os.Getenv("ISUTAR_ORIGIN")
	if isutarEndpoint == "" {
		isutarEndpoint = "http://localhost:5001"
	}
	isupamEndpoint = os.Getenv("ISUPAM_ORIGIN")
	if isupamEndpoint == "" {
		isupamEndpoint = "http://localhost:5050"
	}

	store = sessions.NewCookieStore([]byte(sessionSecret))

	re = render.New(render.Options{
		Directory: "views",
		Funcs: []template.FuncMap{
			{
				"url_for": func(path string) string {
					return baseUrl.String() + path
				},
				"title": func(s string) string {
					return strings.Title(s)
				},
				"raw": func(text string) template.HTML {
					return template.HTML(text)
				},
				"add": func(a, b int) int { return a + b },
				"sub": func(a, b int) int { return a - b },
				"entry_with_ctx": func(entry Entry, ctx context.Context) *EntryWithCtx {
					return &EntryWithCtx{Context: ctx, Entry: entry}
				},
			},
		},
	})

	r := mux.NewRouter()
	r.UseEncodedPath()
	r.HandleFunc("/", myHandler(topHandler))
	r.HandleFunc("/initialize", myHandler(initializeHandler)).Methods("GET")
	r.HandleFunc("/robots.txt", myHandler(robotsHandler))
	r.HandleFunc("/keyword", myHandler(keywordPostHandler)).Methods("POST")
	r.HandleFunc("/pprof/start", myHandler(profileStartHandler))
	r.HandleFunc("/pprof/stop", myHandler(profileStopHandler))
	r.HandleFunc("/pprof/memory", myHandler(dumpMemprofileHandler))
	r.HandleFunc("/cache/size", myHandler(cacheSizeHandler))
	r.HandleFunc("/cache/clear", myHandler(cacheClearHandler))

	l := r.PathPrefix("/login").Subrouter()
	l.Methods("GET").HandlerFunc(myHandler(loginHandler))
	l.Methods("POST").HandlerFunc(myHandler(loginPostHandler))
	r.HandleFunc("/logout", myHandler(logoutHandler))

	g := r.PathPrefix("/register").Subrouter()
	g.Methods("GET").HandlerFunc(myHandler(registerHandler))
	g.Methods("POST").HandlerFunc(myHandler(registerPostHandler))

	k := r.PathPrefix("/keyword/{keyword}").Subrouter()
	k.Methods("GET").HandlerFunc(myHandler(keywordByKeywordHandler))
	k.Methods("POST").HandlerFunc(myHandler(keywordByKeywordDeleteHandler))

	s := r.PathPrefix("/stars").Subrouter()
	s.Methods("GET").HandlerFunc(myHandler(starsHandler))
	s.Methods("POST").HandlerFunc(myHandler(starsPostHandler))

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public/")))
	log.Fatal(http.ListenAndServe(":5000", r))
}

func populateCache() {
	if cachePopulated {
		return
	}
	cachePopulated = true
	logdbg("populateCache: start")
	rows, err := db.Query("SELECT keyword FROM entry")
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	ks := make([]string, 0, 8000)
	for rows.Next() {
		var k string
		err := rows.Scan(&k)
		if err != nil {
			rows.Close()
			panic(k)
		}
		ks = append(ks, k)
	}
	rows.Close()
	for _, k := range ks {
		e, ok := loadEntry(k)
		if !ok {
			continue
		}
		htmlify(e)
	}
	logdbg("populateCache: done")
}

type EntryCache struct {
	m   map[string]*Entry
	mtx *sync.RWMutex
}

func NewEntryCache() *EntryCache {
	return &EntryCache{
		m:   make(map[string]*Entry),
		mtx: &sync.RWMutex{},
	}
}

func readEntry(keyword string) (*Entry, bool) {
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := &Entry{}
	e.Mutex = &sync.RWMutex{}
	err := row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return &Entry{}, false
	}
	return e, true
}

func loadEntry(keyword string) (*Entry, bool) {
	entryCache.mtx.RLock()
	e, ok := entryCache.m[keyword]
	entryCache.mtx.RUnlock()

	if ok {
		return e, true
	}

	entryCache.mtx.Lock()
	e, ok = entryCache.m[keyword]
	if ok {
		entryCache.mtx.Unlock()
		return e, ok
	}

	e, ok = readEntry(keyword)
	if !ok {
		entryCache.mtx.Unlock()
		return e, false
	}

	entryCache.m[keyword] = e
	entryCache.mtx.Unlock()
	return e, true
}

func dropEntry(keyword string) (bool, error) {
	entryCache.mtx.Lock()
	_, ok := entryCache.m[keyword]
	if !ok {
		entryCache.mtx.Unlock()
		return false, nil
	}
	delete(entryCache.m, keyword)
	_, err := db.Exec(`DELETE FROM entry WHERE keyword = ?`, keyword)
	entryCache.mtx.Unlock()
	go updateReplacers()
	return true, err
}

func insertOrUpdateEntry(userID int, keyword, description string) error {
	entryCache.mtx.Lock()
	now := time.Now()
	lastIDmux.Lock()
	res, err := db.Exec(`
		INSERT INTO entry (author_id, keyword, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		author_id = ?, keyword = ?, description = ?, updated_at = ?
	`, userID, keyword, description, now, now, userID, keyword, description, now)
	if err != nil {
		lastIDmux.Unlock()
		entryCache.mtx.Unlock()
		panic(err)
	}
	id64, err := res.LastInsertId()
	if err != nil {
		lastIDmux.Unlock()
		entryCache.mtx.Unlock()
		panic(err)
	}
	id := int(id64)
	if id > lastID {
		//logdbg("inserted")
		go updateReplacers()
		lastID = id
	} else {
		//logdbg("updated")
		e, ok := entryCache.m[keyword]
		if ok {
			e.Lock()
			e.AuthorID = userID
			e.Description = description
			e.Unlock()
		}
	}
	lastIDmux.Unlock()
	entryCache.mtx.Unlock()
	return err
}

type StarCache struct {
	m   map[string][]*Star
	mtx *sync.RWMutex
}

func NewStarCache() *StarCache {
	return &StarCache{
		m:   make(map[string][]*Star),
		mtx: &sync.RWMutex{},
	}
}

func readStars(keyword string) []*Star {
	starCache.mtx.RLock()
	stars, ok := starCache.m[keyword]
	starCache.mtx.RUnlock()
	if ok {
		return stars
	}
	starCache.mtx.Lock()
	stars, ok = starCache.m[keyword]
	if ok {
		starCache.mtx.Unlock()
		return stars
	}
	rows, err := stardb.Query(`SELECT * FROM star WHERE keyword = ?`, keyword)
	if err != nil && err != sql.ErrNoRows {
		starCache.mtx.Unlock()
		panic(err)
	}

	stars = make([]*Star, 0, 10)
	for rows.Next() {
		s := &Star{}
		err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
		if err != nil {
			starCache.mtx.Unlock()
			panic(err)
		}
		stars = append(stars, s)
	}
	rows.Close()
	starCache.m[keyword] = stars
	starCache.mtx.Unlock()
	return stars
}

func populateStarCache() {
	starCache.mtx.Lock()
	erows, err := db.Query(`SELECT keyword FROM entry`)
	if err != nil && err != sql.ErrNoRows {
		starCache.mtx.Unlock()
		panic(err)
	}
	ks := make([]string, 0, 8000)
	for erows.Next() {
		var k string
		err := erows.Scan(&k)
		if err != nil {
			starCache.mtx.Unlock()
			panic(err)
		}
		ks = append(ks, k)
	}
	erows.Close()

	starCache.m = make(map[string][]*Star)
	for _, k := range ks {
		rows, err := stardb.Query(`SELECT * FROM star WHERE keyword = ?`, k)
		if err != nil && err != sql.ErrNoRows {
			starCache.mtx.Unlock()
			panic(err)
		}

		stars := make([]*Star, 0, 10)
		for rows.Next() {
			s := &Star{}
			err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
			if err != nil {
				starCache.mtx.Unlock()
				panic(err)
			}
			stars = append(stars, s)
		}
		starCache.m[k] = stars
		rows.Close()
	}
	starCache.mtx.Unlock()
}

func storeStar(keyword, user string) {
	starCache.mtx.Lock()

	now := time.Now()
	res, err := stardb.Exec(`INSERT INTO star (keyword, user_name, created_at) VALUES (?, ?, ?)`, keyword, user, now)
	if err != nil {
		starCache.mtx.Unlock()
		panic(err)
	}
	id64, err := res.LastInsertId()
	if err != nil {
		starCache.mtx.Unlock()
		panic(err)
	}
	s := &Star{
		ID:        int(id64),
		Keyword:   keyword,
		UserName:  user,
		CreatedAt: now,
	}
	starCache.m[keyword] = append(starCache.m[keyword], s)

	starCache.mtx.Unlock()
}

func starsHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")

	stars := readStars(keyword)

	starre.JSON(w, http.StatusOK, map[string][]*Star{
		"result": stars,
	})
}

func starsPostHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")

	_, ok := loadEntry(keyword)
	if !ok {
		notFound(w)
		return
	}

	user := r.FormValue("user")
	storeStar(keyword, user)

	starre.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func starMain() {
	host := os.Getenv("ISUTAR_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUTAR_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUTAR_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUTAR_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUTAR_DB_PASSWORD")
	dbname := os.Getenv("ISUTAR_DB_NAME")
	if dbname == "" {
		dbname = "isutar"
	}

	stardb, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, dbname,
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	stardb.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	stardb.Exec("SET NAMES utf8mb4")

	starre = render.New(render.Options{Directory: "dummy"})
}

func refreshCacheForTop() {
	rows, err := db.Query(
		"SELECT keyword FROM entry ORDER BY updated_at DESC LIMIT 10",
	)
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	ks := make([]string, 0, 10)
	for rows.Next() {
		var k string
		err := rows.Scan(&k)
		if err != nil {
			rows.Close()
			panic(err)
		}
		ks = append(ks, k)
	}
	rows.Close()
	for _, k := range ks {
		e, ok := loadEntry(k)
		if !ok {
			continue
		}
		htmlify(e)
	}
}
