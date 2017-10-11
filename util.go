package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	_ "os/signal"
	"runtime/debug"
	"strings"
)

var (
	DEBUG    = true
	progname string
)

func init() {
	log.SetFlags(0) // debug log
	arg0 := os.Args[0]
	progname = arg0[strings.LastIndex(arg0, "/")+1:]
}

func logdbg(format string, args ...interface{}) {
	if DEBUG {
		log.Printf(format, args...)
	}
}

func prepareHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			baseUrl, _ = url.Parse("http://" + h)
		} else {
			baseUrl, _ = url.Parse("http://" + r.Host)
		}
		fn(w, r)
	}
}

func myHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Fprintf(os.Stderr, "%+v", err)
				debug.PrintStack()
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		prepareHandler(fn)(w, r)
	}
}

func getProgName() string {
	return progname
}

func pathURIEscape(s string) string {
	return (&url.URL{Path: s}).String()
}

func pathURIUnescape(s string) (string, error) {
	res, err := url.Parse(s)
	if err != nil {
		logdbg("failed to url.Parse(%s): %v", s, err)
	}
	return res.Path, err
}

func notFound(w http.ResponseWriter) {
	code := http.StatusNotFound
	http.Error(w, http.StatusText(code), code)
}

func badRequest(w http.ResponseWriter) {
	code := http.StatusBadRequest
	http.Error(w, http.StatusText(code), code)
}

func forbidden(w http.ResponseWriter) {
	code := http.StatusForbidden
	http.Error(w, http.StatusText(code), code)
}

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}
