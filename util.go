package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	_ "os/signal"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"time"
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
		debugHandler(fn)(w, r)
	}
}

func debugHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		f, err := ioutil.TempFile(os.TempDir(), progname+".pprof.")
		if err != nil {
			logdbg("%v", err)
			panic(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
		//defer f.Close()
		//
		//c := make(chan os.Signal, 1)
		//signal.Notify(c, os.Interrupt)
		//go func() {
		//	for sig := range c {
		//		log.Printf("captured %v, stopping profiler and exiting...", sig)
		//		pprof.StopCPUProfile()
		//		os.Exit(1)
		//	}
		//}()
		prepareHandler(fn)(w, r)
		d := time.Since(start)
		logdbg("%s %v", r.RequestURI, d)
	}
}

func pathURIEscape(s string) string {
	return (&url.URL{Path: s}).String()
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
