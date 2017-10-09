package main

import (
	"context"
	"sync"
	"time"
)

type Entry struct {
	ID          int // const
	AuthorID    int
	Keyword     string // const
	Description string
	UpdatedAt   time.Time
	CreatedAt   time.Time // const

	Html  string
	Stars []*Star

	Mutex       *sync.RWMutex
	HtmlVersion int64
}

func (e *Entry) RLock() {
	e.Mutex.RLock()
}

func (e *Entry) RUnlock() {
	e.Mutex.RUnlock()
}

func (e *Entry) Lock() {
	e.Mutex.Lock()
}

func (e *Entry) Unlock() {
	e.Mutex.Unlock()
}

func (e *Entry) Copy() Entry {
	e.RLock()
	ce := *e
	e.RUnlock()
	ce.Mutex = &sync.RWMutex{}
	return ce
}

type User struct {
	ID        int
	Name      string
	Salt      string
	Password  string
	CreatedAt time.Time
}

type Star struct {
	ID        int       `json:"id"`
	Keyword   string    `json:"keyword"`
	UserName  string    `json:"user_name"`
	CreatedAt time.Time `json:"created_at"`
}

type EntryWithCtx struct {
	Context context.Context
	Entry   Entry
}
