all: isuda exp

deps:
	go get github.com/go-sql-driver/mysql
	go get github.com/gorilla/mux
	go get github.com/gorilla/sessions
	go get github.com/Songmu/strrand
	go get github.com/unrolled/render

isuda: isuda.go type.go util.go
	go build -o isuda isuda.go type.go util.go

isutar: isutar.go type.go util.go
	go build -o isutar isutar.go type.go util.go

exp: exp.go
	go build -o exp exp.go

restart-isuda: isuda
	sudo systemctl restart isuda.go

restart-isutar: isutar
	sudo systemctl restart isutar.go

restart: restart-isuda

.PHONY: all deps restart restart-isuda restart-isutar
