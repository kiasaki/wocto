dev:
	@which reflex >/dev/null || go install github.com/cespare/reflex@latest
	reflex -s go run main.go

run:
	go run main.go
