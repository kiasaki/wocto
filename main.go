package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
)

func main() {
	log.Println("Starting on port 8080")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(handler)))
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}
