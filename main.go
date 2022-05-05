package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite3", "data.sqlite3")
	check(err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS projects (id primary key, name, slug, user_id);`)
	check(err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pages (id primary key, name, project_id, content);`)
	check(err)
	_, err = db.Exec(`INSERT INTO projects VALUES ('1', 'Wocto', '', '1') ON CONFLICT (id) DO NOTHING;`)
	check(err)
	log.Println("Starting on port 8080")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(handler)))
}

func handler(w http.ResponseWriter, r *http.Request) {
	a, err := dbRows(`SELECT * FROM projects`)
	check(err)
	fmt.Fprintf(w, "Hello, %#v", a)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func dbRows(sql string, args ...interface{}) ([]map[string]interface{}, error) {
	r, err := db.Query(sql, args...)
	if err != nil {
		return nil, err
	}
	results := []map[string]interface{}{}
	columns, err := r.Columns()
	if err != nil {
		return nil, err
	}
	for r.Next() {
		values := make([]interface{}, len(columns))
		for i := range values {
			values[i] = new(interface{})
		}
		err := r.Scan(values...)
		if err != nil {
			return nil, err
		}

		result := map[string]interface{}{}
		for i, column := range columns {
			result[column] = *(values[i].(*interface{}))
		}
		results = append(results, result)
	}
	return results, r.Err()
}
