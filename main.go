package main

import (
	"crypto/rand"
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
	if r.URL.Path == "/iedit" {
		handlerEdit(w, r)
		return
	}

	projectSlug := ""
	projects, err := dbRows(`select * from projects where slug = ?`, projectSlug)
	check(err)
	if len(projects) != 1 {
		w.WriteHeader(404)
		w.Write([]byte(`Project Not Found`))
		return
	}

	projectId := projects[0]["id"].(string)
	pages, err := dbRows(`select * from pages where project_id = ?`, projectId)
	check(err)

	for _, page := range pages {
		if page["name"].(string) == r.URL.Path[1:] {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(page["content"].(string)))
			return
		}
	}

	w.Write([]byte(`Page Not Found`))
}

func handlerEdit(w http.ResponseWriter, r *http.Request) {
	// setup
	pages, err := dbRows(`SELECT * FROM pages where project_id = '1'`)
	check(err)

	id := r.URL.Query().Get("page")
	var page map[string]interface{}
	name := `test`
	content := "test\n\ncontent"
	for _, p := range pages {
		if p["id"].(string) == id {
			page = p
			name = p["name"].(string)
			content = p["content"].(string)
		}
	}

	// updates
	if id == "new" {
		id := uuid()
		check(dbExec(`INSERT INTO pages VALUES (?, ?, ?, ?)`, id, "newpage", "1", ""))
		http.Redirect(w, r, "/iedit?page="+id, 302)
		return
	}

	log.Println(r.Method, r.FormValue("name"))
	if r.Method == "POST" {
		name = r.FormValue("name")
		content = r.FormValue("content")
		page["name"] = name
		check(dbExec(`UPDATE pages SET name = ?, content = ? WHERE id = ?`, name, content, id))
	}

	// render
	html := `<form method="post">`

	for _, page := range pages {
		html += fmt.Sprintf(`<div><a href="?page=%s">%s</a></div>`, page["id"], page["name"])
	}

	html += `<div><a href="?page=new">New Page</a></div>`

	html += fmt.Sprintf(`
  <div><input name="name" value="%s" /></div>
  <div><textarea name="content" rows="40">%s</textarea></div>
  <div><button type="submit">Save</button></div>
  <style>
  html { font-family: monospace; font-size: 16px; }
  input, textarea { width: 100%%; margin: 8px 0; }
  </style>
  </form>
  `, name, content)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func uuid() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	check(err)
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func dbExec(sql string, args ...interface{}) error {
	_, err := db.Exec(sql, args...)
	return err
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
