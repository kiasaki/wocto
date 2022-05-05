package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"

	"github.com/Shopify/go-lua"
	_ "github.com/mattn/go-sqlite3"
)

type M = map[string]interface{}

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite3", "data.sqlite3")
	check(err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS data (id primary key, project_id, entity, data);`)
	check(err)
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS data_project_id ON data (project_id, entity);`)
	check(err)
	_, err = db.Exec(`INSERT INTO data VALUES ('1', '1', 'projects', '{"id":"1","name":"Wocto","slug":"","owner_id":"1"}') ON CONFLICT (id) DO NOTHING;`)
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
	projects, err := dbEntitiesWhere("1", "projects", "slug", "=", projectSlug, "", 0, 0)
	check(err)
	if len(projects) != 1 {
		w.WriteHeader(404)
		w.Write([]byte(`Project Not Found`))
		return
	}

	projectId := projects[0]["id"].(string)
	pages, err := dbEntitiesWhere("1", "pages", "project_id", "=", projectId, "", 0, 0)
	check(err)

	for _, page := range pages {
		if page["name"].(string) == r.URL.Path[1:] {
			l := luaNewState(projectId, r, w)
			t := templateToLua(page["content"].(string))
			err := lua.DoString(l, t)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(w, "Error executing page: %v\n%s", err, t)
				return
			}
			s, ok := l.ToString(-1)
			if ok {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(s))
			} else {
				fmt.Fprintf(w, "Error no content")
			}
			return
		}
	}

	w.Write([]byte(`Page Not Found`))
}

func handlerEdit(w http.ResponseWriter, r *http.Request) {
	// setup
	pages, err := dbEntitiesWhere("1", "pages", "project_id", "=", "1", "", 0, 0)
	check(err)

	id := r.URL.Query().Get("page")
	var page map[string]interface{}
	for _, p := range pages {
		if p["id"].(string) == id {
			page = p
		}
	}

	// updates
	if id == "new" {
		id := uuid()
		check(dbPut("1", "pages", M{
			"id":         id,
			"project_id": "1",
			"name":       "newpage",
			"content":    "",
		}))
		http.Redirect(w, r, "/iedit?page="+id, 302)
		return
	}

	if r.Method == "POST" {
		page["name"] = r.FormValue("name")
		page["content"] = r.FormValue("content")
		dbPut("1", "pages", page)
	}

	// render
	html := `<form method="post">`

	for _, page := range pages {
		html += fmt.Sprintf(`<div><a href="?page=%s">%s</a></div>`, page["id"], page["name"])
	}

	html += `<div><a href="?page=new">New Page</a></div>`

	if page != nil {
		html += fmt.Sprintf(`
  <div><input name="name" value="%s" /></div>
  <div><textarea name="content" rows="40">%s</textarea></div>
  <div><button type="submit">Save</button></div>
  <style>
  html { font-family: monospace; font-size: 16px; }
  input, textarea { width: 100%%; margin: 8px 0; }
  </style>
  </form>
  `, page["name"], page["content"])
	}

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

func dbEntity(projectId string, entityName string, id string) (M, error) {
	r, err := dbRows(`select * from data where project_id = ? and entity = ? and id = ?`,
		projectId, entityName, id)
	if len(r) > 1 {
		return r[0], err
	}
	return nil, err
}

func dbEntities(projectId string, entityName string) ([]M, error) {
	return dbRows(`select * from data where project_id = ? and entity = ?`, projectId, entityName)
}

func dbEntitiesWhere(projectId string, entityName string, whereField string, whereOp string, whereValue interface{}, orderBy string, limit, offset int) ([]M, error) {
	args := []interface{}{projectId, entityName}
	sql := `select * from data where project_id = ? and entity = ?`
	if whereField != "" {
		if !regexp.MustCompile("^[a-zA-Z0-9_]+$").MatchString(whereField) {
			return nil, errors.New("dbEntitiesWhere: whereField invalid: " + whereField)
		}
		if !regexp.MustCompile("^[=<>!]+$").MatchString(whereOp) {
			return nil, errors.New("dbEntitiesWhere: whereOp invalid: " + whereOp)
		}
		sql += fmt.Sprintf(" and json_extract(data, '%s') %s ?", "$."+whereField, whereOp)
		args = append(args, whereValue)
	}
	if orderBy != "" {
		dir := "asc"
		if orderBy[0] == '-' {
			dir = "desc"
			orderBy = orderBy[1:]
		}
		sql += " order by json_extract(data, ?) " + dir
		args = append(args, "$."+orderBy)
	}
	if limit > 0 {
		sql += " limit ?"
		args = append(args, limit)
	}
	if offset > 0 {
		sql += " offset ?"
		args = append(args, offset)
	}
	rows, err := dbRows(sql, args...)
	if err != nil {
		return nil, err
	}
	entities := []M{}
	for _, r := range rows {
		e := M{}
		err := json.Unmarshal([]byte(r["data"].(string)), &e)
		if err != nil {
			return nil, err
		}
		entities = append(entities, e)
	}
	return entities, nil
}

func dbPut(projectId string, entityName string, entity M) error {
	b, err := json.Marshal(entity)
	if err != nil {
		return err
	}
	return dbExec(`insert into data (id, project_id, entity, data) VALUES (?, ? ,?, ?) on conflict (id) do update set data = excluded.data`,
		entity["id"].(string), projectId, entityName, string(b))
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
	results := []M{}
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

		result := M{}
		for i, column := range columns {
			result[column] = *(values[i].(*interface{}))
		}
		results = append(results, result)
	}
	return results, r.Err()
}

func templateToLua(t string) string {
	code := `__html = ""
function _h(t)
  __html = __html .. tostring(t)
end
`

	lastI := 0
	inCode := false
	inOutput := false
	for i, c := range t {
		if c == '{' && i > 0 && t[i-1] == '{' {
			code += `_h(` + strconv.Quote(t[lastI:i-1]) + ")\n"
			lastI = i + 1
			inOutput = true
		}
		if inOutput && c == '}' && t[i-1] == '}' {
			code += `_h(` + t[lastI:i-1] + ")\n"
			lastI = i + 1
			inOutput = false
		}
		if c == '%' && i > 0 && t[i-1] == '{' {
			code += `_h(` + strconv.Quote(t[lastI:i-1]) + ")\n"
			lastI = i + 1
			inCode = true
		}
		if inCode && c == '}' && t[i-1] == '%' {
			code += t[lastI:i-1] + "\n"
			lastI = i + 1
			inCode = false
		}
	}
	code += `_h(` + strconv.Quote(t[lastI:]) + ")\n"

	code += "return __html"
	return code
}

func luaNewState(projectId string, r *http.Request, w http.ResponseWriter) *lua.State {
	l := lua.NewState()
	libs := []lua.RegistryFunction{
		{"_G", lua.BaseOpen},
		{"table", lua.TableOpen},
		{"string", lua.StringOpen},
		{"bit32", lua.Bit32Open},
		{"math", lua.MathOpen},
	}
	for _, lib := range libs {
		lua.Require(l, lib.Name, lib.Function, true)
		l.Pop(1)
	}

	l.Register("param", func(l *lua.State) int {
		name := lua.CheckString(l, 1)
		l.PushString(r.URL.Query().Get(name))
		return 1
	})
	return l
}
