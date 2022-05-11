package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type M = map[string]interface{}

type Project struct {
	ID    string
	Slug  string
	Pages []M
}

var databasesLock = &sync.RWMutex{}
var databases = map[string]*sql.DB{}

var projectsLock = &sync.RWMutex{}
var projects = map[string]*Project{}

func main() {
	projects[""] = &Project{ID: "1", Pages: []M{
		M{"name": "404", "content": appCode}}}
	log.Println("Starting on port 8080")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(handler)))
}

func handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("panic: ", err)
			log.Println(string(debug.Stack()))
		}
	}()

	db := dbInstance("1")
	projectSlug := ""
	projectsLock.RLock()
	project, ok := projects[projectSlug]
	projectsLock.RUnlock()
	if !ok {
		matchingProjects, err := dbQuery(db,
			"select * projects where slug = ?", projectSlug)
		check(err)
		if len(matchingProjects) != 1 {
			w.WriteHeader(404)
			w.Write([]byte(`Project Not Found`))
			return
		}
		project := &Project{
			ID:   matchingProjects[0]["id"].(string),
			Slug: matchingProjects[0]["slug"].(string),
		}
		pages, err := dbQuery(db, "select * from pages where project_id = ?", project.ID)
		check(err)
		project.Pages = pages
		projectsLock.Lock()
		projects[projectSlug] = project
		projectsLock.Unlock()
	}

	currentPath := r.URL.Path[1:]
	found := false
	rt := NewRuntime(project.ID, project.Pages, r, w)
	execute := func(page M) {
		t := templateToCode(page["content"].(string))
		_, err := rt.runtime.RunScript(page["name"].(string), t)
		if err != nil {
			if err.Error() == "request end" {
				return
			}
			w.WriteHeader(500)
			fmt.Fprintf(w, "Error executing page: %v\n%s", err, t)
			return
		}
	}
	for _, page := range project.Pages {
		pathRegexp := pagePathToRegexp(page["name"].(string))
		if pathRegexp.MatchString(currentPath) {
			values := matchNamed(pathRegexp, currentPath)
			for k, v := range values {
				r.URL.Query().Set(k, v)
			}
			execute(page)
			found = true
			break
		}
	}

	if !found {
		for _, page := range project.Pages {
			if page["name"].(string) == "404" {
				execute(page)
				found = true
				break
			}
		}
	}
	if !found {
		rt.out = "Page Not Found"
	}

	if strings.HasSuffix(r.URL.Path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(r.URL.Path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else {
		w.Header().Set("Content-Type", "text/html")
	}
	w.Write([]byte(rt.out))
}

const appCode = `{%
dbQuery("create table if not exists users (id primary key, username, password)")
dbQuery("create table if not exists projects (id primary key, name, slug, user_id)")
dbQuery("create table if not exists pages (id primary key, name, content, project_id)")

function eq(a) { return function(b) { return a === b; }; }
function prop(a) { return function(b) { return b[a]; }; }
function comp(a, b) { return function(c) { return a(b(c)); }; }

projectId = "1"
pages = dbQuery("select * from pages where project_id = ? order by name", projectId)

id = param("page")
page = pages.find(comp(eq(id), prop("id")))

if (id === "new") {
  id = uuid()
  dbQuery("insert into pages values (?,?,?,?)", id, "newpage", "", projectId)
  redirect("/edit?page=" + id)
}

if (method === "POST") {
  page.name = param("name")
  page.content = param("content")
  dbQuery("update pages set name = ?, content = ? where id = ?", page.name, page.content, projectId)
}
%}
<form method="post">
{% pages.forEach(function(p) { %}
  <div><a href="/edit?page={{p.id}}">/{{p.name}}</a></div>
{% }) %}
<div><a href="?page=new">New Page</a></div>

{% if (page) { %}
  <div><button type="submit">Save</button></div>
  <div><input name="name" value="{{page.name}}" /></div>
  <div><textarea name="content">{{page.content}}</textarea></div>
{% } %}

<style>
html { font-family: monospace; font-size: 16px; }
input, textarea { width: 100%; margin: 8px 0; }
textarea { height: calc(100vh - 200px); }
</style>
</form>
`

type Runtime struct {
	projectId string
	pages     []M
	r         *http.Request
	w         http.ResponseWriter
	db        *sql.DB
	out       string
	runtime   *goja.Runtime
}

func NewRuntime(projectId string, pages []M, r *http.Request, w http.ResponseWriter) *Runtime {
	rt := goja.New()
	runtime := &Runtime{projectId: projectId, pages: pages, r: r, w: w, runtime: rt}
	runtime.db = dbInstance(projectId)
	global := rt.GlobalObject()
	global.Set("method", rt.ToValue(r.Method))
	global.Set("include", runtime.fnInclude)
	global.Set("uuid", runtime.fnUuid)
	global.Set("param", runtime.fnParam)
	global.Set("sanitize", runtime.fnSanitize)
	global.Set("write", runtime.fnWrite)
	global.Set("redirect", runtime.fnRedirect)
	global.Set("cookiesGet", runtime.fnCookiesGet)
	global.Set("cookiesSet", runtime.fnCookiesSet)
	global.Set("jsonParse", runtime.fnJsonParse)
	global.Set("jsonStringify", runtime.fnJsonStringify)
	global.Set("cryptoHash", runtime.fnCryptoHash)
	global.Set("cryptoCompare", runtime.fnCryptoCompare)
	global.Set("jwtSign", runtime.fnJwtSign)
	global.Set("jwtVerify", runtime.fnJwtVerify)
	global.Set("dbQuery", runtime.fnDbQuery)
	return runtime
}

func (r *Runtime) fnInclude(call goja.FunctionCall) goja.Value {
	name := call.Arguments[0].Export().(string)
	for _, p := range r.pages {
		if p["name"].(string) == name {
			_, err := r.runtime.RunScript(name, templateToCode(p["content"].(string)))
			if err != nil {
				r.runtime.Interrupt(err)
			}
			return goja.Undefined()
		}
	}
	r.runtime.Interrupt(errors.New("include: page '" + name + "' not found"))
	return goja.Undefined()
}

func (r *Runtime) fnUuid(call goja.FunctionCall) goja.Value {
	return r.runtime.ToValue(uuid())
}

func (r *Runtime) fnParam(call goja.FunctionCall) goja.Value {
	name := call.Arguments[0].Export().(string)
	return r.runtime.ToValue(r.r.FormValue(name))
}

func (r *Runtime) fnSanitize(call goja.FunctionCall) goja.Value {
	value := call.Arguments[0].Export().(string)
	return r.runtime.ToValue(template.HTMLEscapeString(value))
}

func (r *Runtime) fnWrite(call goja.FunctionCall) goja.Value {
	r.out += call.Arguments[0].Export().(string)
	return goja.Undefined()
}

func (r *Runtime) fnRedirect(call goja.FunctionCall) goja.Value {
	path := call.Arguments[0].Export().(string)
	http.Redirect(r.w, r.r, path, 302)
	panic(errors.New("request end"))
}

func (r *Runtime) fnCookiesGet(call goja.FunctionCall) goja.Value {
	name := call.Arguments[0].Export().(string)
	if cookie, err := r.r.Cookie(name); err == nil {
		return r.runtime.ToValue(cookie.Value)
	}
	return goja.Undefined()
}

func (r *Runtime) fnCookiesSet(call goja.FunctionCall) goja.Value {
	name := call.Arguments[0].Export().(string)
	value := call.Arguments[1].Export().(string)
	http.SetCookie(r.w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   2147483647,
	})
	return goja.Undefined()
}

func (r *Runtime) fnJsonParse(call goja.FunctionCall) goja.Value {
	t := call.Arguments[0].Export().(string)
	var v interface{}
	check(json.Unmarshal([]byte(t), &v))
	return r.runtime.ToValue(v)
}

func (r *Runtime) fnJsonStringify(call goja.FunctionCall) goja.Value {
	v := call.Arguments[0].Export()
	b, err := json.Marshal(v)
	check(err)
	return r.runtime.ToValue(string(b))
}

func (r *Runtime) fnCryptoHash(call goja.FunctionCall) goja.Value {
	password := call.Arguments[0].Export().(string)
	b, err := bcrypt.GenerateFromPassword([]byte(password), 13)
	check(err)
	return r.runtime.ToValue(string(b))
}

func (r *Runtime) fnCryptoCompare(call goja.FunctionCall) goja.Value {
	hash := []byte(call.Arguments[0].Export().(string))
	password := []byte(call.Arguments[1].Export().(string))
	return r.runtime.ToValue(bcrypt.CompareHashAndPassword(hash, password) == nil)
}

func (r *Runtime) fnJwtSign(call goja.FunctionCall) goja.Value {
	secret := call.Arguments[0].Export().(string)
	payloadRaw := call.Arguments[1].Export()
	mins := int(call.Arguments[2].ToInteger())
	t := time.Now().UTC().Add(time.Duration(mins) * time.Minute).Unix()
	payload, ok := payloadRaw.(map[string]interface{})
	if !ok {
		panic(errors.New("jwtSign: payload not a table"))
	}
	payload["exp"] = t
	payloadBs, err := json.Marshal(payload)
	check(err)
	message := stringToBase64(`{"alg":"HS256","typ":"JWT"}`) + "." + stringToBase64(string(payloadBs))
	sig := hmac.New(sha256.New, []byte(secret))
	sig.Write([]byte(message))
	token := message + "." + stringToBase64(string(sig.Sum(nil)))
	return r.runtime.ToValue(token)
}

func (r *Runtime) fnJwtVerify(call goja.FunctionCall) goja.Value {
	secret := call.Arguments[0].Export().(string)
	token := call.Arguments[1].Export().(string)
	if token == "" {
		panic(errors.New("jwtVerify: no token"))
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		panic(errors.New("jwtVerify: invalid token, need 3 parts"))
	}
	sig := hmac.New(sha256.New, []byte(secret))
	sig.Write([]byte(parts[0] + "." + parts[1]))
	signature := stringToBase64(string(sig.Sum(nil)))
	if parts[2] != signature {
		panic(errors.New("jwtVerify: signature mismatch"))
	}
	payload := M{}
	err := json.Unmarshal([]byte(base64ToString(parts[1])), &payload)
	if err != nil {
		panic(errors.New("jwtVerify: can't parse payload: " + err.Error()))
	}
	expiry := int64(payload["exp"].(float64))
	if time.Now().UTC().Unix() >= expiry {
		panic(errors.New("jwtVerify: expired"))
	}
	return r.runtime.ToValue(payload)
}

func (r *Runtime) fnDbQuery(call goja.FunctionCall) goja.Value {
	sql := call.Arguments[0].Export().(string)
	args := []interface{}{}
	for _, a := range call.Arguments[1:] {
		args = append(args, a.Export())
	}
	results, err := dbQuery(r.db, sql, args...)
	if err != nil {
		r.runtime.Interrupt(err)
		return goja.Undefined()
	}
	return r.runtime.ToValue(results)
}

func dbInstance(projectId string) *sql.DB {
	databasesLock.RLock()
	db, ok := databases[projectId]
	databasesLock.RUnlock()
	if ok {
		return db
	}
	db, err := sql.Open("sqlite3", "data/db/"+projectId+".sqlite3")
	check(err)
	db.SetMaxOpenConns(1)
	databasesLock.Lock()
	databases[projectId] = db
	databasesLock.Unlock()
	return db
}

func dbQuery(db *sql.DB, sql string, args ...interface{}) ([]M, error) {
	rows, err := db.Query(sql, args...)
	if err != nil {
		return nil, err
	}
	results := []M{}
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		for i := range values {
			values[i] = new(interface{})
		}
		err := rows.Scan(values...)
		if err != nil {
			return nil, err
		}

		result := M{}
		for i, column := range columns {
			result[column] = *(values[i].(*interface{}))
		}
		results = append(results, result)
	}
	return results, err
}

var pathReplaceRegexp = regexp.MustCompile("/:([a-zA-Z0-9]+)")

func pagePathToRegexp(path string) *regexp.Regexp {
	pathStrRegexp := pathReplaceRegexp.ReplaceAllStringFunc(path, func(s string) string {
		return "(?P<" + s[2:] + ">[^/]+)"
	})
	return regexp.MustCompile("^" + pathStrRegexp + "$")
}

func matchNamed(r *regexp.Regexp, str string) map[string]string {
	match := r.FindStringSubmatch(str)
	if len(match) == 0 {
		return nil
	}
	results := map[string]string{}
	for i, val := range match {
		if r.SubexpNames()[i] == "" {
			continue
		}
		results[r.SubexpNames()[i]] = val
	}
	return results
}

func templateToCode(t string) string {
	code := ""
	lastI := 0
	inCode := false
	inOutput := false
	for i, c := range t {
		if c == '{' && i > 0 && t[i-1] == '{' {
			code += `write(` + strconv.Quote(t[lastI:i-1]) + ")\n"
			lastI = i + 1
			inOutput = true
		}
		if inOutput && c == '}' && t[i-1] == '}' {
			code += `write(sanitize(` + t[lastI:i-1] + "))\n"
			lastI = i + 1
			inOutput = false
		}
		if c == '%' && i > 0 && t[i-1] == '{' {
			code += `write(` + strconv.Quote(t[lastI:i-1]) + ")\n"
			lastI = i + 1
			inCode = true
		}
		if inCode && c == '}' && t[i-1] == '%' {
			code += t[lastI:i-1] + "\n"
			lastI = i + 1
			inCode = false
		}
	}
	code += `write(` + strconv.Quote(t[lastI:]) + ")\n"
	return code
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

func stringToBase64(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

func base64ToString(b string) string {
	if s, err := base64.URLEncoding.DecodeString(b); err == nil {
		return string(s)
	}
	return ""
}
