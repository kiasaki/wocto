package main

import (
	"bufio"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type Project struct {
	Slug   string
	Domain string
	Env    map[string]interface{}
}

var projectsLock = &sync.RWMutex{}
var projects = map[string]*Project{}

var db *sql.DB

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "repl" {
		startRepl()
		return
	}
	var err error
	db, err = sql.Open("sqlite3", "db.sqlite3")
	check(err)
	dbQuery("create table if not exists projects (slug, domain, env)")
	db.SetMaxOpenConns(1)
	log.Println("Starting on port " + env("PORT", "8080"))
	log.Fatal(http.ListenAndServe(":"+env("PORT", "8080"), http.HandlerFunc(handler)))
}

func startRepl() {
	env := map[string]interface{}{}
	eval(env, parse(stdlib))
	reader := bufio.NewReader(os.Stdin)
	repl := func() {
		for {
			fmt.Print("> ")
			line, _, err := reader.ReadLine()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(print(eval(env, parse(string(line)))))
		}
	}
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("error: %v\n", err)
			repl()
		}
	}()
	repl()
}

func handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("panic: %v\n", err)
			log.Println(string(debug.Stack()))
			w.WriteHeader(500)
			fmt.Fprintf(w, "error: %v\n", err)
		}
	}()
	projectSlug := ""
	projectsByDomain, err := dbQuery("select slug from projects where domain = ?", r.Host)
	check(err)
	if len(projectsByDomain) > 0 {
		projectSlug = projectsByDomain[0]["slug"].(string)
	}
	if projectSlug == "" {
		hostParts := strings.Split(r.Host, ".")
		if len(hostParts) >= 3 {
			projectSlug = hostParts[len(hostParts)-3]
		}
	}
	projectsLock.RLock()
	project, ok := projects[projectSlug]
	projectsLock.RUnlock()
	if !ok {
		matchingProjects, err := dbQuery("select * from projects where slug = ?", projectSlug)
		check(err)
		if len(matchingProjects) != 1 {
			dbQuery("insert into projects values (?,?,?)", projectSlug, "", "{}")
			matchingProjects = []map[string]interface{}{{"slug": projectSlug, "domain": "", "env": "{}"}}
		}
		var e map[string]interface{}
		check(json.Unmarshal([]byte(matchingProjects[0]["env"].(string)), &e))
		project = &Project{
			Slug:   matchingProjects[0]["slug"].(string),
			Domain: matchingProjects[0]["domain"].(string),
			Env:    e,
		}
		projectsLock.Lock()
		projects[projectSlug] = project
		projectsLock.Unlock()
	}

	if r.URL.Path == "/repl" {
		a := r.Header.Get("Authorization")
		aa := "Basic " + base64.StdEncoding.EncodeToString([]byte("op:"+env("SECRET", "herpderp")))
		if a != aa {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Login\"")
			w.WriteHeader(401)
			return
		}
		if r.Method == "POST" {
		}
		w.Write([]byte(replHtml))
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	check(err)
	r.Body.Close()
	valuesToMap := func(mm map[string][]string) map[string]string {
		m := map[string]string{}
		for k, v := range mm {
			m[k] = strings.Join(v, ",")
		}
		return m
	}
	r.ParseForm()
	headers := valuesToMap(r.Header)
	query := valuesToMap(r.URL.Query())
	form := valuesToMap(r.Form)
	request := map[string]interface{}{
		"method":  r.Method,
		"host":    r.Host,
		"path":    r.URL.Path,
		"headers": headers,
		"query":   query,
		"form":    form,
		"body":    string(body),
	}
	projectsLock.Lock()
	defer projectsLock.Unlock()
	response := eval(project.Env, []interface{}{"main", request})
	if response, ok := response.(map[string]interface{}); ok {
		if v, ok := response["headers"].(map[string]interface{}); ok {
			for k, v := range v {
				w.Header().Set(k, fmt.Sprintf("%v", v))
			}
		}
		if v, ok := response["status"].(int64); ok {
			w.WriteHeader(int(v))
		}
		if v, ok := response["body"].(string); ok {
			w.Write([]byte(v))
		} else {
			bs, err := json.Marshal(response["body"])
			check(err)
			w.Write(bs)
		}
	}
	dbQuery("update projects set env = ? where slug = ?", print(project.Env), project.Slug)
}

func dbQuery(sql string, args ...interface{}) ([]map[string]interface{}, error) {
	rows, err := db.Query(sql, args...)
	if err != nil {
		return nil, err
	}
	results := []map[string]interface{}{}
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

		result := map[string]interface{}{}
		for i, column := range columns {
			result[column] = *(values[i].(*interface{}))
		}
		results = append(results, result)
	}
	return results, err
}

func check(err interface{}) {
	if err != nil {
		panic(err)
	}
}

func env(name, alt string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return alt
}

func uuid() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	check(err)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// lang

func parse(s string) interface{} {
	symbolRunes := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+*/-_!=<>"
	pos := -1
	i := []interface{}{}
	a := []int{}
	lastAPos := 0
	next := func() byte {
		pos++
		if pos >= len(s) {
			return 0
		}
		return s[pos]
	}
	for {
		start := pos + 1
		switch c := next(); {
		case c == 0:
			if len(a) > 0 {
				panic(fmt.Sprintf("unclosed parens starting at position %d", lastAPos))
			}
			if len(i) == 0 {
				return nil
			}
			if len(i) == 1 {
				return i[0]
			}
			return []interface{}{append([]interface{}{"fn", nil}, i...)}
		case strings.ContainsRune(" \t\n\r", rune(c)):
			// ignore
		case c == '(':
			lastAPos = pos
			a = append(a, len(i))
		case c == ')':
			if len(a) == 0 {
				panic(fmt.Sprintf("unexpected extra closing parens at position %d", pos))
			}
			start := a[len(a)-1]
			l := append([]interface{}{}, i[start:]...)
			if len(l) == 0 {
				i = append(i[0:start], nil)
			} else {
				i = append(i[0:start], l)
			}
			a = a[:len(a)-1]
		case (c >= '0' && c <= '9') || c == '-':
			for c = next(); c >= '0' && c <= '9'; c = next() {
			}
			n, err := strconv.ParseInt(s[start:pos], 10, 64)
			check(err)
			i = append(i, n)
			pos--
		case strings.ContainsRune(symbolRunes, rune(c)):
			for c = next(); strings.ContainsRune(symbolRunes, rune(c)); c = next() {
			}
			i = append(i, s[start:pos])
			pos--
		default:
			panic(fmt.Sprintf("unexpected character at position %d", pos))
		}
	}
}

func eval(env map[string]interface{}, a interface{}) interface{} {
	switch b := a.(type) {
	case nil:
		return a
	case int64:
		return a
	case string:
		if c, ok := envGet(env, b); ok {
			return c
		}
		panic(fmt.Sprintf("eval: no '%s' in env", b))
	case []interface{}:
		if bi, ok := b[0].(string); ok {
			switch bi {
			case "+":
				values := mustArgs("+", env, b[1:], "number", "number")
				return mustNumber(values[0]) + mustNumber(values[1])
			case "-":
				values := mustArgs("-", env, b[1:], "number", "number")
				return mustNumber(values[0]) - mustNumber(values[1])
			case "quote":
				return b[1]
			case "def":
				values := mustArgs("def", env, b[2:], "string")
				env[mustString(b[1])] = values[0]
				return values[0]
			case "fn":
				mustList(b[1])
				return append([]interface{}{env}, b[1:]...)
			case "cond":
				for _, c := range b[1:] {
					cc := mustList(c)
					if eval(env, cc[0]) != nil {
						return eval(env, cc[1])
					}
				}
				return nil
			case "eq":
				values := mustArgs("eq", env, b[1:])
				if print(values[0]) == print(values[1]) {
					return "t"
				}
				return nil
			case "type":
				v := eval(env, b[1])
				switch v.(type) {
				case nil:
					return "list"
				case int64:
					return "number"
				case string:
					return "symbol"
				case []interface{}:
					return "list"
				case map[string]interface{}:
					return "env"
				}
			case "list":
				return mustArgs("list", env, b[1:])
			case "concat":
				values := mustArgs("concat", env, b[1:])
				d := []interface{}{}
				for _, v := range values {
					if vv, ok := v.([]interface{}); ok {
						d = append(d, vv...)
					} else {
						d = append(d, v)
					}
				}
				return d
			case "nth":
				values := mustArgs("nth", env, b[1:], "list", "number")
				l := mustList(values[0])
				n := int(mustNumber(values[1]))
				if n >= len(l) {
					if len(values) >= 3 {
						return values[2]
					} else {
						return nil
					}
				}
				return l[n]
			default:
			}
		}
		fnRaw := eval(env, b[0])
		fn, ok := fnRaw.([]interface{})
		if !ok {
			panic(fmt.Sprintf("eval: call to non fn: %v", fnRaw))
		}
		fnDefEnv, ok := fn[0].(map[string]interface{})
		if !ok {
			panic(fmt.Sprintf("eval: call to non fn (env): %v", fn))
		}
		argNames, ok := fn[1].([]interface{})
		if fn[1] != nil && !ok {
			panic(fmt.Sprintf("eval: call to non fn (args): %v", fn))
		}
		fnEnv := map[string]interface{}{"*up*": fnDefEnv}
		args := []interface{}{}
		for _, c := range b[1:] {
			args = append(args, eval(env, c))
		}
		if argNames == nil {
			fnEnv["args"] = args
		} else {
			for i, a := range argNames {
				b := mustString(a)
				fnEnv[b] = args[i]
			}
		}
		var d interface{}
		for _, e := range fn[2:] {
			d = eval(fnEnv, e)
		}
		return d
	default:
		panic(fmt.Sprintf("eval: unknown value type: %T %v", a, a))
	}
}

func print(a interface{}) string {
	switch b := a.(type) {
	case nil:
		return "()"
	case int64:
		return fmt.Sprintf("%d", b)
	case string:
		return b
	case []interface{}:
		cs := []string{}
		for _, c := range b {
			cs = append(cs, print(c))
		}
		return "(" + strings.Join(cs, " ") + ")"
	case map[string]interface{}:
		return fmt.Sprintf("<env %p>", b)
	default:
		panic(fmt.Sprintf("print: unknown value type: %v", a))
	}
}

func envGet(env map[string]interface{}, name string) (interface{}, bool) {
	if a, ok := env[name]; ok {
		return a, true
	}
	if p, ok := env["*up*"]; ok {
		if pp, ok := p.(map[string]interface{}); ok {
			return envGet(pp, name)
		}
	}
	return nil, false
}

func mustNumber(a interface{}) int64 {
	if b, ok := a.(int64); ok {
		return b
	}
	panic(fmt.Sprintf("expected number got '%v'", a))
}

func mustString(a interface{}) string {
	if b, ok := a.(string); ok {
		return b
	}
	panic(fmt.Sprintf("expected string got '%v'", a))
}

func mustList(a interface{}) []interface{} {
	if a == nil {
		return nil
	}
	if b, ok := a.([]interface{}); ok {
		return b
	}
	panic(fmt.Sprintf("expected list got '%v'", a))
}

func mustArgs(name string, env map[string]interface{}, args []interface{}, argTypes ...string) []interface{} {
	values := []interface{}{}
	for _, a := range args {
		values = append(values, eval(env, a))
	}
	for i, at := range argTypes {
		if at == "number" {
			if _, ok := values[i].(int64); !ok {
				panic(fmt.Sprintf("%s: expected arg %d to be %s, got: %v", name, i+1, at, values[i]))
			}
		}
		if at == "list" {
			if _, ok := values[i].([]interface{}); !ok {
				panic(fmt.Sprintf("%s: expected arg %d to be %s, got: %v", name, i+1, at, values[i]))
			}
		}
	}
	return values
}

const stdlib = `
(def t (quote t))
(def nil ())

(def car (fn (a) (nth 0 a)))
(def cdr (fn (a) (slice 1 0 a)))
(def cons (fn (a b) (concat a b)))

`

const replHtml = `
<!doctype html>
<meta charset=utf8>
<title>repl</title>
<link rel="stylesheet" href="https://unpkg.com/@datavis-tech/codemirror-6-prerelease@5.0.0/codemirror.next/legacy-modes/style/codemirror.css">
<script src="https://unpkg.com/@datavis-tech/codemirror-6-prerelease@5.0.0/dist/codemirror.js"></script>
<style>
body { margin: 0; }
.codemirror { height: 100vh; overflow: auto; }
.codemirror-matching-bracket { background: rgba(0,200,0,0.33); }
.codemirror-nonmatching-bracket { background: rgba(0,0,200,0.33); }
</style>
<div id=editor></div>
<script>
  let {
    EditorState,
    EditorView,
    keymap,
    history,
    redo,
    redoSelection,
    undo,
    undoSelection,
    lineNumbers,
    baseKeymap,
    indentSelection,
    legacyMode,
    legacyModes: { javascript },
    matchBrackets,
    specialChars,
    multipleSelections
  } = CodeMirror;
  let mode = legacyMode({mode: javascript({indentUnit: 2}, {})})
  let isMac = /Mac/.test(navigator.platform)
  let state = EditorState.create({doc: "", extensions: [
    lineNumbers(),
    history(),
    specialChars(),
    multipleSelections(),
    mode,
    matchBrackets(),
    keymap({
      "Mod-z": undo,
      "Mod-Shift-z": redo,
      "Mod-u": view => undoSelection(view) || true,
      [isMac ? "Mod-Shift-u" : "Alt-u"]: redoSelection,
      "Ctrl-y": isMac ? undefined : redo,
      "Shift-Tab": indentSelection
    }),
    keymap(baseKeymap),
  ]})
  let view = new EditorView({state})
  document.querySelector("#editor").appendChild(view.dom)
</script>
`
