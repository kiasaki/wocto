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
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Shopify/go-lua"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
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
	defer func() {
		if err := recover(); err != nil {
			log.Println("panic: ", err)
		}
	}()

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
				if err.Error() == "request end" {
					return
				}
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
		html += fmt.Sprintf(`<div><a href="?page=%s">/%s</a></div>`, page["id"], page["name"])
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

func stringToBase64(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

func base64ToString(b string) string {
	if s, err := base64.URLEncoding.DecodeString(b); err == nil {
		return string(s)
	}
	return ""
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

	l.PushString(r.Method)
	l.SetGlobal("method")
	l.Register("uuid", func(l *lua.State) int {
		l.PushString(uuid())
		return 1
	})
	l.Register("param", func(l *lua.State) int {
		name := lua.CheckString(l, 1)
		l.PushString(r.URL.Query().Get(name))
		return 1
	})
	l.Register("redirect", func(l *lua.State) int {
		path := lua.CheckString(l, 1)
		http.Redirect(w, r, path, 302)
		panic(errors.New("request end"))
	})
	l.Register("cookiesGet", func(l *lua.State) int {
		name := lua.CheckString(l, 1)
		if cookie, err := r.Cookie(name); err == nil {
			l.PushString(cookie.Value)
		} else {
			l.PushNil()
		}
		return 1
	})
	l.Register("cookiesSet", func(l *lua.State) int {
		name := lua.CheckString(l, 1)
		value := lua.CheckString(l, 2)
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    value,
			HttpOnly: true,
			Path:     "/",
			MaxAge:   2147483647,
		})
		return 0
	})
	l.Register("jsonParse", func(l *lua.State) int {
		t := lua.CheckString(l, 1)
		var v interface{}
		check(json.Unmarshal([]byte(t), &v))
		pushAny(l, v)
		return 1
	})
	l.Register("jsonStringify", func(l *lua.State) int {
		v, err := pullValue(l, 1)
		check(err)
		b, err := json.Marshal(v)
		check(err)
		l.PushString(string(b))
		return 1
	})
	l.Register("cryptoHash", func(l *lua.State) int {
		password := lua.CheckString(l, 1)
		b, err := bcrypt.GenerateFromPassword([]byte(password), 13)
		check(err)
		l.PushString(string(b))
		return 1
	})
	l.Register("cryptoCompare", func(l *lua.State) int {
		hash := []byte(lua.CheckString(l, 1))
		password := []byte(lua.CheckString(l, 2))
		l.PushBoolean(bcrypt.CompareHashAndPassword(hash, password) == nil)
		return 1
	})
	l.Register("jwtSign", func(l *lua.State) int {
		secret := lua.CheckString(l, 1)
		payloadRaw := mustPullTable(l, 2)
		mins := lua.CheckInteger(l, 3)
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
		l.PushString(token)
		return 1
	})
	l.Register("jwtVerify", func(l *lua.State) int {
		secret := lua.CheckString(l, 1)
		token := lua.CheckString(l, 2)
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
		pushAny(l, payload)
		return 1
	})
	l.Register("dbWhere", func(l *lua.State) int {
		entity := lua.CheckString(l, 1)
		whereField := lua.CheckString(l, 2)
		whereOp := lua.CheckString(l, 3)
		whereValue, err := pullValue(l, 4)
		check(err)
		orderBy := lua.CheckString(l, 5)
		limit := lua.CheckInteger(l, 6)
		offset := lua.CheckInteger(l, 7)
		rows, err := dbEntitiesWhere(projectId, entity, whereField, whereOp, whereValue, orderBy, limit, offset)
		check(err)
		pushAny(l, rows)
		return 1
	})
	l.Register("dbPut", func(l *lua.State) int {
		entity := lua.CheckString(l, 1)
		valueRaw, err := pullValue(l, 2)
		check(err)
		value, ok := valueRaw.(map[string]interface{})
		if !ok {
			panic(errors.New("dbPut: argument 2 is not a table/map"))
		}
		check(dbPut(projectId, entity, M(value)))
		return 0
	})
	return l
}

func pullTable(l *lua.State, idx int) (interface{}, error) {
	if !l.IsTable(idx) {
		return nil, fmt.Errorf("need a table at index %d, got %s", idx, lua.TypeNameOf(l, idx))
	}

	return pullTableRec(l, idx)
}

func mustPullTable(l *lua.State, idx int) interface{} {
	v, err := pullTable(l, idx)
	if err != nil {
		lua.Errorf(l, err.Error())
		panic("unreachable")
	}
	return v
}

func pullTableRec(l *lua.State, idx int) (interface{}, error) {
	if !l.CheckStack(2) {
		return nil, errors.New("pull table, stack exhausted")
	}

	idx = l.AbsIndex(idx)
	if isArray(l, idx) {
		return pullArrayRec(l, idx)
	}

	table := make(map[string]interface{})

	l.PushNil()
	for l.Next(idx) {
		// -1: value, -2: key, ..., idx: table
		key, ok := l.ToString(-2)
		if !ok {
			err := fmt.Errorf("key should be a string (%s)", lua.TypeNameOf(l, -2))
			l.Pop(2)
			return nil, err
		}

		value, err := pullValue(l, -1)
		if err != nil {
			l.Pop(2)
			return nil, err
		}

		table[key] = value

		l.Pop(1)
	}

	return table, nil
}

func pullValue(l *lua.State, idx int) (interface{}, error) {
	t := l.TypeOf(idx)
	switch t {
	case lua.TypeNil:
		return nil, nil
	case lua.TypeBoolean:
		return l.ToBoolean(idx), nil
	case lua.TypeString:
		return lua.CheckString(l, idx), nil
	case lua.TypeNumber:
		return lua.CheckNumber(l, idx), nil
	case lua.TypeTable:
		return pullTableRec(l, idx)
	default:
		err := fmt.Errorf("pull value, unsupported type %s", lua.TypeNameOf(l, idx))
		return nil, err
	}
}

func isArray(l *lua.State, idx int) bool {
	if !l.IsTable(idx) {
		return false
	}

	if !lua.MetaField(l, idx, "_is_array") {
		return false
	}
	defer l.Pop(1)

	return l.ToBoolean(-1)
}

func pullArrayRec(l *lua.State, idx int) (interface{}, error) {
	table := make([]interface{}, lua.LengthEx(l, idx))

	l.PushNil()
	for l.Next(idx) {
		k, ok := l.ToInteger(-2)
		if !ok {
			l.Pop(2)
			return nil, fmt.Errorf("pull array: expected numeric index, got '%s'", l.TypeOf(-2))
		}

		v, err := pullValue(l, -1)
		if err != nil {
			l.Pop(2)
			return nil, err
		}

		table[k-1] = v
		l.Pop(1)
	}

	return table, nil
}

func pushAny(l *lua.State, val interface{}) {
	switch val := val.(type) {
	case nil:
		l.PushNil()
	case bool:
		l.PushBoolean(val)
	case string:
		l.PushString(val)
	case uint8:
		l.PushNumber(float64(val))
	case uint16:
		l.PushNumber(float64(val))
	case uint32:
		l.PushNumber(float64(val))
	case uint64:
		l.PushNumber(float64(val))
	case uint:
		l.PushNumber(float64(val))
	case int8:
		l.PushNumber(float64(val))
	case int16:
		l.PushNumber(float64(val))
	case int32:
		l.PushNumber(float64(val))
	case int64:
		l.PushNumber(float64(val))
	case int:
		l.PushNumber(float64(val))
	case float32:
		l.PushNumber(float64(val))
	case float64:
		l.PushNumber(val)
	case complex64:
		pushAny(l, []float32{real(val), imag(val)})
	case complex128:
		pushAny(l, []float64{real(val), imag(val)})
	default:
		forwardOnReflect(l, val)
	}
}

func forwardOnReflect(l *lua.State, val interface{}) {
	switch v := reflect.ValueOf(val); v.Kind() {
	case reflect.Array, reflect.Slice:
		recurseOnFuncSlice(l, func(i int) interface{} { return v.Index(i).Interface() }, v.Len())
	case reflect.Map:
		l.CreateTable(0, v.Len())
		for _, key := range v.MapKeys() {
			mapKey := key.Interface()
			mapVal := v.MapIndex(key).Interface()
			pushAny(l, mapKey)
			pushAny(l, mapVal)
			l.RawSet(-3)
		}
	default:
		lua.Errorf(l, fmt.Sprintf("contains unsupported type: %T", val))
		panic("unreachable")
	}
}

func recurseOnFuncSlice(l *lua.State, input func(int) interface{}, n int) {
	l.CreateTable(n, 0)
	l.NewTable()
	l.PushBoolean(true)
	l.SetField(-2, "_is_array")
	l.SetMetaTable(-2)
	for i := 0; i < n; i++ {
		pushAny(l, input(i))
		l.RawSetInt(-2, i+1)
	}
}
