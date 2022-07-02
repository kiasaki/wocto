<title>Wocto</title>
<style>
:root { --primary: #8B5CF6; }
html, body { margin: 0; font-family: sans-serif; font-size: 16px; }
* { box-sizing: border-box; }
a { color: var(--primary); }
container { display: block; max-width: 960px; padding: 16px; margin: 0; }
container { background: #fff; min-height: 100vh; }
h1 { margin-top: 0; }
label { display: block; margin: 0 0 4px; }
input, textarea { margin: 0 0 16px; padding: 8px 12px; border: 1px solid #ccc; }
input, textarea { font-size: 16px; font-family: sans-serif; }
input:focus, textarea:focus { outline: 0; }
button, .button { display: inline-block; background: var(--primary); color: #fff; }
button, .button { padding: 12px 12px; border: 0; font-size: 16px; line-height: 15px; }
button:hover, .button:hover { opacity: 0.9; cursor: pointer; }
form input, form textarea, .wf { width: 100%; }
error { display: block; margin-bottom: 16px; }
error { padding: 16px; color: #B91C1C; background: #FEF2F2; }
pre { overflow-x: auto; }
hstack { display: flex; }
vstack { display: flex; flex-direction: column; }
spacer { display: block; flex: 1; }
space { display: inline-block; width: 16px; height: 16px; }
.hide { display: none; }
@media (max-width: 768px) {
  .hide-phone { display: none; }
  .block-phone { display: block; }
  .inline-phone { display: inline; }
}
.header { display: flex; background: #fff; line-height: 24px; position: fixed; top: 0; left: 0; right: 0; padding: 12px; border-bottom: 1px solid #ccc; z-index: 2; }
.header a { color: black; text-decoration: none; margin-right: 8px; }
.header a:hover { color: black; text-decoration: underline; }
.sidebar { width: 240px; background: #fafafa; position: fixed; left: 0; top: 49px; bottom: 0; border-right: 1px solid #ccc; padding: 16px; }
container { padding-left: 256px; }
@media (max-width: 768px) {
  .sidebar { display: none; }
  container { padding-left: 16px; }
}
</style>
<script>
const q = document.querySelector.bind(document);
const toggle = (x) => q(x).style.display = q(x).style.display == 'none' ? 'inherit' : 'none';
</script>
<container>
<%
function eq(a) { return function(b) { return a === b; }; }
function prop(a) { return function(b) { return b[a]; }; }
function comp(a, b) { return function(c) { return a(b(c)); }; }

secret = __secret || "keyboardcat"
error = ""
user = null
token = cookiesGet("token")
if (token) {
  payload = jwtVerify(secret, token)
  if (payload) {
    user = dbQuery("select * from users where id = $1", payload.id)[0]
  }
}

if (!user) {
  if (method === "POST") {
    user = dbQuery("select * from users where username = $1", param("username"))[0]
    if (user) {
      if (cryptoCompare(user.password, param("password"))) {
        token = jwtSign(secret, {"id": user.id}, 7*24*60)
        cookiesSet("token", token)
        redirect(path)
      } else {
        error = "Wrong password"
      }
    } else {
      id = uuid()
      dbQuery("insert into users values ($1,$2,$3)",
        id, param("username"), cryptoHash(param("password")))
      token = jwtSign(secret, {"id": id}, 7*24*60)
      cookiesSet("token", token)
      redirect(path)
    }
  }
%>
<form method="post" style="max-width:360px;margin:0;">
  <h1>Sign in</h1>
  <% if (error) { %><error><? error ?></error><% } %>
  <div>
    <label>Username</label>
    <input type="text" name="username" value="<? param("username") ?>" autofocus />
  </div>
  <div>
    <label>Password</label>
    <input type="password" name="password" />
  </div>
  <button type="submit" class="wf">Login / Signup</button>
</form>
<%
  end()
} else {
%>
<div class="header">
  <a class="hide inline-phone" onclick="toggle('.sidebar')">
    <svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" class="css-i6dzq1"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
  </a>
  <strong style="margin-right:8px;">W</strong>
  <a href="/">Projects</a>
  <a href="/profile">Profile</a>
</div>
<space style="height:48px;"></space>
<%
}

if (path === "/logout") {
  cookiesSet("token", "")
  redirect("/")
}

if (path === "/profile") {
  %><h1>Profile</h1>
  <a href="/logout">Logout</a>
<% }

if (path === "/projects-new") {
  id = uuid()
  dbQuery("insert into projects values ($1,$2,$3,$4,$5)", id, "Untitled", id, "", user.id)
  redirect("/projects-view?id="+id)
}

if (path === "/projects-pages-new") {
  project = dbQuery("select * from projects where id = $1 and user_id = $2",
    param("id"), user.id)[0]
  if (!project) { write("Page not found"); end() }
  id = uuid()
  dbQuery("insert into pages values ($1,$2,$3,$4)", id, "untitled", "", project.id)
  redirect("/projects-view?id="+project.id+"&page="+id)
}

if (path === "/projects-view") {
  project = dbQuery("select * from projects where id = $1 and user_id = $2",
    param("id"), user.id)[0]
  if (!project) { write("Page not found"); end() }
  pages = dbQuery("select * from pages where project_id = $1", project.id)
  page = pages.find(comp(eq(param("page")), prop("id")))
  if (method === "POST") {
    page.name = param("name")
    page.content = param("content")
    dbQuery("update pages set name = $1, content = $2 where id = $3", page.name, page.content, page.id)
    __clearCache(project.slug)
  }
  %>
  <div class="sidebar">
    <div><a href="/projects-edit?id=<? project.id ?>">- Edit <? project.name ?></a></div>
      <div><a href="/projects-pages-new?id=<? project.id ?>">+ New Page</a></div>
      <%pages.forEach(function(p) {%>
        <div>
          <a href="/projects-view?id=<? project.id ?>&page=<? p.id ?>">/<? p.name ?></a>
        </div>
      <%})%>
  </div>
  <%if (page) {%>
  <form method="post" style="height:calc(100% - 80px);margin:0;">
    <vstack style="height:100%">
      <div>
        <input type="text" name="name" value="<? page.name ?>" />
      </div>
      <spacer>
        <textarea name="content" id="editor" style="height:calc(100% - 120px);font-family:monospace;overflow:auto;"><? page.content ?></textarea>
      </spacer>
      <div><button type="submit">Save</button></div>
    </vstack>
  </form>
  <%} else {%>
  <p>Select a page to edit</p>
  <%}%>
<script>
window.addEventListener("keydown", function(e) {
  if (e.key == "Enter" && e.ctrlKey) {
    document.querySelector("form").submit();
  }
});
</script>
<!--
<link rel="stylesheet" href="https://unpkg.com/@datavis-tech/codemirror-6-prerelease@5.0.0/codemirror.next/legacy-modes/style/codemirror.css">
<script src="https://unpkg.com/@datavis-tech/codemirror-6-prerelease@5.0.0/dist/codemirror.js"></script>
<script>
let {
  EditorState, EditorView, keymap, history, redo,
  redoSelection, undo, undoSelection, lineNumbers,
  baseKeymap, indentSelection, legacyMode,
  legacyModes: { javascript },
  matchBrackets, specialChars, multipleSelections
} = CodeMirror;
let mode = legacyMode({mode: javascript({indentUnit: 2}, {})});
let isMac = /Mac/.test(navigator.platform);
let extensions = [
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
];
let textarea = document.querySelector("#editor");
let view = new EditorView({doc: textarea.value, extensions})
textarea.parentNode.insertBefore(view.dom, textarea)
textarea.style.display = "none"
if (textarea.form) textarea.form.addEventListener("submit", () => {
  textarea.value = view.state.doc.toString()
})
</script>
-->
<% }

if (path === "/projects-edit") {
  project = dbQuery("select * from projects where id = $1 and user_id = $2",
    param("id"), user.id)[0]
  if (!project) { write("Page not found"); end() }
  if (method === "POST") {
    project.name = param("name")
    project.slug = param("slug")
    project.domain = param("domain")
    if (project.name.length === 0 && project.slug.length === 0) {
      error = "Missing name or slug"
    } else if (dbQuery("select * from projects where (slug = $1 or domain = $2) and id != $3",
      project.slug, project.domain, project.id).length > 0) {
      error = "Slug already taken"
    } else {
      dbQuery("update projects set name = $1, slug = $2, domain = $3 where id = $4",
        project.name, project.slug, project.domain, project.id)
      __clearCache(project.slug)
      redirect("/projects-view?id=" + project.id)
    }
  }
%>
  <form method="post">
    <h1>Edit <? project.name ?></h1>
    <% if (error) { %><error><? error ?></error><% } %>
    <label>Name</label>
    <input type="text" name="name" value="<? project.name ?>" />
    <label>Slug</label>
    <input type="text" name="slug" value="<? project.slug ?>" />
    <label>Domain</label>
    <input type="text" name="domain" value="<? project.domain ?>" />
    <hstack>
      <spacer></spacer>
      <button type="submit">Save</button>
    </hstack>
  </form>
<%
}

if (path === "/") {
  projects = dbQuery("select * from projects where user_id = $1", user.id)
  %><h1>Projects</h1>
  <a href="/projects-new">+ New Project</a>
  <%projects.map(function(p) {%>
    <div><a href="/projects-view?id=<? p.id ?>"><? p.name ?></a></div>
  <%})%>
<% }
%>
</container>
