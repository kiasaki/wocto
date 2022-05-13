<title>Wocto</title>
<style>
:root { --primary: #8B5CF6; }
html, body { margin: 0; font-family: sans-serif; font-size: 16px; }
a { color: var(--primary); }
container { display: block; max-width: 960px; padding: 32px; margin: 0; }
container { background: #fff; min-height: 100vh; }
h1 { margin-top: 0; }
label { display: block; margin: 0 0 4px; }
input, textarea { margin: 0 0 16px; padding: 8px 12px; border: 2px solid #111; }
input, textarea { font-size: 16px; font-family: sans-serif; }
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
</style>
<container>
<%
dbQuery("create table if not exists users (id primary key, username, password)")
dbQuery("create table if not exists projects (id primary key, name, slug, domain, user_id)")
dbQuery("create table if not exists pages (id primary key, name, content, project_id)")

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
    user = dbQuery("select * from users where id = ?", payload.id)[0]
  }
}

if (!user) {
  if (method === "POST") {
    user = dbQuery("select * from users where username = ?", param("username"))[0]
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
      dbQuery("insert into users values (?,?,?)",
        id, param("username"), cryptoHash(param("password")))
      token = jwtSign(secret, {"id": id}, 7*24*60)
      cookiesSet("token", token)
      redirect(path)
    }
  }
%>
<form method="post" style="max-width:360px;margin:0;">
  <h1>Login / Signup</h1>
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
<hstack>
  <a href="/">Projects</a>
  <spacer></spacer>
  <a href="/profile"><? user.username ?></a>
</hstack>
<space></space>
<%
}

if (path === "/logout") {
  setCookie("token", "")
  redirect("/")
}

if (path === "/profile") {
  %><h1>Profile</h1>
  <a href="/logout">Logout</a>
<% }

if (path === "/projects-new") {
  id = uuid()
  dbQuery("insert into projects values (?,?,?,?,?)", id, "Untitled", id, "", user.id)
  redirect("/projects-view?id="+id)
}

if (path === "/projects-pages-new") {
  project = dbQuery("select * from projects where id = ? and user_id = ?",
    param("id"), user.id)[0]
  if (!project) { write("Page not found"); end() }
  id = uuid()
  dbQuery("insert into pages values (?,?,?,?)", id, "untitled", "", project.id)
  redirect("/projects-view?id="+project.id+"&page="+id)
}

if (path === "/projects-view") {
  project = dbQuery("select * from projects where id = ? and user_id = ?",
    param("id"), user.id)[0]
  if (!project) { write("Page not found"); end() }
  pages = dbQuery("select * from pages where project_id = ?", project.id)
  page = pages.find(comp(eq(param("page")), prop("id")))
  if (method === "POST") {
    page.name = param("name")
    page.content = param("content")
    dbQuery("update pages set name = ?, content = ? where id = ?", page.name, page.content, page.id)
    __clearCache(project.slug)
  }
  %>
  <h1><? project.name ?></h1>
  <hstack>
    <div style="flex: 0 0 280px">
      <div><a href="/projects-edit?id=<? project.id ?>">- Edit Project</a></div>
      <div><a href="/projects-pages-new?id=<? project.id ?>">+ New Page</a></div>
      <%pages.forEach(function(p) {%>
        <div>
          <a href="/projects-view?id=<? project.id ?>&page=<? p.id ?>">/<? p.name ?></a>
        </div>
      <%})%>
    </div>
    <spacer>
      <%if (page) {%>
      <form method="post">
        <hstack>
          <input type="text" name="name" value="<? page.name ?>" />
          <space></space>
          <div><button type="submit">Save</button></div>
        </hstack>
        <textarea name="content" rows="40" style="font-family:monospace;" autofocus><? page.content ?></textarea>
      </form>
      <%}%>
    </spacer>
  </hstack>
<% }

if (path === "/projects-edit") {
  project = dbQuery("select * from projects where id = ? and user_id = ?",
    param("id"), user.id)[0]
  if (!project) { write("Page not found"); end() }
  if (method === "POST") {
    project.name = param("name")
    project.slug = param("slug")
    project.domain = param("domain")
    if (project.name.length === 0 && project.slug.length === 0) {
      error = "Missing name or slug"
    } else if (dbQuery("select * from projects where (slug = ? || domain = ?) and id != ?",
      project.slug, project.domain, project.id).length > 0) {
      error = "Slug already taken"
    } else {
      dbQuery("update projects set name = ?, slug = ?, domain = ? where id = ?",
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
  projects = dbQuery("select * from projects where user_id = ?", user.id)
  %><h1>Projects</h1>
  <a href="/projects-new">+ New Project</a>
  <%projects.map(function(p) {%>
    <div><a href="/projects-view?id=<? p.id ?>"><? p.name ?></a></div>
  <%})%>
<% }
%>
</container>
