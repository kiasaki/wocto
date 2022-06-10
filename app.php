<title>Wocto</title>
<style>
:root { --primary: #8B5CF6; }
html, body { margin: 0; font-family: sans-serif; font-size: 16px; }
a { color: var(--primary); }
container { display: block; max-width: 960px; padding: 16px; margin: 0; }
container { background: #fff; min-height: 100vh; }
h1 { margin-top: 0; }
label { display: block; margin: 0 0 4px; }
input, textarea { margin: 0 0 16px; padding: 8px 12px; border: 1px solid #111; }
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
</style>
<container>
<%
dbQuery("create table if not exists users (id text primary key, username text, password text)")
dbQuery("create table if not exists projects (id text primary key, name text, slug text, domain text, user_id text)")
dbQuery("create table if not exists pages (id text primary key, name text, content text, project_id text)")

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
  <style>container { max-width: 100%; }</style>
  <hstack style="height: calc(100% - 70px);padding-bottom: 16px;">
    <div style="flex: 0 0 240px">
    <div><a href="/projects-edit?id=<? project.id ?>">- Edit <? project.name ?></a></div>
      <div><a href="/projects-pages-new?id=<? project.id ?>">+ New Page</a></div>
      <%pages.forEach(function(p) {%>
        <div>
          <a href="/projects-view?id=<? project.id ?>&page=<? p.id ?>">/<? p.name ?></a>
        </div>
      <%})%>
    </div>
    <spacer>
      <%if (page) {%>
      <form method="post" style="height:100%;margin:0;">
        <vstack style="height:100%">
          <hstack>
            <input type="text" name="name" value="<? page.name ?>" />
            <space></space>
            <div><button type="submit">Save</button></div>
          </hstack>
          <spacer>
            <textarea name="content" style="height:100%;font-family:monospace;white-space:nowrap;overflow:auto;"
              autofocus><? page.content ?></textarea>
          </spacer>
        </vstack>
      </form>
      <%}%>
    </spacer>
    <spacer style="margin-left:16px;">
      <iframe style="width:100%;height:100%;border:1px solid black;"
        src="http://<? project.slug ?>.atriumph.com/<? page ? page.name : '' ?>"></iframe>
    </spacer>
  </hstack>
  <script>
    window.addEventListener("keydown", function(e) {
      if (e.key == "Enter" && e.ctrlKey) {
        document.querySelector("form").submit();
      }
    });
    if (window.location.hostname.includes("atriumph.loc")) {
      let i = document.querySelector("iframe");
      i.src = i.src.replace("atriumph.com", "atriumph.loc:8080");
    }
  </script>
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
