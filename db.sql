create table if not exists users (id text primary key, username text, password text);
create table if not exists projects (id text primary key, name text, slug text, domain text, user_id text);
create table if not exists pages (id text primary key, name text, content text, project_id text);
