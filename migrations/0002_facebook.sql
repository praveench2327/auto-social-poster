create table if not exists facebook_pages (
  id               serial primary key,
  user_id          text not null unique,
  page_id          text not null,
  page_name        text not null,
  access_token     text not null,
  user_token       text,
  token_expires_at timestamptz,
  mode             text not null default 'live',
  connected_at     timestamptz not null default now()
);

create table if not exists facebook_oauth_states (
  nonce      text primary key,
  user_id    text not null,
  expires_at timestamptz not null
);

create table if not exists facebook_posts (
  id               serial primary key,
  user_id          text not null,
  body             text not null,
  image_url        text,
  publish_at       timestamptz not null,
  status           text not null default 'pending',
  platform_post_id text,
  error            text,
  created_at       timestamptz not null default now(),
  posted_at        timestamptz
);

create index if not exists facebook_posts_user_id_idx on facebook_posts (user_id);
create index if not exists facebook_posts_due_idx on facebook_posts (status, publish_at);
