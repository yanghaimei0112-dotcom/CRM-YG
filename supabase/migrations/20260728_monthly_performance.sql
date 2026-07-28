-- 首页团队目标进度榜：手工填报的月度业绩数据
-- 业务员可填报/修改自己的当月数据，管理员可代填任何人；全团队可读（激励榜公开）
create table if not exists public.monthly_performance (
  user_id uuid not null references auth.users(id) on delete cascade,
  month date not null,
  amount numeric(12,2) not null default 0,
  new_deals integer not null default 0,
  updated_by uuid,
  updated_at timestamptz not null default now(),
  primary key (user_id, month)
);

alter table public.monthly_performance enable row level security;

create policy mp_read on public.monthly_performance
  for select to authenticated using (true);

create policy mp_insert on public.monthly_performance
  for insert to authenticated
  with check (user_id = auth.uid() or public.is_admin());

create policy mp_update on public.monthly_performance
  for update to authenticated
  using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());

-- 聚合函数扩展：加入手工填报字段与 user_id（返回类型变化，需先删后建）
drop function if exists public.monthly_team_stats();

create function public.monthly_team_stats()
returns table(owner_name text, new_customers integer, visit_count integer, amount numeric, new_deals integer, user_id uuid)
language sql stable security definer
set search_path = public
as $$
  with ms as (select date_trunc('month', now())::date as s)
  select o.name as owner_name,
         coalesce(c.cnt, 0)::integer as new_customers,
         coalesce(v.cnt, 0)::integer as visit_count,
         coalesce(m.amount, 0) as amount,
         coalesce(m.new_deals, 0)::integer as new_deals,
         o.id as user_id
  from (select id, name from profiles where name is not null and name <> '') o
  left join (select owner_name, count(*) as cnt from customers, ms where create_date >= ms.s group by owner_name) c
    on c.owner_name = o.name
  left join (select coalesce(p.name, v.owner) as owner_name, count(*) as cnt
             from visits v left join profiles p on p.id = v.created_by, ms
             where v.visit_date >= ms.s
             group by coalesce(p.name, v.owner)) v
    on v.owner_name = o.name
  left join (select mp.user_id, mp.amount, mp.new_deals from public.monthly_performance mp, ms where mp.month = ms.s) m
    on m.user_id = o.id;
$$;

revoke all on function public.monthly_team_stats() from public, anon;
grant execute on function public.monthly_team_stats() to authenticated;
