"""Server-rendered HTML for the portal. Every value goes through h() (HTML escape).

No CDN and no external assets: CSS and JS are inline and carry the per-response
CSP nonce. Colours follow the browser's light/dark preference.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any
from urllib.parse import quote

from .auth import Identity

FINAL = {"success", "partial", "blocked", "failed", "needs_input", "rejected", "error", "interrupted"}


def h(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def u(v: str) -> str:
    return quote(str(v), safe="")


def ts(t: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""


CSS = """
:root{--bg:#f7f7f8;--fg:#1d1d20;--muted:#60606a;--card:#fff;--border:#dcdce1;--accent:#2f5fd0;--accent-fg:#fff;
--ok:#1d7a3a;--bad:#b42318;--warn:#a15c00;--code:#f0f0f3;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#141417;--fg:#e8e8ec;--muted:#a0a0aa;--card:#1d1d22;--border:#34343c;
--accent:#7aa2ff;--accent-fg:#0b1020;--ok:#5fd38a;--bad:#ff7b72;--warn:#f0b35a;--code:#26262d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;gap:4px 16px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--card)}
header .brand{font-weight:600}header nav{display:flex;flex-wrap:wrap;gap:4px 14px}header nav a{color:var(--fg);text-decoration:none}
header nav a.on{color:var(--accent);font-weight:600}header .me{margin-left:auto;color:var(--muted);display:flex;gap:8px;align-items:center}
main{max-width:1100px;margin:0 auto;padding:16px}a{color:var(--accent)}h1{font-size:1.35rem;margin:.2rem 0 1rem}h2{font-size:1.1rem;margin:1.4rem 0 .5rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin:0 0 12px}
.muted{color:var(--muted)}.badge{display:inline-block;padding:1px 8px;border-radius:999px;border:1px solid var(--border);font-size:.82rem;white-space:nowrap}
.b-ok{color:var(--ok);border-color:var(--ok)}.b-bad{color:var(--bad);border-color:var(--bad)}.b-warn{color:var(--warn);border-color:var(--warn)}
.count{background:var(--bad);color:#fff;border-radius:999px;padding:0 6px;font-size:.75rem;margin-left:3px}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
.scroll{overflow-x:auto}pre{background:var(--code);padding:8px 10px;border-radius:6px;overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-word;font-size:.85rem}
input[type=text],input[type=password],textarea,select{width:100%;padding:7px 9px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
textarea{min-height:70px}label{display:block;font-weight:500;margin:.6rem 0 .2rem}
button,.btn{display:inline-block;padding:6px 14px;border-radius:6px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);font:inherit;cursor:pointer;text-decoration:none}
button.secondary,.btn.secondary{background:transparent;color:var(--accent)}button.danger{background:var(--bad);border-color:var(--bad);color:#fff}
button:disabled{opacity:.5;cursor:not-allowed}.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.msg{padding:8px 12px;border-radius:6px;margin:0 0 12px;border:1px solid var(--border)}
.msg.err{border-color:var(--bad);color:var(--bad)}.msg.ok{border-color:var(--ok);color:var(--ok)}
.bubble{border-radius:10px;padding:8px 12px;margin:6px 0;max-width:90%}.bubble.me{background:var(--code);margin-left:auto}.bubble.agent{border:1px solid var(--border)}
.shots{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}.shots img{width:100%;max-height:70vh;object-fit:contain;border:1px solid var(--border);border-radius:6px;background:#000}
.events{font:12px/1.4 ui-monospace,Consolas,monospace;max-height:360px;overflow:auto}.events div{border-bottom:1px solid var(--border);padding:2px 0;word-break:break-word}
.inline,.row form{display:inline}.narrow{max-width:420px}figure{margin:0}
.tk-frame{display:block;max-width:100%;cursor:crosshair;border:2px solid var(--warn);border-radius:6px;background:#000}
.tk-tools input[type=text]{width:auto;flex:1 1 220px}input.share-user{max-width:240px}.tk-tools select{width:auto}
@media (max-width:600px){main{padding:10px}header .me{margin-left:0}}
"""

JS = """
(function(){
  document.querySelectorAll('form[data-confirm]').forEach(function(f){
    f.addEventListener('submit',function(e){ if(!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault(); });
  });
  var poll=document.body.getAttribute('data-poll');
  if(poll){ var v=null; setInterval(function(){
    fetch(poll,{credentials:'same-origin'}).then(function(r){return r.ok?r.json():null}).then(function(j){
      if(!j) return; if(v===null){v=j.v;return;}
      if(j.v!==v){ var a=document.activeElement; var typing=a&&(a.tagName==='TEXTAREA'||a.tagName==='INPUT'||a.tagName==='SELECT')&&a.value;
        if(!typing) location.reload(); }
    }).catch(function(){});
  },2500); }
  var live=document.getElementById('live');
  if(live){
    var api=live.getAttribute('data-api'), after=0, shown=null;
    var shots=document.getElementById('shots'), ev=document.getElementById('events'), st=document.getElementById('live-status');
    function tick(){
      fetch(api+'?after='+after,{credentials:'same-origin'}).then(function(r){return r.ok?r.json():null}).then(function(j){
        if(!j) return; st.textContent=j.status||'';
        var key=j.screenshots.map(function(s){return s.name}).join('|');
        if(key!==shown){ shown=key; while(shots.firstChild) shots.removeChild(shots.firstChild);
          if(!j.screenshots.length){ var p=document.createElement('p'); p.className='muted'; p.textContent='No screenshots yet.'; shots.appendChild(p); }
          j.screenshots.slice().reverse().forEach(function(s){ var fig=document.createElement('figure');
            var a=document.createElement('a'); a.href=s.url; var img=document.createElement('img'); img.src=s.url; img.alt=s.name; a.appendChild(img);
            var cap=document.createElement('figcaption'); cap.className='muted'; cap.textContent=s.name; fig.appendChild(a); fig.appendChild(cap); shots.appendChild(fig); }); }
        j.events.forEach(function(e){ var d=document.createElement('div'); d.textContent=e.time+'  #'+e.seq+'  '+e.kind+'  '+e.detail; ev.appendChild(d); after=Math.max(after,e.seq); });
        while(ev.childNodes.length>300) ev.removeChild(ev.firstChild);
        if(j.events.length) ev.scrollTop=ev.scrollHeight;
      }).catch(function(){});
    }
    var holder=live.getAttribute('data-takeover');
    function tick2(){ fetch(api+'?after='+after,{credentials:'same-origin'}).then(function(r){return r.ok?r.json():null}).then(function(j){
      if(j && (j.takeover===null?'':j.takeover)!==holder) location.reload(); }).catch(function(){}); }
    tick(); setInterval(tick,1500); setInterval(tick2,3000);
  }
  var tk=document.getElementById('tk');
  if(tk){
    var img=document.getElementById('tk-frame'), msg=document.getElementById('tk-msg'), base=tk.getAttribute('data-frame');
    var input=tk.getAttribute('data-input'), every=parseInt(tk.getAttribute('data-interval')||'1000',10);
    var csrf=document.querySelector('meta[name=csrf]').getAttribute('content'), busy=false, last=null;
    function refresh(){ if(busy) return; busy=true; var n=new Image();
      n.onload=function(){ img.src=n.src; busy=false; }; n.onerror=function(){ busy=false; msg.textContent='Screen not available.'; };
      n.src=base+'?t='+Date.now(); }
    refresh(); setInterval(refresh, Math.max(300, every));
    function send(fields){ var body=new URLSearchParams(fields); body.set('csrf',csrf);
      return fetch(input,{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()})
        .then(function(r){return r.json().then(function(j){ msg.textContent=(j.ok?'Sent: ':'Not sent: ')+(j.message||j.error||''); setTimeout(refresh,250); });})
        .catch(function(){ msg.textContent='Could not reach the portal.'; }); }
    function point(e){ var r=img.getBoundingClientRect(); var sx=img.naturalWidth/r.width, sy=img.naturalHeight/r.height;
      return {x:Math.round((e.clientX-r.left)*sx), y:Math.round((e.clientY-r.top)*sy)}; }
    var down=null, dragged=false;
    img.addEventListener('dragstart',function(e){ e.preventDefault(); });
    img.addEventListener('mousedown',function(e){ if(e.button===0){ down=point(e); dragged=false; } });
    img.addEventListener('mouseup',function(e){ if(e.button!==0||!down) return; var p=point(e), s=down; down=null;
      if(Math.abs(p.x-s.x)+Math.abs(p.y-s.y)>6){ dragged=true; last=p;
        send({action:'drag',x:s.x,y:s.y,x2:p.x,y2:p.y,modifiers:document.getElementById('tk-mods').value}); } });
    img.addEventListener('click',function(e){ if(dragged){ dragged=false; return; } var p=point(e); last=p; var mode=document.getElementById('tk-mode').value;
      send({action:mode,x:p.x,y:p.y,modifiers:document.getElementById('tk-mods').value}); });
    img.addEventListener('contextmenu',function(e){ e.preventDefault(); var p=point(e); last=p; send({action:'right_click',x:p.x,y:p.y}); });
    img.addEventListener('wheel',function(e){ e.preventDefault(); var p=point(e); send({action:'scroll',x:p.x,y:p.y,direction:e.deltaY<0?'up':'down',amount:3}); },{passive:false});
    document.getElementById('tk-type').addEventListener('submit',function(e){ e.preventDefault(); var t=document.getElementById('tk-text');
      if(t.value){ send({action:'type',text:t.value}); t.value=''; } });
    document.getElementById('tk-key').addEventListener('submit',function(e){ e.preventDefault(); var k=document.getElementById('tk-keytext');
      if(k.value) send({action:'key',text:k.value}); });
    tk.querySelectorAll('button[data-key]').forEach(function(b){ b.addEventListener('click',function(){ send({action:'key',text:b.getAttribute('data-key')}); }); });
    var chord=document.getElementById('tk-chord');
    if(chord){ var names={Enter:'Return',Escape:'Escape',Backspace:'BackSpace',Delete:'Delete',Tab:'Tab',ArrowLeft:'Left',ArrowRight:'Right',ArrowUp:'Up',ArrowDown:'Down',
        Home:'Home',End:'End',PageUp:'Page_Up',PageDown:'Page_Down',Insert:'Insert',' ':'space'};
      chord.addEventListener('keydown',function(e){ if(['Control','Shift','Alt','Meta','OS'].indexOf(e.key)>=0) return; e.preventDefault();
        var k=names[e.key]||(/^F[0-9]{1,2}$/.test(e.key)?e.key:(e.key.length===1?e.key.toLowerCase():''));
        if(!k){ msg.textContent='That key cannot be sent.'; return; }
        var parts=[]; if(e.ctrlKey) parts.push('ctrl'); if(e.altKey) parts.push('alt'); if(e.shiftKey) parts.push('shift'); parts.push(k);
        var combo=parts.join('+'); chord.value=combo; send({action:'key',text:combo}); }); }
  }
})();
"""


def badge(status: str) -> str:
    s = (status or "").lower()
    cls = "b-ok" if s in ("success", "verified", "approved") else "b-bad" if s in ("failed", "blocked", "error", "rejected", "declined", "interrupted", "orphaned") else "b-warn" if s.startswith("waiting") or s in ("partial", "needs_input", "running", "pending", "draft", "timeout") else ""
    return f'<span class="badge {cls}">{h(status or "unknown")}</span>'


def layout(title: str, body: str, ident: Identity | None, csrf: str, nonce: str, active: str = "", counts: dict | None = None, poll: str = "", flash: str = "", flash_ok: bool = False) -> str:
    counts = counts or {}
    nav = ""
    me = ""
    if ident:
        items = [("chat", "/", "Task chat"), ("sessions", "/sessions", "Sessions"), ("approvals", "/approvals", "Approvals"), ("playbooks", "/playbooks", "Playbooks")]
        nav = "<nav>" + "".join(
            f'<a href="{href}" class="{"on" if key == active else ""}">{h(label)}' + (f'<span class="count">{int(counts[key])}</span>' if counts.get(key) else "") + "</a>" for key, href, label in items
        ) + "</nav>"
        me = f'<span class="me">{h(ident.name)} <span class="badge">{h(ident.role)}</span>'
        if ident.source not in ("trusted_header", "dev-no-auth"):
            me += f'<form method="post" action="/logout" class="inline"><input type="hidden" name="csrf" value="{h(csrf)}"><button class="secondary" type="submit">Sign out</button></form>'
        elif ident.source == "dev-no-auth":
            me += ' <span class="badge b-bad">no auth (dev)</span>'
        me += "</span>"
    msg = f'<div class="msg {"ok" if flash_ok else "err"}">{h(flash)}</div>' if flash else ""
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
        f"<meta name=csrf content=\"{h(csrf)}\"><title>{h(title)} - Analyst Agent</title><style nonce=\"{h(nonce)}\">{CSS}</style></head>"
        f"<body data-poll=\"{h(poll)}\"><header><span class=brand>Analyst Agent</span>{nav}{me}</header><main>{msg}{body}</main>"
        f"<script nonce=\"{h(nonce)}\">{JS}</script></body></html>"
    )


def csrf_input(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{h(csrf)}">'


# --------------------------------------------------------------------------- login


def login_page(mode: str, csrf: str, error: str = "") -> str:
    if mode == "oidc":
        body = '<div class="card"><h1>Sign in</h1><p>Sign in with your company account.</p><a class="btn" href="/login/oidc">Continue with SSO</a></div>'
    elif mode == "trusted_header":
        body = '<div class="card"><h1>Sign in</h1><p>This portal is behind the company SSO proxy. Open it through the proxy address; direct access is not accepted.</p></div>'
    else:
        body = (
            '<div class="card narrow"><h1>Sign in</h1><form method="post" action="/login">'
            + csrf_input(csrf)
            + '<label for=un>User name</label><input type=text id=un name=username autocomplete=username required autofocus>'
            '<label for=pw>Password</label><input type=password id=pw name=password autocomplete=current-password required>'
            '<p><button type=submit>Sign in</button></p></form></div>'
        )
    return body if not error else f'<div class="msg err">{h(error)}</div>' + body


# --------------------------------------------------------------------------- chat


def chat_page(ident: Identity, csrf: str, playbooks: list, sessions: list[dict], questions: dict, pending_by_session: dict) -> str:
    opts = '<option value="auto">Auto-match a playbook from the request</option><option value="none">No playbook: the planner builds the steps</option>'
    opts += "".join(f'<option value="{h(pb.name)}">{h(pb.name)} v{h(pb.version)} - {h(pb.description[:80])}</option>' for pb in playbooks)
    can_run = ident.can("analyst")
    form = (
        '<div class="card"><form method="post" action="/tasks">' + csrf_input(csrf)
        + '<label for=rq>What do you need?</label><textarea id=rq name=request required placeholder="e.g. Reconcile the October ERP and CRM exports"></textarea>'
        + f'<div class="grid"><div><label for=pb>Playbook</label><select id=pb name=playbook>{opts}</select></div>'
        + '<div><label for=pr>Parameters (one name=value per line)</label><textarea id=pr name=params placeholder="period=2026-10"></textarea></div></div>'
        + f'<p><button type=submit {"" if can_run else "disabled"}>Start task</button> <span class="muted">Plan and risky steps go to the approval inbox first.</span></p></form></div>'
    )
    threads = []
    for s in sessions[:30]:
        sid = s["id"]
        agent = [f'{badge(s.get("status", ""))} <a href="/sessions/{u(sid)}">session {h(sid)}</a> &middot; <a href="/sessions/{u(sid)}/live">live view</a>']
        if s.get("report"):
            agent.append(f' &middot; <a href="/sessions/{u(sid)}/report">what I checked</a>')
        steps = s.get("steps") or []
        if steps:
            done = sum(1 for x in steps if x["status"] == "verified")
            agent.append(f'<div class="muted">{done}/{len(steps)} steps verified</div>')
        if s.get("message"):
            agent.append(f"<div>{h(s['message'])}</div>")
        for q in s.get("questions") or []:
            agent.append(f'<div>Question: {h(q)}</div>')
        if pending_by_session.get(sid):
            agent.append(f'<div><a href="/approvals">{len(pending_by_session[sid])} approval(s) waiting in the inbox</a></div>')
        pq = questions.get(sid)
        if pq:
            may = ident.name == pq.asked_by or ident.can("admin")
            fields = "".join(f'<label for="q{i}-{h(sid)}">{h(q)}</label><input type=text id="q{i}-{h(sid)}" name="a{i}" required>' for i, q in enumerate(pq.questions))
            agent.append(
                f'<form method="post" action="/sessions/{u(sid)}/answer" class="card">{csrf_input(csrf)}<strong>The agent needs some information first</strong>{fields}'
                f'<p class="muted">Waiting until {h(ts(pq.deadline))}.</p><p><button type=submit {"" if may else "disabled"}>Send answers</button></p></form>'
            )
        threads.append(
            f'<div class="card"><div class="bubble me"><div class="muted">{h(s.get("user"))} &middot; {h(ts(s.get("started")))}'
            + (f' &middot; playbook {h(s.get("playbook"))}' if s.get("playbook") else "")
            + f'</div>{h(s.get("request"))}</div><div class="bubble agent">{"".join(agent)}</div></div>'
        )
    return "<h1>Task chat</h1>" + form + "<h2>Conversations</h2>" + ("".join(threads) or '<p class="muted">No tasks yet.</p>')


# --------------------------------------------------------------------------- sessions


def sessions_page(sessions: list[dict]) -> str:
    rows = "".join(
        f'<tr><td><a href="/sessions/{u(s["id"])}">{h(s["id"])}</a></td><td>{badge(s.get("status", ""))}</td><td>{h(s.get("user"))}</td>'
        f'<td>{h((s.get("request") or "")[:120])}</td><td>{h(s.get("playbook") or "")}</td><td>{h(ts(s.get("started")))}</td>'
        f'<td><a href="/sessions/{u(s["id"])}/live">live</a></td></tr>'
        for s in sessions
    )
    return "<h1>Sessions</h1><div class=\"card scroll\"><table><tr><th>Session</th><th>Status</th><th>User</th><th>Request</th><th>Playbook</th><th>Started</th><th></th></tr>" + (rows or '<tr><td colspan=7 class="muted">No sessions yet.</td></tr>') + "</table></div>"


def event_detail(e: dict) -> str:
    rest = {k: v for k, v in e.items() if k not in ("seq", "ts", "session", "user", "kind")}
    text = json.dumps(rest, default=str, ensure_ascii=False)
    return text if len(text) <= 400 else text[:400] + " ..."


def approval_card(item, ident: Identity, csrf: str, show_session: bool = True, may=None) -> str:
    """`may` is a bool (approve and reject alike) or ReviewRights (decide / approve / reason)."""
    r = item.req
    left = max(0, int(item.deadline - time.time()))
    may = ident.can("reviewer") if may is None else may
    if isinstance(may, bool):
        can_reject = can_approve = may
        reason = "" if may else ("your team does not review this playbook" if ident.can("reviewer") else "")
    else:
        can_reject, can_approve, reason = may.decide, may.approve, may.reason
        if not ident.can("reviewer"):
            reason = ""
    if not can_reject:
        why = '<span class="muted">Only reviewers and admins can decide' + (f" ({h(reason)})" if reason else "") + ".</span>"
    elif not can_approve:
        why = f'<span class="muted">You can reject but not approve this: {h(reason)}.</span>'
    else:
        why = ""
    back = "" if show_session else "<input type=hidden name=back value=session>"
    form = (
        f'<form method="post" action="/approvals/{u(item.id)}">{csrf_input(csrf)}{back}<label for="n-{h(item.id)}">Note (optional)</label>'
        f'<input type=text id="n-{h(item.id)}" name=note><p class="row"><button type=submit name=decision value=approve {"" if can_approve else "disabled"}>Approve</button>'
        f'<button type=submit name=decision value=reject class="danger" {"" if can_reject else "disabled"}>Reject</button>'
        + why
        + "</p></form>"
    )
    sess = f'<div>Session <a href="/sessions/{u(item.session_id)}">{h(item.session_id)}</a> &middot; started by {h(item.requested_by)}</div>' if show_session else ""
    return (
        f'<div class="card"><div class="row"><strong>{h(r.summary)}</strong>{badge("waiting")}</div>{sess}'
        f'<div class="muted">Step {h(r.step_id)} &middot; action <strong>{h(r.action_class)}</strong>'
        + (f' &middot; amount <strong>{h(r.amount)}</strong>' if getattr(r, "amount", None) not in (None, "") else "")
        + f' &middot; requested {h(ts(item.created_at))} &middot; '
        f'declined automatically in {left // 60} min {left % 60} s</div>'
        + ('<p class="msg ok">Carried over a portal restart: no run is waiting on this plan. Approving it resumes the session from its last checkpoint; '
           'the resumed run uses this approval only if its plan is exactly this one (otherwise it asks again).</p>' if getattr(item, "parked", False) else "")
        + (f"<pre>{h(r.preview)}</pre>" if r.preview else "")
        + form + "</div>"
    )


def share_card(sid: str, csrf: str, viewers: list[str], may_share: bool) -> str:
    rows = "".join(
        f'<li>{h(v)}' + (f' <form method="post" action="/sessions/{u(sid)}/share" class="inline">{csrf_input(csrf)}<input type=hidden name=op value=remove>'
                         f'<input type=hidden name=user value="{h(v)}"><button type=submit class="secondary">Remove</button></form>' if may_share else "") + "</li>"
        for v in viewers
    )
    form = (
        f'<form method="post" action="/sessions/{u(sid)}/share" class="row">{csrf_input(csrf)}<input type=hidden name=op value=add>'
        '<label for=share-user class="inline">Share with user</label><input type=text id=share-user name=user required class="share-user">'
        '<button type=submit>Share</button></form>'
        if may_share else ""
    )
    if not (rows or form):
        return ""
    return '<h2>Shared with</h2><div class="card">' + (f"<ul>{rows}</ul>" if rows else '<p class="muted">Not shared with anyone. Team members of the owner see it anyway.</p>') + form + "</div>"


def hold_label(info: dict) -> str:
    who = h((info.get("takeover") or {}).get("by") or "someone")
    if info.get("takeover_from_restart"):
        return f"held by {who} (from before restart)"
    if info.get("takeover_stale"):
        return f"held by {who} (the run is no longer running)"
    return f"taken over by {who}"


def session_page(info: dict, events: list[dict], ident: Identity, csrf: str, pending: list, question, may_decide=None, viewers: list[str] | None = None, may_share: bool = False, may_release: bool = False) -> str:
    sid = info["id"]
    final = info.get("status") in FINAL
    head = (
        f'<h1>Session {h(sid)}</h1><div class="card"><div class="row">{badge(info.get("status", ""))}'
        + (' <span class="badge b-bad">STOP requested</span>' if info.get("stopped") else "")
        + (f' <span class="badge b-warn">{hold_label(info)}</span>' if info.get("takeover") is not None else "")
        + f'</div><p>{h(info.get("request"))}</p><div class="muted">by {h(info.get("user"))} &middot; started {h(ts(info.get("started")))}'
        + (f' &middot; playbook {h(info.get("playbook"))}' if info.get("playbook") else "")
        + (f' &middot; params {h(json.dumps(info.get("params") or {}))}' if info.get("params") else "")
        + "</div>"
        + (f'<p>{h(info["message"])}</p>' if info.get("message") else "")
        + f'<p class="row"><a class="btn secondary" href="/sessions/{u(sid)}/live">Live view</a>'
        + (f'<a class="btn secondary" href="/sessions/{u(sid)}/report">What I checked</a>' if info.get("report") else "")
        + f'<a class="btn secondary" href="/sessions/{u(sid)}/file/events.jsonl">Raw audit log</a>'
        + f'<form method="post" action="/sessions/{u(sid)}/stop" data-confirm="Stop this session before its next action?">{csrf_input(csrf)}'
        + f'<button type=submit class="danger" {"disabled" if final or info.get("stopped") else ""}>Kill switch: stop</button></form>'
        + (
            f'<form method="post" action="/sessions/{u(sid)}/resume" data-confirm="Resume this session from its last checkpoint? Verified steps are skipped and the plan needs approval again.">{csrf_input(csrf)}'
            '<button type=submit>Resume from checkpoint</button></form>'
            if info.get("resumable") else
            f'<form method="post" action="/sessions/{u(sid)}/resume" data-confirm="Release the takeover hold and resume this session from its last checkpoint? The release is audited under your name.">{csrf_input(csrf)}'
            '<button type=submit>Release hold and resume</button></form>'
            if info.get("resumable_after_release") and may_release else ""
        )
        + "</p>"
        + (f'<p class="muted">This session is {hold_label(info)}. Resume needs the hold released first: '
           + ("you can release it (Release hold on the live view, or Release hold and resume here)." if may_release else
              f'{h((info.get("takeover") or {}).get("by") or "an admin")} or an admin must release it.') + "</p>"
           if info.get("takeover_stale") else "")
        + "</div>"
    )
    parts = [head]
    if info.get("orphaned"):
        parts.append(
            '<div class="card"><div class="row"><strong>Orphaned — run was interrupted</strong>' + badge("orphaned") + "</div>"
            '<p class="muted">The portal restarted while these were waiting. They were declined (never auto-approved).'
            + (" The session can be resumed from its last checkpoint." if info.get("resumable") else "")
            + "</p><ul>"
            + "".join(f'<li>{h(o["what"])} <span class="muted">({h(ts(o["ts"]))})</span></li>' for o in info["orphaned"])
            + "</ul></div>"
        )
    if pending:
        parts.append("<h2>Waiting for approval</h2>" + "".join(approval_card(p, ident, csrf, show_session=False, may=may_decide(p) if may_decide else None) for p in pending))
    if question:
        parts.append(f'<div class="card">The agent is waiting for answers. <a href="/">Answer in task chat</a>.</div>')
    if info.get("questions"):
        parts.append('<div class="card"><strong>Questions for you</strong><ul>' + "".join(f"<li>{h(q)}</li>" for q in info["questions"]) + "</ul></div>")
    rows = "".join(
        f'<tr><td>{i}</td><td>{h(s["id"])}</td><td>{h(s.get("intent"))}</td><td>{h(s.get("tier"))}</td><td>{badge(s.get("status", ""))}</td><td>{h(s.get("attempts", ""))}</td><td>{h(s.get("note", ""))}</td></tr>'
        for i, s in enumerate(info.get("steps") or [], 1)
    )
    parts.append('<h2>Steps</h2><div class="card scroll"><table><tr><th>#</th><th>Step</th><th>Intent</th><th>Tier</th><th>Status</th><th>Attempts</th><th>Notes</th></tr>' + (rows or '<tr><td colspan=7 class="muted">No plan yet.</td></tr>') + "</table></div>")
    if info.get("approvals"):
        parts.append('<h2>Approvals</h2><div class="card scroll"><table><tr><th>Step</th><th>Decision</th><th>By</th><th>Note</th><th>When</th></tr>' + "".join(
            f'<tr><td>{h(a["step"])}</td><td>{badge("approved" if a["approved"] else "declined")}</td><td>{h(a["by"])}</td><td>{h(a["note"])}</td><td>{h(ts(a["ts"]))}</td></tr>' for a in info["approvals"]
        ) + "</table></div>")
    outs = info.get("outputs") or []
    if outs:
        parts.append('<h2>Outputs</h2><div class="card"><ul>' + "".join(
            f'<li><a href="{"/out/" + quote(o["rel"]) if o["kind"] == "out" else f"/sessions/{u(sid)}/file/" + quote(o["rel"])}">{h(o["name"])}</a> <span class="muted">{int(o["size"])} bytes</span></li>' for o in outs
        ) + "</ul></div>")
    parts.append(share_card(sid, csrf, viewers or [], may_share))
    ev_rows = "".join(f'<tr><td>{h(e.get("seq"))}</td><td>{h(ts(e.get("ts")))}</td><td>{h(e.get("kind"))}</td><td><code>{h(event_detail(e))}</code></td></tr>' for e in events[-300:])
    parts.append(f'<h2>Audit log</h2><div class="card scroll"><table><tr><th>#</th><th>Time</th><th>Event</th><th>Detail</th></tr>{ev_rows or "<tr><td colspan=4 class=muted>No events yet.</td></tr>"}</table></div>')
    return "".join(parts)


def takeover_panel(sid: str, csrf: str, tk: dict) -> str:
    """Take over / hand back buttons and, for the person holding the takeover, the remote screen."""
    if not tk:
        return ""
    buttons = ""
    if tk.get("may"):
        buttons += (f'<form method="post" action="/sessions/{u(sid)}/takeover" data-confirm="Pause the agent and take over the desktop? Every input is checked against the window allowlist and audited under your name.">'
                    f'{csrf_input(csrf)}<button type=submit>Take over</button></form>')
    if tk.get("may_end"):
        buttons += (f'<form method="post" action="/sessions/{u(sid)}/handback" data-confirm="Hand the session back to the agent?">{csrf_input(csrf)}'
                    '<button type=submit class="secondary">Hand back</button></form>')
    if tk.get("may_release"):
        buttons += (f'<form method="post" action="/sessions/{u(sid)}/handback" data-confirm="Release this takeover hold? No run is waiting for it. The release is audited under your name.">{csrf_input(csrf)}'
                    '<button type=submit class="secondary">Release hold</button></form>')
        if tk.get("resumable_after_release"):
            buttons += (f'<form method="post" action="/sessions/{u(sid)}/resume" data-confirm="Release the hold and resume this session from its last checkpoint?">{csrf_input(csrf)}'
                        '<button type=submit>Release hold and resume</button></form>')
    if tk.get("active") and tk.get("stale"):
        who = h(tk.get("holder") or "someone")
        since = f" since {h(ts(tk.get('since')))}" if tk.get("since") else ""
        where = "from before restart" if tk.get("from_restart") else "the run is no longer running"
        state = (f'<strong>Held by {who} ({where}){since}.</strong> No agent is waiting for a hand-back, so there is no screen or input. '
                 + ("Release the hold to resume the session." if tk.get("may_release") else f"{who} or an admin can release it."))
    elif tk.get("active"):
        state = f'<strong>Paused: taken over by {h(tk.get("holder") or "someone")}.</strong> The agent waits until they hand back.'
    elif tk.get("may"):
        state = '<span class="muted">Take over pauses the agent before its next action so you can drive the desktop yourself.</span>'
    else:
        state = f'<span class="muted">{h(tk.get("why") or "")}</span>' if tk.get("why") else ""
    out = f'<div class="card"><div class="row">{state}{buttons}</div>'
    if tk.get("active") and tk.get("watch"):
        ok, why = tk.get("desktop") or (True, "")
        if not ok:
            out += f'<p class="msg err">{h(why)}</p>'
        else:
            dry = '<p class="msg err">Dry run: your input is logged but not sent (tiers.desktop_pixels.dry_run).</p>' if tk.get("dry_run") else ""
            ctl = (
                '<div class="row tk-tools"><label for=tk-mode class="inline">Click</label><select id=tk-mode><option value=click>left click</option><option value=double_click>double click</option>'
                '<option value=right_click>right click</option><option value=move>move only</option></select>'
                '<label for=tk-mods class="inline">with</label><select id=tk-mods><option value="">no modifier</option><option value=shift>shift</option><option value=ctrl>ctrl</option><option value=alt>alt</option></select>'
                '<span class="muted">Right-click, the wheel and dragging (press, move, release) on the image also work.</span></div>'
                '<form id=tk-type class="row tk-tools"><label for=tk-text class="inline">Type</label><input type=text id=tk-text autocomplete=off><button type=submit>Type</button></form>'
                '<form id=tk-key class="row tk-tools"><label for=tk-keytext class="inline">Key</label><input type=text id=tk-keytext placeholder="ctrl+s, Return, Tab" autocomplete=off><button type=submit>Press</button>'
                + "".join(f'<button type=button class="secondary" data-key="{k}">{k}</button>' for k in ("Return", "Tab", "Escape", "BackSpace"))
                + "</form>"
                '<div class="row tk-tools"><label for=tk-chord class="inline">Chord</label><input type=text id=tk-chord placeholder="click here, then press e.g. Ctrl+C" autocomplete=off readonly>'
                + "".join(f'<button type=button class="secondary" data-key="{k}">{k}</button>' for k in ("ctrl+c", "ctrl+v", "ctrl+x", "ctrl+a", "ctrl+z", "ctrl+s", "shift+Tab"))
                + "</div>"
                if tk.get("controls") else '<p class="muted">You are watching; only the person holding the takeover can send input.</p>'
            )
            out += (
                f'{dry}<div id="tk" data-frame="/api/sessions/{u(sid)}/takeover/frame" data-input="/api/sessions/{u(sid)}/takeover/input" data-interval="{int(tk.get("interval", 1000))}">'
                f'{ctl}<p id="tk-msg" class="muted" aria-live="polite"></p><img id="tk-frame" class="tk-frame" alt="Remote screen"></div>'
                '<p class="muted">Every input goes through the same window allowlist as the agent; refused input is not sent. All input is audited as human:&lt;you&gt;.</p>'
            )
    return out + "</div>"


def live_page(sid: str, csrf: str, stopped: bool, final: bool, tk: dict | None = None) -> str:
    tk = tk or {}
    return (
        f'<h1>Live view: {h(sid)}</h1><div class="card row"><span>Status: <strong id="live-status">...</strong></span>'
        f'<a href="/sessions/{u(sid)}">Session detail</a>'
        f'<form method="post" action="/sessions/{u(sid)}/stop" data-confirm="Stop this session before its next action?">{csrf_input(csrf)}'
        f'<button type=submit class="danger" {"disabled" if final or stopped else ""}>Kill switch: stop</button></form></div>'
        + takeover_panel(sid, csrf, tk)
        + f'<div id="live" data-api="/api/sessions/{u(sid)}/live" data-takeover="{h(tk.get("holder") or "") if tk.get("active") else ""}"></div>'
        '<h2>Latest screenshots</h2><div id="shots" class="shots"><p class="muted">Loading...</p></div>'
        '<h2>Audit events</h2><div class="card events" id="events"></div>'
        '<p class="muted">Refreshes every 1.5 seconds. Screenshots come from the session\'s audit folder.</p>'
    )


def report_page(sid: str, text: str) -> str:
    return f'<h1>What I checked: {h(sid)}</h1><p><a href="/sessions/{u(sid)}">Back to session</a> &middot; <a href="/sessions/{u(sid)}/file/report.md">report.md</a></p><div class="card"><pre>{h(text)}</pre></div>'


# --------------------------------------------------------------------------- approvals


def approvals_page(pending: list, history: list, ident: Identity, csrf: str, may_decide=None) -> str:
    body = "<h1>Approval inbox</h1>"
    body += "".join(approval_card(p, ident, csrf, may=may_decide(p) if may_decide else None) for p in pending) or '<p class="muted">Nothing is waiting for approval.</p>'
    if history:
        body += '<h2>Recent decisions</h2><div class="card scroll"><table><tr><th>When</th><th>Session</th><th>Step</th><th>Action</th><th>Decision</th><th>By</th><th>Note</th></tr>' + "".join(
            f'<tr><td>{h(ts(x.decision.decided_at))}</td><td><a href="/sessions/{u(x.session_id)}">{h(x.session_id)}</a></td><td>{h(x.req.step_id)}</td><td>{h(x.req.action_class)}</td>'
            f'<td>{badge("orphaned" if x.outcome == "orphaned" else "approved" if x.decision.approved else ("timeout" if x.decision.by == "timeout" else "declined"))}</td><td>{h(x.decision.by)}</td><td>{h(x.decision.note)}</td></tr>'
            for x in history if x.decision
        ) + "</table></div>"
    return body


# --------------------------------------------------------------------------- playbooks


def playbooks_page(entries: list) -> str:
    def row(e):
        pb = e.playbook
        name = pb.name if pb else e.id
        return (
            f'<tr><td><a href="/playbooks/view?id={u(e.id)}">{h(name)}</a></td><td>{h(pb.version if pb else "")}</td><td>{h(pb.owner if pb else "")}</td>'
            f'<td>{h(len(pb.steps) if pb else "")}</td><td>{h(", ".join(pb.parameters) if pb else "")}</td><td>{badge(e.status)}</td>'
            f'<td>{h(e.author)}</td><td class="muted">{h(e.id)}{(" - " + h(e.error[:120])) if e.error else ""}</td></tr>'
        )

    head = "<tr><th>Name</th><th>Version</th><th>Owner</th><th>Steps</th><th>Parameters</th><th>Status</th><th>Author</th><th>File</th></tr>"
    approved = [e for e in entries if not e.is_draft]
    drafts = [e for e in entries if e.is_draft and e.status != "rejected"]
    rejected = [e for e in entries if e.status == "rejected"]
    out = "<h1>Playbooks</h1><h2>In use</h2><div class=\"card scroll\"><table>" + head + ("".join(row(e) for e in approved) or '<tr><td colspan=8 class="muted">None.</td></tr>') + "</table></div>"
    out += "<h2>Drafts waiting for review</h2><div class=\"card scroll\"><table>" + head + ("".join(row(e) for e in drafts) or '<tr><td colspan=8 class="muted">No drafts.</td></tr>') + "</table></div>"
    if rejected:
        out += "<h2>Rejected</h2><div class=\"card scroll\"><table>" + head + "".join(row(e) for e in rejected) + "</table></div>"
    return out


def playbook_view(e, ident: Identity, csrf: str) -> str:
    pb = e.playbook
    raw = e.raw or {}
    meta = [("File", e.id), ("Status", e.status), ("Author", e.author), ("Reviewed by", raw.get("reviewed_by", "")), ("Review note", raw.get("review_note", ""))]
    if pb:
        meta = [("Name", pb.name), ("Version", pb.version), ("Owner", pb.owner), ("Backup owner", pb.backup_owner), ("Approver", pb.approver), ("Workflow", pb.workflow), ("Description", pb.description)] + meta
    body = f'<h1>Playbook {h(pb.name if pb else e.id)}</h1><p><a href="/playbooks">All playbooks</a></p>'
    if e.error:
        body += f'<div class="msg err">This file does not load: {h(e.error)}</div>'
    body += '<div class="card scroll"><table>' + "".join(f"<tr><th>{h(k)}</th><td>{badge(v) if k == 'Status' else h(v)}</td></tr>" for k, v in meta if v not in (None, "")) + "</table></div>"
    if e.reviewable and e.is_draft:
        may = ident.can("reviewer")
        body += (
            f'<div class="card"><strong>Review this draft</strong><form method="post" action="/playbooks/review">{csrf_input(csrf)}<input type=hidden name=id value="{h(e.id)}">'
            '<label for=rn>Review note</label><input type=text id=rn name=note>'
            f'<p class="row"><button type=submit name=decision value=approve {"" if may and pb else "disabled"}>Approve and publish</button>'
            f'<button type=submit name=decision value=reject class="danger" {"" if may else "disabled"}>Reject</button>'
            + ("" if may else '<span class="muted">Only reviewers and admins can review.</span>')
            + "</p></form></div>"
        )
    if pb:
        if pb.parameters:
            body += '<h2>Parameters</h2><div class="card scroll"><table><tr><th>Name</th><th>Required</th><th>Default</th><th>Description</th></tr>' + "".join(
                f'<tr><td>{h(k)}</td><td>{h("yes" if v.get("required", True) and "default" not in v else "no")}</td><td>{h(v.get("default", ""))}</td><td>{h(v.get("description", ""))}</td></tr>' for k, v in pb.parameters.items() if isinstance(v, dict)
            ) + "</table></div>"
        if pb.permissions:
            body += f'<h2>Permissions</h2><pre>{h(json.dumps(pb.permissions, indent=1))}</pre>'
        body += "<h2>Steps</h2>"
        for i, st in enumerate(pb.steps, 1):
            body += (
                f'<div class="card"><strong>{i}. {h(st.intent)}</strong><div class="muted">id {h(st.id)} &middot; tier {h(st.tier)} &middot; mode {h(st.mode)}'
                + (f' &middot; <span class="badge b-warn">approval {h(st.approval)}{(" / " + h(st.action_class)) if st.action_class else ""}</span>' if st.approval == "required" or st.action_class else "")
                + "</div>"
                + (f"<p>{h(st.instructions)}</p>" if st.instructions else "")
                + (f'<details><summary>Script ({h(st.script.get("kind", ""))})</summary><pre>{h(st.script.get("code") or json.dumps(st.script, indent=1))}</pre></details>' if st.script else "")
                + f'<div>Checks:</div><pre>{h(json.dumps(st.checks, indent=1))}</pre></div>'
            )
        if pb.final_checks:
            body += f'<h2>Final checks</h2><pre>{h(json.dumps(pb.final_checks, indent=1))}</pre>'
    body += f'<details class="card"><summary>Raw file</summary><pre>{h(json.dumps(raw, indent=1, ensure_ascii=False) if raw else "")}</pre></details>'
    return body


def error_page(code: int, message: str) -> str:
    return f'<h1>{int(code)}</h1><div class="card"><p>{h(message)}</p><p><a href="/">Back to the portal</a></p></div>'
