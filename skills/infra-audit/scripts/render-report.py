#!/usr/bin/env python3
"""Render the audit report from findings.json, then open it in a browser.

The JSON is the source of truth. Fix something, change that finding's status,
re-run this: the report is regenerated and the progress bar moves. Never edit
the HTML by hand, it is overwritten.

Usage: render-report.py <findings.json> [--open | --no-open]
"""
import json
import subprocess
import sys
from datetime import date
from html import escape
from pathlib import Path

SEV = {
    "P1": ("Critique", "p1"),
    "P2": ("Important", "p2"),
    "P3": ("Moyen", "p3"),
    "P4": ("Hygiène", "p4"),
}
STATUS = {
    "todo": ("À traiter", "st-todo"),
    "in_progress": ("En cours", "st-prog"),
    "fixed": ("Corrigé", "st-fixed"),
    "accepted": ("Risque accepté", "st-acc"),
    "blocked": ("Bloqué", "st-blocked"),
}

CSS = """
:root{--bg:#0f1310;--panel:#161c18;--panel2:#1c2420;--ink:#e8efe9;--dim:#93a89a;--line:#2a352e;
--ok:#7bc47f;--warn:#e0b252;--bad:#e0776b;--acc:#8fd3a8;
--crit:#e0776b;--high:#e09a52;--mid:#d9c26b;--low:#8fd3a8;--clean:#7bc47f;
--mono:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.65 -apple-system,"Inter",Segoe UI,Roboto,sans-serif;display:flex}
nav{position:sticky;top:0;height:100vh;width:250px;flex:0 0 250px;background:var(--panel);
border-right:1px solid var(--line);padding:26px 18px;overflow:auto}
nav h1{font-size:15px;margin:0 0 4px;letter-spacing:.3px}
nav .sub{color:var(--dim);font-size:12px;margin-bottom:22px}
nav .grp{color:var(--dim);font-size:10.5px;letter-spacing:1.2px;text-transform:uppercase;
margin:20px 0 7px;padding-left:10px}
nav a{display:flex;gap:8px;align-items:baseline;color:var(--dim);text-decoration:none;
padding:7px 10px;border-radius:7px;font-size:13.5px;border-left:2px solid transparent}
nav a:hover{background:var(--panel2);color:var(--ink)}
nav a.done .nm{text-decoration:line-through;opacity:.5}
nav a.crit{border-left-color:var(--bad)}
main{flex:1;padding:44px 56px;max-width:1080px}
h2{font-size:22px;margin:52px 0 14px;padding-bottom:9px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:0;color:var(--acc)}
p{color:#cfdad2}
.verdict{background:linear-gradient(135deg,#18251c,#141b17);border:1px solid var(--ok);
border-radius:14px;padding:26px 30px;margin-bottom:26px}
/* --- header card: one state per global exposure level --- */
.verdict{position:relative}
.verdict .lvlbar{position:absolute;left:0;top:0;bottom:0;width:5px;border-radius:14px 0 0 14px}
.verdict.lvl-crit{border-color:var(--crit);background:linear-gradient(135deg,#2a1a18,#161b18)}
.verdict.lvl-crit .lvlbar{background:var(--crit)}
.verdict.lvl-high{border-color:var(--high);background:linear-gradient(135deg,#271f17,#161b18)}
.verdict.lvl-high .lvlbar{background:var(--high)}
.verdict.lvl-mid{border-color:var(--mid);background:linear-gradient(135deg,#24221a,#161b18)}
.verdict.lvl-mid .lvlbar{background:var(--mid)}
.verdict.lvl-low{border-color:var(--low);background:linear-gradient(135deg,#1a2420,#161b18)}
.verdict.lvl-low .lvlbar{background:var(--low)}
.verdict.lvl-clean{border-color:var(--clean);background:linear-gradient(135deg,#18251c,#141b17)}
.verdict.lvl-clean .lvlbar{background:var(--clean)}
.verdict.lvl-crit .tag{background:var(--crit)}.verdict.lvl-high .tag{background:var(--high)}
.verdict.lvl-mid .tag{background:var(--mid)}.verdict.lvl-low .tag{background:var(--low)}
.verdict.lvl-clean .tag{background:var(--clean)}
.verdict .prog-line{color:var(--dim);font-size:13px;margin:10px 0 0;font-family:var(--mono)}
.verdict .residual{margin:14px 0 0;padding:10px 14px;border-radius:8px;background:#0d1210;
border-left:3px solid var(--warn);color:#cfdad2;font-size:13.5px}
.verdict .tag{display:inline-block;background:var(--ok);color:#0d150f;font-weight:700;
font-size:12px;letter-spacing:1.4px;padding:5px 12px;border-radius:20px}
.verdict.warn .tag{background:var(--warn)}.verdict.bad .tag{background:var(--bad)}
.verdict h2{border:0;margin:14px 0 8px;font-size:26px;padding:0}
.bar{height:8px;background:var(--panel2);border-radius:99px;overflow:hidden;margin:18px 0 0;display:flex}
.bar i{display:block;height:100%}
.bar i.f{background:var(--ok)}.bar i.a{background:var(--dim);opacity:.55}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin:20px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px}
.kpi .n{font:600 27px/1.1 var(--mono);color:var(--acc)}
.kpi .n.bad{color:var(--bad)}.kpi .n.warn{color:var(--warn)}.kpi .n.ok{color:var(--ok)}
.kpi .l{color:var(--dim);font-size:12px;margin-top:6px}
code,.m{font-family:var(--mono);font-size:12.5px;background:var(--panel2);padding:2px 6px;
border-radius:4px;color:#bfe6cd}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:13px 15px;
overflow-x:auto;font:12.5px/1.6 var(--mono);color:#bfe6cd;margin:0}
.pill{display:inline-block;font:600 11px/1 var(--mono);padding:4px 8px;border-radius:5px}
.p-ok{background:#1d3325;color:var(--ok)}.p-warn{background:#33291a;color:var(--warn)}
.p-bad{background:#33201d;color:var(--bad)}.p-n{background:#232b26;color:var(--dim)}
.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);
border-radius:9px;padding:18px 22px;margin:16px 0}
.card.s-P1{border-left-color:var(--bad)}.card.s-P2{border-left-color:var(--warn)}
.card.s-P3{border-left-color:var(--acc)}.card.s-P4{border-left-color:var(--dim)}
/* --- per-state block styling --- */
.card.st-todo{}                                   /* neutral: severity colour carries it */
.card.st-in_progress{border-left-color:var(--warn);background:linear-gradient(90deg,#1d2419,var(--panel) 55%)}
.card.st-in_progress h3::after{content:" ...";color:var(--warn)}
.card.st-blocked{border-left-color:var(--bad);background:linear-gradient(90deg,#241a19,var(--panel) 55%)}
.card.st-fixed{opacity:.62;border-left-color:var(--ok)}
.card.st-fixed h3{text-decoration:line-through;text-decoration-color:var(--dim)}
.card.st-accepted{opacity:.68;border-left-style:dashed;border-left-color:var(--dim)}
.sep{display:flex;align-items:center;gap:14px;margin:40px 0 6px;color:var(--dim);
font:600 12px/1 var(--mono);letter-spacing:1.6px;text-transform:uppercase}
.sep::before,.sep::after{content:"";flex:1;height:1px;background:var(--line)}
.navsep{margin:16px 0 6px;padding:0 10px;color:var(--dim);
font:600 10px/1 var(--mono);letter-spacing:1.4px;text-transform:uppercase}
.card.st-fixed pre,.card.st-accepted pre{opacity:.75}
.card.st-fixed:hover,.card.st-accepted:hover{opacity:1}
nav a.st-fixed .nm{text-decoration:line-through;opacity:.5}
nav a.st-accepted .nm{opacity:.55;font-style:italic}
nav a.st-in_progress{border-left-color:var(--warn)}
nav a.st-blocked{border-left-color:var(--bad)}
nav a.crit{border-left-color:var(--bad)}
.legend{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 18px;align-items:center}
.legend .l{color:var(--dim);font-size:11.5px;margin-right:4px}
.chead{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:4px}
.ord{font:700 12px/1.6 var(--mono);color:var(--dim)}
.chead .pill:last-child{margin-left:auto}
.cat{color:var(--dim);font-size:12px;margin-bottom:10px}
.lab{color:var(--dim);font-size:11px;letter-spacing:.7px;text-transform:uppercase;
font-weight:600;margin:15px 0 5px}
.box{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);
border-radius:9px;padding:16px 20px;margin:18px 0}
.box.w{border-left-color:var(--warn)}
ul{padding-left:20px}li{margin:6px 0;color:#cfdad2}
.cols{columns:2;column-gap:30px}.cols li{break-inside:avoid;font-size:13.5px}
@media(max-width:900px){.cols{columns:1}}
footer{color:var(--dim);font-size:12px;margin-top:60px;padding-top:18px;border-top:1px solid var(--line)}
button.copy{background:var(--acc);color:#0d150f;border:0;border-radius:9px;padding:11px 18px;
font-size:13.5px;font-weight:700;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.4)}
.copybar{position:fixed;right:24px;bottom:24px;z-index:10}
@media(max-width:860px){body{display:block}nav{display:none}main{padding:26px 20px 80px}}
"""


def block(label, body, pre=False):
    if not body:
        return ""
    inner = f"<pre>{escape(body)}</pre>" if pre else f"<p>{escape(body)}</p>"
    return f'<div class="lab">{escape(label)}</div>{inner}'


# A finding is live until it is fixed or knowingly accepted. "blocked" is
# still an exposure, so it counts as open everywhere.
ACTIVE = ("todo", "in_progress", "blocked")
SETTLED = ("fixed", "accepted")


def lint_plan(findings):
    """Warnings when the action list contradicts its own heading.

    The section is titled "de la plus urgente a la moins", so burying the worst
    open finding under lighter ones, or ranking settled history above live
    work, is a defect in the plan even when every rank is unique. This never
    rewrites `order`: the plan belongs to whoever wrote it.
    """
    sev_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    ordered = sorted(findings, key=lambda f: f.get("order", 999))
    active = [f for f in ordered if f.get("status") in ACTIVE]
    warnings = []

    if active:
        worst = min(sev_rank.get(f.get("severity", "P4"), 9) for f in active)
        first = active[0]
        if sev_rank.get(first.get("severity", "P4"), 9) > worst:
            worst_f = next(f for f in active
                           if sev_rank.get(f.get("severity", "P4"), 9) == worst)
            warnings.append(
                f"the worst open finding is {worst_f.get('id')} ({worst_f.get('severity')}) at "
                f"rank #{worst_f.get('order')}, but the list opens on {first.get('id')} "
                f"({first.get('severity')}). The action list is titled most-urgent-first: either "
                f"move it up, or say why in meta.order_note - it renders in the report.")

    # Settled findings interleaved with open ones used to be warned about here.
    # They are not any more: render() now sinks them to the bottom on its own,
    # so the author no longer has to keep `order` free of closed work.
    return warnings


def render(data, out_path):
    meta = data.get("meta", {})
    findings = list(data.get("findings", []))
    sev_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    # Settled work sinks to the bottom, whatever its rank: the plan is read for
    # what is left to do, and a fixed item sitting at #1 pushes live findings
    # off the first screen. Within each group `order` still decides, so the
    # settled block keeps the priority order it was closed in - the rank badge
    # keeps its original number rather than being renumbered, which is why the
    # open list can legitimately start at #2.
    findings.sort(key=lambda f: (0 if f.get("status") in ACTIVE else 1,
                                 f.get("order", 999),
                                 sev_rank.get(f.get("severity", "P4"), 9),
                                 str(f.get("id", ""))))

    total = len(findings)
    done = sum(1 for f in findings if f.get("status") == "fixed")
    acc = sum(1 for f in findings if f.get("status") == "accepted")
    left = total - done - acc
    open_p1 = sum(1 for f in findings if f.get("severity") == "P1"
                  and f.get("status") in ("todo", "in_progress", "blocked"))
    blocked = sum(1 for f in findings if f.get("status") == "blocked")
    prog = sum(1 for f in findings if f.get("status") == "in_progress")
    pct_f = round(100 * done / total) if total else 0
    pct_a = round(100 * acc / total) if total else 0

    # Global exposure level, derived from the severity of what is NOT fixed.
    # Deliberately independent of progress: 8 items closed out of 10 still reads
    # critical while a P1 stands. An ACCEPTED P1 never turns the header green
    # either - a knowingly retained risk is still a live exposure.
    worst_open = min((sev_rank.get(f.get("severity", "P4"), 9)
                      for f in findings if f.get("status") in ACTIVE), default=9)
    worst_acc = min((sev_rank.get(f.get("severity", "P4"), 9)
                     for f in findings if f.get("status") == "accepted"), default=9)
    worst = min(worst_open, worst_acc)
    driven_by_accepted = worst_acc < worst_open

    LEVELS = {
        0: ("lvl-crit", "EXPOSITION CRITIQUE",
            "Compromission possible en l'état"),
        1: ("lvl-high", "RISQUE ELEVE",
            "Surface d'attaque évitable, rien de critique"),
        2: ("lvl-mid", "RISQUE MODERE",
            "Rien n'est compromis, mais l'abus ne coûte rien à l'attaquant"),
        3: ("lvl-low", "RISQUE FAIBLE",
            "Il ne reste que de l'hygiène"),
        9: ("lvl-clean", "AUCUN RISQUE OUVERT",
            "Tout ce qui a été trouvé est traité"),
    }
    tone, tag, headline = LEVELS[worst]
    if driven_by_accepted and worst != 9:
        tag += " (ACCEPTE)"
        headline = "Le niveau est porté par un risque accepté, pas par un oubli"

    order_note = escape(str(meta.get("order_note", ""))) or (
        "Il ne suit pas toujours la gravité : quand la correction la plus grave est une "
        "migration, les réductions de surface rapides passent devant, parce qu'elles protègent "
        "plus tôt et sans risque de rupture.")

    residual = ""
    if driven_by_accepted and worst <= 1:
        residual = ("Un risque de gravité "
                    + ["P1", "P2", "P3", "P4"][worst]
                    + " a été accepté sciemment. C'est une décision, pas une correction : "
                    "l'exposition reste réelle et le niveau global la reflète.")

    sev_pill = {"P1": "p-bad", "P2": "p-warn", "P3": "p-n", "P4": "p-n"}
    st_pill = {"fixed": "p-ok", "in_progress": "p-warn", "blocked": "p-bad",
               "todo": "p-n", "accepted": "p-n"}

    nav, cards = [], []
    settled_started = False
    for f in findings:
        if not settled_started and f.get("status") in SETTLED:
            settled_started = True
            nav.append('<div class="navsep">Déjà traité</div>')
            cards.append('<div class="sep"><span>Déjà traité</span></div>')
        fid = escape(str(f.get("id", "")))
        sev = f.get("severity", "P4")
        sev_lab, _ = SEV.get(sev, SEV["P4"])
        st = f.get("status", "todo")
        st_lab, _ = STATUS.get(st, STATUS["todo"])
        settled = st in ("fixed", "accepted")
        crit = sev == "P1" and not settled
        nav.append(
            f'<a class="st-{st}{" crit" if crit else ""}" href="#{fid}">'
            f'<span class="pill {sev_pill.get(sev, "p-n")}">{sev}</span>'
            f'<span class="nm">{escape(f.get("title", ""))}</span></a>'
        )
        cards.append(f"""
<article class="card s-{sev} st-{st}" id="{fid}">
  <div class="chead">
    <span class="ord">#{f.get("order", "?")}</span>
    <span class="pill {sev_pill.get(sev, "p-n")}">{sev} {escape(sev_lab)}</span>
    <h3>{escape(f.get("title", ""))}</h3>
    <span class="pill {st_pill.get(st, "p-n")}">{escape(st_lab)}</span>
  </div>
  <div class="cat">{escape(f.get("category", ""))}</div>
  {block("Preuve", f.get("evidence", ""), pre=True)}
  {block("Pourquoi ça compte ici", f.get("impact", ""))}
  {block("Correction", f.get("correction", ""))}
  {block("Coût et risque de la correction", f.get("cost", ""))}
  {block("Contrainte à ne pas casser", f.get("constraint", ""))}
  {block("Suivi", f.get("notes", ""))}
</article>""")

    def ul(items):
        return "".join(f"<li>{escape(i)}</li>" for i in items)

    prompt = [f"Audit infra de {meta.get('target', '?')} du {meta.get('date', '?')}.",
              f"Avancement : {done}/{total} corrigés, {acc} acceptés, {open_p1} P1 ouverts.", ""]
    for f in findings:
        if f.get("status") in ("todo", "in_progress", "blocked"):
            prompt.append(f"{f.get('severity')} #{f.get('order')} {f.get('title')} "
                          f"[{f.get('status')}] -> {f.get('correction', '')}")
    prompt_js = json.dumps("\n".join(prompt))

    blocked_kpi = (f'<div class="kpi"><div class="n bad">{blocked}</div>'
                   f'<div class="l">bloquées</div></div>') if blocked else (
                  f'<div class="kpi"><div class="n warn">{prog}</div>'
                  f'<div class="l">en cours</div></div>') if prog else ""
    target = escape(str(meta.get("target", "")))
    html = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit infra - {target}</title>
<style>{CSS}</style></head><body>
<nav>
  <h1>Audit infrastructure</h1>
  <div class="sub">{target}<br>{escape(str(meta.get("date", "")))}</div>
  <div class="grp">Actions, par urgence</div>
  {"".join(nav)}
  <div class="grp">Contexte</div>
  <a href="#solide"><span class="nm">Déjà en place</span></a>
  <a href="#accepte"><span class="nm">Risques acceptés</span></a>
  <a href="#limites"><span class="nm">Méthode et limites</span></a>
</nav>
<main>
  <div class="verdict {tone}">
    <span class="lvlbar"></span>
    <span class="tag">{tag}</span>
    <h2>{headline}</h2>
    <p style="margin:0">{escape(str(meta.get("summary", "")))}</p>
    <div class="bar"><i class="f" style="width:{pct_f}%"></i><i class="a" style="width:{pct_a}%"></i></div>
    <p class="prog-line">avancement : {done}/{total} corrigées &middot; {acc} acceptées &middot; {left} restantes</p>
    {f'<p class="residual">{escape(residual)}</p>' if residual else ''}
  </div>

  <div class="grid">
    <div class="kpi"><div class="n ok">{done}</div><div class="l">corrigées</div></div>
    <div class="kpi"><div class="n {'warn' if left else 'ok'}">{left}</div><div class="l">restantes</div></div>
    <div class="kpi"><div class="n {'bad' if open_p1 else 'ok'}">{open_p1}</div><div class="l">critiques ouvertes</div></div>
    <div class="kpi"><div class="n">{acc}</div><div class="l">risques acceptés</div></div>
    {blocked_kpi}
  </div>

  <h2>Actions, de la plus urgente à la moins</h2>
  <div class="legend"><span class="l">États :</span>
    <span class="pill p-n">À traiter</span>
    <span class="pill p-warn">En cours</span>
    <span class="pill p-ok">Corrigé</span>
    <span class="pill p-n">Risque accepté</span>
    <span class="pill p-bad">Bloqué</span>
  </div>
  <div class="box w"><h4 style="margin:0 0 8px">Ordre d'exécution</h4>
  <p style="margin:0">{order_note}</p></div>
  {"".join(cards)}

  <h2 id="solide">Ce qui est déjà en place</h2>
  <ul class="cols">{ul(data.get("already_in_place", [])) or "<li>(non renseigné)</li>"}</ul>

  <h2 id="accepte">Risques identifiés et acceptés</h2>
  <ul>{ul(data.get("accepted_risks", [])) or "<li>(aucun)</li>"}</ul>

  <h2 id="limites">Méthode et limites</h2>
  <p>Audit en lecture seule : lecture de la configuration et de l'état du serveur, plus des
  requêtes HTTP non authentifiées sur des chemins publics. Aucune modification, aucune tentative
  d'authentification, aucun test d'exploitation.</p>
  <p><b>Non couvert :</b></p>
  <ul>{ul(data.get("not_covered", [])) or "<li>(non renseigné)</li>"}</ul>
  <div class="box"><p style="margin:0">Un audit ne prouve pas l'absence de faille : il constate
  ce qui a été regardé, à une date donnée. Aucune note globale n'est donnée volontairement, une
  note sur 100 donnerait une fausse impression de mesure.</p></div>

  <footer>Rapport régénéré le {date.today().isoformat()} depuis findings.json.
  Ne pas éditer ce HTML à la main : il est réécrit à chaque mise à jour.</footer>
</main>
<div class="copybar"><button class="copy" id="cp">Copier l'état comme prompt</button></div>
<script>
var P = {prompt_js};
document.getElementById("cp").addEventListener("click", function(){{
  var b = this;
  navigator.clipboard.writeText(P).then(function(){{
    b.textContent = "Copié !";
    setTimeout(function(){{ b.textContent = "Copier l'état comme prompt"; }}, 1800);
  }});
}});

// The report is re-rendered in place after every status change, and the owner
// keeps the same tab open across a whole fix session. A file:// page cannot
// fetch itself to check for a change (CORS blocks it), so it reloads on its
// own schedule: on coming back to the tab, and slowly while it is being read.
// Scroll position is carried across so the reload is invisible.
(function(){{
  var KEY = "infra-audit-scroll";
  try {{
    var y = sessionStorage.getItem(KEY);
    if (y !== null) window.scrollTo(0, parseInt(y, 10));
  }} catch (e) {{}}

  function reload() {{
    // Never yank the page out from under a selection or an open dialog.
    var sel = window.getSelection();
    if (sel && String(sel).length) return;
    try {{ sessionStorage.setItem(KEY, String(window.scrollY)); }} catch (e) {{}}
    location.reload();
  }}

  document.addEventListener("visibilitychange", function(){{
    if (!document.hidden) reload();
  }});
  setInterval(function(){{ if (!document.hidden) reload(); }}, 10000);
}})();
</script>
</body></html>"""
    out_path.write_text(html, encoding="utf-8")
    return out_path, done, total, open_p1


def open_browser(path):
    for cmd in (["xdg-open"], ["open"], ["wslview"]):
        try:
            subprocess.Popen(cmd + [str(path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            continue
    return False


def main():
    flags = {"--no-open", "--open"}
    args = [a for a in sys.argv[1:] if a not in flags]
    if not args:
        print(__doc__)
        sys.exit(1)
    src = Path(args[0]).expanduser()
    data = json.loads(src.read_text(encoding="utf-8"))
    out = src.with_suffix(".html")
    # Whether the report already existed decides whether to open a tab. A fix
    # session re-renders after every status change, and each of those spawning
    # a new tab buries the one the owner is reading. The page reloads itself
    # instead (see the script at the end of the template), so re-rendering in
    # place is enough. --open forces a new tab anyway.
    existed = out.exists()
    out, done, total, p1 = render(data, out)
    print(f"report: {out}")
    print(f"progress: {done}/{total} fixed, {p1} P1 still open")
    for w in lint_plan(data.get("findings", [])):
        print(f"plan: {w}", file=sys.stderr)
    force = "--open" in sys.argv
    if "--no-open" in sys.argv:
        return
    if existed and not force:
        print("(updated in place; the open tab reloads itself, --open forces a new one)")
        return
    open_browser(out) or print("(no browser opener found, open the file manually)")


if __name__ == "__main__":
    main()
