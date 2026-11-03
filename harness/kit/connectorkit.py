#!/usr/bin/env python3
"""connectorkit — hover-trace + ordered playback for connectors in hand-built SVG diagrams (any artifact page).

WHAT IT GIVES A PAGE
  * hover any connector (or its number badge): it glows in ITS OWN colour (SVG-native filter, not CSS drop-shadow),
    the badge grows ×1.55 with a white ring, a halo disc and an expanding ripple; every other connector in that
    diagram dims to 18 %; the hovered unit is raised to the front.
  * while highlighted, the connector's evidence class (data-ct="SRC" or "SRC/GK" on the g.cx unit or its line) shows
    as a pill beside its number, or at the path midpoint when it has no number — pairs with assetkit.
  * a 20 px ▶ button on EVERY diagram that has a connector (2026-10-16): it plays ONCE — the numbered connectors in
    natural number order (2 < 2.1 < 10), then any un-numbered ones top to bottom — 900 ms per step; the same button (■)
    stops it. Its tooltip says what the order means: "numbered steps in order", or, for a diagram with no numbers,
    "relations, not an execution order" plus the diagram's declared reason (svg data-cxwhy). Hover inside a playing
    diagram is ignored. An arrowhead inherited from a parent <g marker-end> makes each inner line its own connector.
  * CLASSIFICATION (gate G7): a diagram whose connectors are a sequence/flow must number them in execution order; one
    whose connectors are not (relations, alternatives) declares svg data-cxkind="relations" data-cxwhy="<reason>"; an
    un-numbered connector inside a numbered diagram carries data-cxwhy="<why it is not a step>".

EMITTER CONTRACT (the only thing a generator must do)
  * a numbered connector = <g class="cx"> <path|line marker-end=…/> <g class="nb"><circle …/><text>N</text></g> [label] </g>
  * optional: data-ct="SRC|GK|…" on the unit (or its path) to show its class while highlighted.
  * a page that cannot regroup its markup (a retrofitted hand-drawn diagram) may instead tag the arrow and its
    number badge g.nb with the same data-cxg="id": at load they are wrapped into one g.cx (badge moved next to it).
  * an un-numbered connector needs nothing: any element with marker-end, path.ie or path.cx is wrapped lazily
    on first hover (so JS-drawn diagrams are covered too) with a 12 px invisible hit stroke.
  * the glow colour is read from the computed stroke at hover time, so it follows light/dark themes.
  * theme tokens (optional): --ak-accent --ak-alert --ak-line --ak-panel2 --ak-muted --ak-ink; each falls back to
    the clusterdos-archv1 names (--cluster --gap --line --panel2 --mut --ink), then to a literal.

USE
  from connectorkit import CONNECTOR_CSS, CONNECTOR_JS        # put CSS in <style>, JS in the LAST <script>
  probe: PROBE_HEAD (in <head>) + PROBE_START_JS (on load) + PROBE_COLLECT_JS (later, defines `tr`) → check(tr)

LIMITS (known, documented)
  * a marker arrowhead keeps its own fill: SVG markers do not inherit from the referencing path.
  * a badge drawn at the very edge of its viewBox has its halo clipped by the SVG viewport.
"""

CONNECTOR_CSS = r'''
/* connector trace: hover any connector or its number badge; it glows in its own colour, the rest of that diagram dims */
svg .cx-hit{fill:none;stroke:transparent;stroke-width:12;pointer-events:stroke;cursor:crosshair}
svg .cx{transition:opacity .12s}
svg.cx-on .cx:not(.cx-hl),svg.cx-on [data-cxu]:not(.cx-hl){opacity:.18}
svg .cx-hl{opacity:1}
svg .cx-hl [data-cxl],svg [data-cxl].cx-hl{stroke:var(--hc)!important;stroke-opacity:1!important;stroke-width:3px!important;filter:url(#cxglow)}
svg .cx-hl .nb circle:not(.cx-halo):not(.cx-ripple){fill:var(--hc)!important;stroke:#fff!important;stroke-width:2px!important;filter:url(#cxglow2)}
svg .cx-hl .nb .cx-halo{fill:var(--hc);stroke:none;opacity:.9;pointer-events:none;filter:url(#cxglow2)}
svg .cx-hl .nb .cx-ripple{fill:none;stroke:var(--hc);stroke-width:2.5px;pointer-events:none;transform-box:fill-box;transform-origin:center;animation:cxripple 1.1s ease-out infinite}
@keyframes cxripple{from{transform:scale(1);opacity:1}to{transform:scale(2.1);opacity:0}}
@media (prefers-reduced-motion:reduce){svg .cx-hl .nb .cx-ripple{animation:none;opacity:.8}}
svg .cx-hl .nb text{fill:#000!important;font-weight:800}
svg .cx-hl>text{font-weight:700}
@media (prefers-reduced-motion:reduce){svg .cx{transition:none}}
.cxbar{position:sticky;left:0;width:max-content;margin:-8px 0 4px -8px}
.cxplay{width:20px;height:20px;padding:0;border:1px solid var(--ak-line,var(--line,#c8d0cc));border-radius:50%;background:var(--ak-panel2,var(--panel2,#eef1ef));color:var(--ak-muted,var(--mut,#667));font-size:9px;line-height:18px;text-align:center;cursor:pointer}
.cxplay:hover{color:var(--ak-ink,var(--ink,#123));border-color:var(--ak-accent,var(--cluster,#2a8f7f))}.cxplay.on{color:var(--ak-alert,var(--gap,#c0392b));border-color:var(--ak-alert,var(--gap,#c0392b))}
.cxplay:focus-visible{outline:2px solid var(--ak-accent,var(--cluster,#2a8f7f));outline-offset:2px}
'''

CONNECTOR_JS = r'''
(function(){
 // retrofit grouping: an arrow and its badge that share data-cxg become one g.cx unit (before anything else runs)
 [].forEach.call(document.querySelectorAll('svg'),function(svg){var by={};[].forEach.call(svg.querySelectorAll('[data-cxg]'),function(el){(by[el.getAttribute('data-cxg')]=by[el.getAttribute('data-cxg')]||[]).push(el);});
  Object.keys(by).forEach(function(k){var els=by[k],ln=els.filter(function(e){return !e.classList.contains('nb');})[0],nb=els.filter(function(e){return e.classList.contains('nb');})[0];if(!ln||!nb)return;
   var g=document.createElementNS('http://www.w3.org/2000/svg','g');g.setAttribute('class','cx');if(ln.getAttribute('data-ct'))g.setAttribute('data-ct',ln.getAttribute('data-ct'));ln.parentNode.insertBefore(g,ln);g.appendChild(ln);g.appendChild(nb);});});
 // connector trace: every connector (marker-end arrow, interaction edge, ego edge, numbered unit g.cx) becomes one hover unit
 function lines(u){return u.matches('path,line,polyline')?[u]:[].slice.call(u.querySelectorAll('path,line,polyline')).filter(function(x){return !x.closest('.nb')&&!x.closest('marker')&&!x.classList.contains('cx-hit');});}
 // wiring is idempotent PER ELEMENT (a diagram the page's JS redraws is re-wired on its next use); an arrowhead set on a
 // parent <g marker-end> is inherited by every line inside it, so each of those lines is its own connector
 function wire(svg){
  [].forEach.call(svg.querySelectorAll('[marker-end],path.ie,path.cx'),function(el){if(el.closest('marker')||el.hasAttribute('data-cxl')||el.classList.contains('cx-hit')||(el.parentNode.closest&&el.parentNode.closest('g.cx,[data-cxu]')))return;
   if(el.tagName.toLowerCase()==='g'){if(el.classList.contains('cx'))return;[].forEach.call(el.querySelectorAll('path,line,polyline'),function(c){if(!c.closest('g.cx,.nb,[data-cxu],marker')&&!c.hasAttribute('data-cxl')&&!c.classList.contains('cx-hit'))c.setAttribute('data-cxu','');});return;}
   el.setAttribute('data-cxu','');});
  [].forEach.call(svg.querySelectorAll('g.cx:not([data-cxw]),[data-cxu]:not([data-cxw])'),function(u){u.setAttribute('data-cxw','');lines(u).forEach(function(l){if(l.hasAttribute('data-cxl'))return;l.setAttribute('data-cxl','');
   if(l.classList.contains('ie'))return;var h=l.cloneNode(false);['class','marker-end','marker-start','stroke-dasharray','data-cxl','data-cxu','data-cxw','style'].forEach(function(a){h.removeAttribute(a);});h.setAttribute('class','cx-hit');h.setAttribute('marker-end','none');h.setAttribute('marker-start','none');
   if(u===l){var g=document.createElementNS('http://www.w3.org/2000/svg','g');l.parentNode.insertBefore(g,l);g.appendChild(l);g.appendChild(h);l.removeAttribute('data-cxu');l.removeAttribute('data-cxw');l.classList.remove('cx');g.setAttribute('data-cxu','');g.setAttribute('data-cxw','');
    ['data-cxwhy','data-ct'].forEach(function(a){if(l.hasAttribute(a))g.setAttribute(a,l.getAttribute(a));});}else l.parentNode.insertBefore(h,l.nextSibling);});});}
 // glow filters: SVG-native (CSS drop-shadow on SVG children is not honoured by every browser); userSpaceOnUse so a 0-height line keeps its glow
 (function(){var d=document.createElement('div');d.setAttribute('aria-hidden','true');d.style.cssText='position:absolute;width:0;height:0;overflow:hidden';
  function f(id,a,b){return '<filter id="'+id+'" filterUnits="userSpaceOnUse" x="-4000" y="-4000" width="16000" height="16000" color-interpolation-filters="sRGB"><feGaussianBlur in="SourceGraphic" stdDeviation="'+a+'" result="a"/><feGaussianBlur in="SourceGraphic" stdDeviation="'+b+'" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="a"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';}
  d.innerHTML='<svg width="0" height="0" style="min-width:0">'+f('cxglow',2,5)+f('cxglow2',3,8)+'</svg>';document.body.insertBefore(d,document.body.firstChild);})();
 // the badge itself grows, gets a pulsing halo in the connector colour, and the unit is raised above its neighbours
 function badge(u,on){[].forEach.call(u.querySelectorAll('.nb'),function(nb){var c=nb.querySelector('circle:not(.cx-halo)'),t=nb.querySelector('text');if(!c)return;
  if(on){if(!c.hasAttribute('data-r0'))c.setAttribute('data-r0',c.getAttribute('r'));var r=+c.getAttribute('data-r0');c.setAttribute('r',(r*1.55).toFixed(1));
   if(t){if(!t.hasAttribute('data-fs0'))t.setAttribute('data-fs0',t.getAttribute('font-size'));t.setAttribute('font-size',(+t.getAttribute('data-fs0')*1.4).toFixed(1));t.setAttribute('dy',(+t.getAttribute('data-fs0')*0.12).toFixed(1));}
   [['cx-halo',2.4],['cx-ripple',1.75]].forEach(function(k){var h=document.createElementNS('http://www.w3.org/2000/svg','circle');h.setAttribute('class',k[0]);h.setAttribute('cx',c.getAttribute('cx'));h.setAttribute('cy',c.getAttribute('cy'));h.setAttribute('r',(r*k[1]).toFixed(1));nb.insertBefore(h,nb.firstChild);});}
  else{if(c.hasAttribute('data-r0'))c.setAttribute('r',c.getAttribute('data-r0'));if(t&&t.hasAttribute('data-fs0')){t.setAttribute('font-size',t.getAttribute('data-fs0'));t.removeAttribute('dy');}
   [].forEach.call(nb.querySelectorAll('.cx-halo,.cx-ripple'),function(h){h.remove();});}});}
 // class pill (SRC/GK/PLAN/HARNESS/EXT) of the highlighted connector, from data-ct on the unit or its line: beside the number, else at the midpoint
 var CTC={SRC:'var(--ak-src,var(--ok,#1d7a4a))',GK:'var(--ak-gk,var(--queued,#5a46a0))',PLAN:'var(--ak-plan,var(--l4,#2563a8))',HARNESS:'var(--ak-harness,var(--host,#b0560e))',EXT:'var(--ak-ext,var(--mut,#667))'};
 function ctPill(u,on){[].forEach.call(u.querySelectorAll('.cx-ctpill'),function(x){x.remove();});if(!on)return;
  var l=lines(u)[0],ct=u.getAttribute('data-ct')||(l&&l.getAttribute('data-ct'));if(!ct||!l)return;var c=u.querySelector('.nb circle:not(.cx-halo):not(.cx-ripple)'),x,y;
  if(c){x=+c.getAttribute('cx')+(+c.getAttribute('r'))+5;y=+c.getAttribute('cy');}else{try{var L=l.getTotalLength(),pt=l.getPointAtLength(L/2);x=pt.x+6;y=pt.y-9;}catch(e){return;}}
  var g=document.createElementNS('http://www.w3.org/2000/svg','g');g.setAttribute('class','cx-ctpill');var h='';
  ct.split('/').forEach(function(k){var w=k.length*6.3+8,col=CTC[k]||'var(--ak-alert,var(--gap,#c0392b))';h+='<rect x="'+x+'" y="'+(y-7)+'" width="'+w+'" height="14" rx="3" fill="var(--panel,#fff)" stroke="'+col+'" stroke-width="1.2"/><text x="'+(x+w/2)+'" y="'+(y+3.5)+'" font-size="9.5" font-weight="800" text-anchor="middle" fill="'+col+'">'+k+'</text>';x+=w+3;});
  g.innerHTML=h;u.appendChild(g);}
 var cur=null;function off(){if(cur){badge(cur.u,false);ctPill(cur.u,false);cur.u.classList.remove('cx-hl');cur.s.classList.remove('cx-on');cur=null;}}
 function hl(u,svg){off();var l=lines(u)[0];if(!l)return;var c=getComputedStyle(l).stroke;if(!c||c==='none')c=getComputedStyle(l).color;u.style.setProperty('--hc',c);
  if(u.parentNode&&u.parentNode.lastElementChild!==u&&!u.classList.contains('ie'))u.parentNode.appendChild(u);
  u.classList.add('cx-hl');badge(u,true);ctPill(u,true);svg.classList.add('cx-on');cur={u:u,s:svg};}
 var play=null;  // {svg, btn, timer}: the one diagram playing; hover is ignored inside it while it plays
 document.addEventListener('pointerover',function(ev){var t=ev.target;if(!t.closest)return;var svg=t.closest('svg');if(play&&svg===play.svg)return;if(!svg){if(!play)off();return;}wire(svg);
  var u=t.closest('g.cx,[data-cxu]');if(!u||!svg.contains(u)){if(!play)off();return;}if(cur&&cur.u===u)return;if(play)stop();hl(u,svg);},{passive:true});
 document.addEventListener('pointerleave',function(){if(!play)off();},{passive:true});
 // play: light the numbered connectors one at a time, 1st number → last, once (no loop); the same button stops it
 function num(u){return u.querySelector('.nb text').textContent.trim().split('.').map(Number);}
 function isNum(u){return !!(u.querySelector&&u.querySelector('.nb text'));}
 function at(u){try{var b=lines(u)[0].getBBox();return [b.y,b.x];}catch(e){return [0,0];}}
 // every connector of a diagram, as play order: the NUMBERED ones in number order (2 < 2.1 < 10), then the un-numbered ones
 // top to bottom, left to right (they are relations or declared non-steps, never an execution order)
 function units(svg){wire(svg);var all=[].slice.call(svg.querySelectorAll('g.cx,[data-cxu]')).filter(function(u){return !(u.parentNode.closest&&u.parentNode.closest('g.cx,[data-cxu]'));});
  var n=all.filter(isNum).sort(cmp),r=all.filter(function(u){return !isNum(u);}).sort(function(a,b){var p=at(a),q=at(b);return (p[0]-q[0])||(p[1]-q[1]);});return {n:n,r:r};}
 window.__cxUnits=units;
 function titleFor(svg){var u=units(svg),w=svg.getAttribute('data-cxwhy')||'';
  if(u.n.length&&!u.r.length)return 'Play the '+u.n.length+' numbered connectors in order, 1st to last';
  if(u.n.length)return 'Play the '+u.n.length+' numbered steps in order, then the '+u.r.length+' un-numbered connector'+(u.r.length>1?'s':'')+' (not steps — hover one for why)';
  if(svg.getAttribute('data-cxkind')!=='relations')return 'Trace each of the '+u.r.length+' connector'+(u.r.length>1?'s':'')+' in turn, top to bottom (this diagram declares no order)';
  return 'Trace each of the '+u.r.length+' connector'+(u.r.length>1?'s':'')+' in turn, top to bottom — these are relations, not an execution order'+(w?': '+w:'');}
 function cmp(a,b){a=num(a);b=num(b);for(var i=0;i<Math.max(a.length,b.length);i++){var d=(a[i]||0)-(b[i]||0);if(d)return d;}return 0;}
 function setBtn(b,on){b.classList.toggle('on',on);b.textContent=on?'\u25A0':'\u25B6';b.setAttribute('aria-label',on?'Stop':(b.getAttribute('data-t')||'Play the connectors in order'));b.title=b.getAttribute('aria-label');}
 function stop(){if(!play)return;clearTimeout(play.timer);setBtn(play.btn,false);var p=play;play=null;if(cur&&cur.s===p.svg)off();}
 function start(svg,btn){stop();var U=units(svg),us=U.n.concat(U.r),i=0;
  if(!us.length)return;play={svg:svg,btn:btn,timer:0};setBtn(btn,true);var ms=window.__cxStep||900;
  (function step(){if(!play||play.svg!==svg)return;if(i>=us.length){stop();return;}var u=us[i++];hl(u,svg);if(window.__cxLog)window.__cxLog.push(isNum(u)?u.querySelector('.nb text').textContent.trim():'r'+(i-U.n.length));play.timer=setTimeout(step,ms);})();}
 // a ▶ on EVERY diagram that has a connector (numbered or not), including diagrams the page's JS draws later
 function hasConn(svg){return !!svg.querySelector('g.cx,path.ie,path.cx,[marker-end]:not(marker *),[marker-end]:not(marker) *');}
 function setup(svg){if(svg.__cxb||!svg.parentNode||svg.closest('.cxbar')||!hasConn(svg))return;svg.__cxb=1;
  var bar=document.createElement('div');bar.className='cxbar';var b=document.createElement('button');b.type='button';b.className='cxplay';b.setAttribute('data-t',titleFor(svg));setBtn(b,false);bar.appendChild(b);
  svg.parentNode.insertBefore(bar,svg);b.addEventListener('click',function(){if(play&&play.btn===b)stop();else{b.setAttribute('data-t',titleFor(svg));start(svg,b);}});}
 [].forEach.call(document.querySelectorAll('svg'),setup);
 if(window.MutationObserver)new MutationObserver(function(ms){ms.forEach(function(m){[].forEach.call(m.addedNodes,function(n){if(n.nodeType!==1)return;if(n.tagName&&n.tagName.toLowerCase()==='svg')setup(n);else if(n.querySelectorAll)[].forEach.call(n.querySelectorAll('svg'),setup);});});}).observe(document.body,{childList:true,subtree:true});
})();
'''

# ── browser probe (headless Chrome --dump-dom): proves the behaviour, used by run_gates-style gates ──
PROBE_HEAD = "window.__cxStep=1;window.__cxLog=[];"
# phase 1 (on load): play the first diagram with > 3 numbered connectors; phase 2 (+150 ms): play the smallest
# relations-only diagram (no numbers, >= 3 connectors) — each must light every connector exactly once, in order, then stop
PROBE_START_JS = (
    "var B=[].filter.call(document.querySelectorAll('.cxplay'),function(b){return b.parentNode.nextElementSibling.querySelectorAll('g.cx .nb text').length>3;})[0];"
    "if(B){var S=B.parentNode.nextElementSibling,UU=window.__cxUnits(S),U=UU.n.map(function(u){return u.querySelector('.nb text').textContent.trim();});"
    "window.__cxPlay={btn:B,svg:S,n:U.length+UU.r.length,want:U.join(',')};B.click();}"
    "setTimeout(function(){window.__cxLogN=window.__cxLog.slice();window.__cxLog=[];var best=null;"
    "[].forEach.call(document.querySelectorAll('.cxplay'),function(b){var s=b.parentNode.nextElementSibling;if(!s||s.querySelector('g.cx .nb text'))return;var k=window.__cxUnits(s).r.length;if(k>=3&&(!best||k<best.k))best={b:b,s:s,k:k};});"
    "if(best){window.__cxRel={btn:best.b,svg:best.s,n:best.k};best.b.click();}},150);")
PROBE_COLLECT_JS = (
    "var __rl=window.__cxLog.slice();var tr={svgs:0,ok:0,badges:0,fail:[],noplay:0,unclassified:[]};[].forEach.call(document.querySelectorAll('svg'),function(sv,i){if(sv.closest('.cxbar')||!(sv.querySelector('g.cx,path.ie,path.cx,[marker-end]:not(marker *),[marker-end]:not(marker) *')))return;"
    "var U=window.__cxUnits(sv),u0=U.n[0]||U.r[0];if(!u0)return;tr.svgs++;var bar=sv.previousElementSibling;if(!(bar&&bar.classList.contains('cxbar')))tr.noplay++;"
    "var id=(sv.closest('section,details')||{}).id+':'+(sv.getAttribute('aria-label')||'').slice(0,50);"
    "if(U.r.length&&!U.n.length&&sv.getAttribute('data-cxkind')!=='relations')tr.unclassified.push(id+' ('+U.r.length+' un-numbered, no relations declaration)');"
    "if(U.r.length&&U.n.length){var bare=U.r.filter(function(u){return !(u.getAttribute('data-cxwhy')||(u.querySelector('[data-cxwhy]')));}).length;if(bare)tr.unclassified.push(id+' ('+bare+' un-numbered connector(s) in a numbered diagram without a reason)');}"
    "var c=u0.querySelector('[data-cxl]')||u0;"
    "c.dispatchEvent(new PointerEvent('pointerover',{bubbles:true}));var u=sv.querySelector('.cx-hl'),l=u&&(u.matches('[data-cxl]')?u:u.querySelector('[data-cxl]')),hc=u&&u.style.getPropertyValue('--hc'),f=l&&getComputedStyle(l).filter,nb=u&&u.querySelector('.nb circle[data-r0]');"
    "var good=!!(u&&sv.classList.contains('cx-on')&&hc&&f&&f.indexOf('url(')>=0&&(!nb||(getComputedStyle(nb).fill===getComputedStyle(l).stroke&&getComputedStyle(nb).filter.indexOf('url(')>=0&&+nb.getAttribute('r')>+nb.getAttribute('data-r0')&&!!u.querySelector('.nb .cx-halo')&&!!u.querySelector('.nb .cx-ripple'))));var dct=u&&(u.getAttribute('data-ct')||(l&&l.getAttribute('data-ct')));if(dct){tr.ct=(tr.ct||0)+1;if(!u.querySelector('.cx-ctpill')){tr.ctmiss=(tr.ctmiss||0)+1;good=false;}}if(nb&&good)tr.badges++;if(good)tr.ok++;else tr.fail.push(i+':'+id+' hl='+!!u+' hc='+hc+' f='+f);"
    "document.dispatchEvent(new PointerEvent('pointerleave'));});"
    "var pb=window.__cxPlay||{};var pl=(window.__cxLogN||window.__cxLog).slice();pb.done=pb.btn?!pb.btn.classList.contains('on'):false;pb.ordered=pl.length===pb.n&&pl.slice(0,pb.want.split(',').length).join(',')===pb.want;"
    "if(pb.btn){pb.btn.click();var on1=pb.btn.classList.contains('on')&&pb.svg.classList.contains('cx-on');pb.btn.click();pb.stops=on1&&!pb.btn.classList.contains('on')&&!pb.svg.classList.contains('cx-on');}"
    "tr.play={buttons:document.querySelectorAll('.cxplay').length,n:pb.n,ordered:pb.ordered,done:pb.done,stops:pb.stops};delete pb.btn;delete pb.svg;"
    "var rb=window.__cxRel;if(rb){var rl=__rl;tr.rel={n:rb.n,played:rl.length,log:rl.join(','),once:rl.length===rb.n&&new Set(rl).size===rl.length,done:!rb.btn.classList.contains('on'),says_relations:/relations, not an execution order/.test(rb.btn.title)};}")


def check(tr, need_play=True):
    """(ok, summary) for the `tr` object PROBE_COLLECT_JS produced."""
    tr = tr or {}
    pl = tr.get('play') or {}
    ok_trace = tr.get('svgs', 0) > 0 and not tr.get('fail') and tr.get('ok') == tr.get('svgs')
    ok_play = (not need_play) or (pl.get('buttons', 0) > 0 and pl.get('ordered') is True and pl.get('done') is True and pl.get('stops') is True)
    rel = tr.get('rel')
    ok_rel = rel is None or (rel.get('once') and rel.get('done') and rel.get('says_relations'))
    ok_cls = not tr.get('unclassified') and not tr.get('noplay')
    summ = (f"trace={tr.get('ok')}/{tr.get('svgs')} badges={tr.get('badges')} class-pills={tr.get('ct', 0) - tr.get('ctmiss', 0)}/{tr.get('ct', 0)} play={pl}"
            f" relations-play={rel} no-button={tr.get('noplay')} unclassified={len(tr.get('unclassified') or [])}"
            + (f" TRACE-FAIL {tr['fail'][:4]}" if tr.get('fail') else '') + (f" UNCLASSIFIED {tr['unclassified'][:4]}" if tr.get('unclassified') else ''))
    return ok_trace and ok_play and ok_rel and ok_cls, summ
