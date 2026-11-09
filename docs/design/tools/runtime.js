// Minimal runtime for the Orus Shield prototype pages: renders a template with
// {{holes}}, data-for / data-if blocks and on* event bindings, and re-renders on setState.
(function () {
  var comp = null, tpl = null, root = null;
  var HOLE = /\{\{\s*([^}]+?)\s*\}\}/g;
  function lookup(path, scope) {
    path = path.trim();
    if (path === 'true') return true;
    if (path === 'false') return false;
    if (/^-?\d+(\.\d+)?$/.test(path)) return Number(path);
    var parts = path.split('.'), v = scope;
    for (var i = 0; i < parts.length; i++) { if (v == null) return undefined; v = v[parts[i]]; }
    return v;
  }
  function interp(str, scope) {
    return str.replace(HOLE, function (_, p) { var v = lookup(p, scope); return v == null ? '' : String(v); });
  }
  function eventFor(el, name) {
    if (name === 'onclick') return 'click';
    if (name === 'onchange') {
      var t = (el.getAttribute('type') || '').toLowerCase();
      return el.tagName === 'INPUT' && t !== 'checkbox' && t !== 'radio' ? 'input' : 'change';
    }
    return name.slice(2);
  }
  function processAttrs(el, scope) {
    var attrs = Array.prototype.slice.call(el.attributes);
    attrs.forEach(function (a) {
      var name = a.name, val = a.value;
      if (name.indexOf('on') === 0 && /^\{\{[^}]+\}\}$/.test(val.trim())) {
        el.removeAttribute(name);
        var fn = lookup(val.trim().slice(2, -2), scope);
        if (typeof fn === 'function') el.addEventListener(eventFor(el, name), fn);
        return;
      }
      if (val.indexOf('{{') === -1) return;
      var whole = /^\{\{[^}]+\}\}$/.test(val.trim());
      var v = whole ? lookup(val.trim().slice(2, -2), scope) : interp(val, scope);
      if (name === 'value' && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
        el.removeAttribute('value');
        el.__value = v == null ? '' : String(v);
        return;
      }
      if (v === false || v == null) el.removeAttribute(name); else el.setAttribute(name, String(v));
    });
  }
  function processChildren(parent, scope) {
    var kids = Array.prototype.slice.call(parent.childNodes);
    kids.forEach(function (n) { processNode(n, scope); });
  }
  function processNode(n, scope) {
    if (n.nodeType === 3) {
      if (n.nodeValue.indexOf('{{') !== -1) n.nodeValue = interp(n.nodeValue, scope);
      return;
    }
    if (n.nodeType !== 1) return;
    if (n.tagName === 'TEMPLATE' && (n.hasAttribute('data-for') || n.hasAttribute('data-if'))) {
      var frag = document.createDocumentFragment();
      if (n.hasAttribute('data-for')) {
        var list = lookup(n.getAttribute('data-for'), scope) || [];
        var as = n.getAttribute('data-as');
        list.forEach(function (item, i) {
          var s = Object.create(scope); s[as] = item; s.$index = i;
          var c = n.content.cloneNode(true); processChildren(c, s); frag.appendChild(c);
        });
      } else if (lookup(n.getAttribute('data-if'), scope)) {
        var c2 = n.content.cloneNode(true); processChildren(c2, scope); frag.appendChild(c2);
      }
      n.parentNode.replaceChild(frag, n);
      return;
    }
    processAttrs(n, scope);
    processChildren(n, scope);
  }
  function render() {
    var active = document.activeElement, id = active && active.id, sel = null;
    if (id && active.selectionStart != null) { try { sel = [active.selectionStart, active.selectionEnd]; } catch (e) { sel = null; } }
    var frag = tpl.content.cloneNode(true);
    processChildren(frag, comp.renderVals());
    root.replaceChildren(frag);
    root.querySelectorAll('input, textarea').forEach(function (el) { if (el.__value !== undefined) el.value = el.__value; });
    if (id) {
      var again = document.getElementById(id);
      if (again) { again.focus(); if (sel) { try { again.setSelectionRange(sel[0], sel[1]); } catch (e) { /* not a text field */ } } }
    }
  }
  window.DCLogic = function DCLogic(props) { this.props = props || {}; this.state = {}; };
  window.DCLogic.prototype.setState = function (patch) {
    var p = typeof patch === 'function' ? patch(this.state, this.props) : patch;
    this.state = Object.assign({}, this.state, p);
    render();
  };
  window.DCLogic.prototype.forceUpdate = function () { render(); };
  window.mountPrototype = function (Component) {
    tpl = document.getElementById('page-template');
    root = document.getElementById('app');
    comp = new Component({});
    render();
  };
})();
