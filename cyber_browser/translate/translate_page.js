// Injected into the isolated ApplicationWorld (page scripts cannot see or tamper with it).
// Collects visible text nodes, swaps in translations and can restore the original.
(() => {
  if (window.__cbT) return;
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'CODE', 'PRE', 'TEXTAREA', 'INPUT',
                        'SELECT', 'OPTION', 'SVG', 'MATH', 'IFRAME', 'KBD', 'SAMP']);
  window.__cbT = {
    nodes: [], originals: [], dir: null,
    sample() {
      const lang = (document.documentElement.getAttribute('lang') || '').trim();
      const text = document.body ? document.body.innerText.slice(0, 3000) : '';
      return [lang, text];
    },
    collect(max) {
      this.restore();
      this.nodes = []; this.originals = [];
      if (!document.body) return [];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode(n) {
          const t = n.nodeValue;
          if (!t || t.trim().length < 2 || !/\p{L}/u.test(t)) return NodeFilter.FILTER_REJECT;
          for (let p = n.parentElement; p; p = p.parentElement) {
            if (SKIP.has(p.tagName) || p.isContentEditable) return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      });
      let n;
      while ((n = walker.nextNode()) && this.nodes.length < max) {
        this.nodes.push(n);
        this.originals.push(n.nodeValue);
      }
      return this.originals.map(t => t.trim());
    },
    apply(translations, dir) {
      for (let i = 0; i < translations.length && i < this.nodes.length; i++) {
        const t = translations[i];
        if (!t) continue;
        const o = this.originals[i];
        this.nodes[i].nodeValue = o.match(/^\s*/)[0] + t + o.match(/\s*$/)[0];
      }
      if (dir) {
        this.dir = document.documentElement.getAttribute('dir');
        document.documentElement.setAttribute('dir', dir);
      }
      return true;
    },
    restore() {
      for (let i = 0; i < this.nodes.length; i++) this.nodes[i].nodeValue = this.originals[i];
      if (this.dir !== null) document.documentElement.setAttribute('dir', this.dir);
      else document.documentElement.removeAttribute('dir');
      this.dir = null;
      return true;
    }
  };
})();
